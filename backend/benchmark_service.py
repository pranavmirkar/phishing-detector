"""
Benchmarks API (used by the dashboard's Benchmarks tab).

  GET    /api/benchmarks/datasets        what can be run + status of the public corpora
  POST   /api/benchmarks/real/download   fetch public corpora by group (fixed, reviewed URLs only)
  DELETE /api/benchmarks/real            remove the downloaded corpora
  POST   /api/benchmarks/run             start a benchmark job  -> {job_id}
  GET    /api/benchmarks/jobs/<id>       progress / result of a job
  GET    /api/benchmarks/results         most recent saved result per dataset

Runs execute in a background thread, one at a time, through the same engine as the command-line
scripts (benchmark/engine.py) and the same PhishingDetector.analyze() as /api/analyze, with WHOIS
switched off per instance so live analysis is unaffected and results are repeatable.
Nothing from the public corpora is stored in results except sender domains.
"""
import json
import os
import threading
import time
import urllib.request
import uuid
from urllib.parse import urlparse
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from detector import PhishingDetector
from benchmark import corpora as C
from benchmark import engine

bp = Blueprint("benchmarks", __name__, url_prefix="/api/benchmarks")

BENCH_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark")
# Writable locations for downloaded corpora and saved runs (override in containers with a volume).
DATA_DIR = os.environ.get("PG_BENCH_DATA") or os.path.join(BENCH_DIR, "data", "real")
RUNS_DIR = os.environ.get("PG_BENCH_RUNS") or os.path.join(BENCH_DIR, "runs")

PRIVATE = {
    "private_dev": {
        "file": "dataset.jsonl", "name": "Development set",
        "description": "Bundled synthetic emails (typosquats, homoglyphs, subdomain abuse, BEC, newsletters, "
                       "small-business mail). Used while building the rules, so scores here are optimistic.",
    },
    "private_holdout": {
        "file": "dataset_v2.jsonl", "name": "Second set",
        "description": "Bundled synthetic emails with different wording, brands and attack styles, written "
                       "before the rules were improved. Includes known-hard cases (forged brand sender, no other clue).",
    },
}
LIMITS = {"custom_max_rows": 2000, "real_min_n": 20, "real_max_n": 6000, "real_default_n": 1500, "field_max": 60000}
MAX_JOBS = 20
CUSTOM_FIELDS = ("sender", "reply_to", "subject", "content", "auth_results", "return_path", "recipient")

def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


_ALLOWED_HOSTS = {urlparse(v["url"]).hostname for v in C.SOURCES.values()}
_lock = threading.Lock()
_jobs = {}
_download = {"state": "idle", "current": "", "done": 0, "total": 0, "file_index": 0, "file_count": 0, "error": ""}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


_count_cache = {}


def _private_info():
    out = []
    for key, meta in PRIVATE.items():
        path = os.path.join(BENCH_DIR, meta["file"])
        if not os.path.exists(path):
            continue
        mtime = os.path.getmtime(path)
        if _count_cache.get(key, (None,))[0] != mtime:
            rows = _read_jsonl(path)
            ph = sum(r["label"] == "phishing" for r in rows)
            _count_cache[key] = (mtime, len(rows), ph)
        _, n, ph = _count_cache[key]
        out.append({"id": key, "name": meta["name"], "description": meta["description"],
                    "samples": n, "phishing": ph, "legit": n - ph})
    return out


def _real_files():
    have = engine.present_sources(DATA_DIR)
    files = []
    for key, src in C.SOURCES.items():
        path = have.get(key)
        files.append({"id": key, "name": src["name"], "url": src["page"], "present": bool(path),
                      "bytes": os.path.getsize(path) if path else 0, "group": src["group"],
                      "label": src["label"], "role": src["role"], "credit": src["credit"]})
    return files


def _split_ready(split, include_spam=False):
    """A split needs at least one phishing and one legitimate source on disk."""
    have = engine.present_sources(DATA_DIR)
    keys = [k for k in C.wanted(split) if k in have]
    labels = {C.SOURCES[k]["label"] for k in keys}
    return {"phishing", "legit"} <= labels and (not include_spam or "spam" in have)


# ── public corpora download ───────────────────────────────────────────────────
def _download_worker(keys):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        todo = [k for k in keys if not (os.path.exists(os.path.join(DATA_DIR, C.SOURCES[k]["file"]))
                                        and os.path.getsize(os.path.join(DATA_DIR, C.SOURCES[k]["file"])) > 0)]
        with _lock:
            _download.update(file_count=len(todo), file_index=0)
        for i, key in enumerate(todo, 1):
            src = C.SOURCES[key]
            dest = os.path.join(DATA_DIR, src["file"])
            with _lock:
                _download.update(current=src["name"], done=0, total=0, file_index=i)
            if src["kind"] == "enron":                 # streamed sample of a 443 MB archive, built by benchmark/enron.py
                from benchmark import enron

                def _progress(done, limit=45_000_000):
                    with _lock:
                        _download.update(done=min(done, limit), total=limit)

                enron.build_sample(dest, on_progress=_progress)
                continue
            req = urllib.request.Request(src["url"], headers={"User-Agent": "PhishGuard-benchmark/1.0"})
            tmp = dest + ".part"
            with urllib.request.urlopen(req, timeout=30) as resp, open(tmp, "wb") as out:
                if (urlparse(resp.geturl()).hostname or "") not in _ALLOWED_HOSTS:     # a redirect must stay on a reviewed host
                    raise ValueError(f"{src['name']}: redirected to an unexpected host")
                total = int(resp.headers.get("Content-Length") or 0)
                if total > src["max_bytes"]:
                    raise ValueError(f"{src['name']}: file larger than expected ({total} bytes)")
                with _lock:
                    _download["total"] = total
                got = 0
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    got += len(chunk)
                    if got > src["max_bytes"]:
                        raise ValueError(f"{src['name']}: download exceeded the size limit")
                    out.write(chunk)
                    with _lock:
                        _download["done"] = got
            with open(tmp, "rb") as f:
                head = f.read(8)
            ok = head.startswith(b"BZh") if src["kind"] == "tar" else head.startswith(b"From ")
            if not ok:
                os.remove(tmp)
                raise ValueError(f"{src['name']}: unexpected file format")
            os.replace(tmp, dest)
        with _lock:
            _download.update(state="done", current="", error="")
    except Exception as exc:
        with _lock:
            _download.update(state="error", error=str(exc)[:300], current="")


def start_download(group):
    keys = [k for k, v in C.SOURCES.items() if group == "all" or v["group"] == group]
    if not keys:
        return False
    with _lock:
        if _download["state"] == "running":
            return None
        _download.update(state="running", current="", done=0, total=0, error="")
    threading.Thread(target=_download_worker, args=(keys,), daemon=True).start()
    return True


# ── custom upload ─────────────────────────────────────────────────────────────
def _clean_custom(rows):
    if not isinstance(rows, list) or not rows:
        raise ValueError("Upload a non-empty list of labelled emails.")
    if len(rows) > LIMITS["custom_max_rows"]:
        raise ValueError(f"At most {LIMITS['custom_max_rows']} rows per run.")
    cleaned, skipped = [], 0
    fm = LIMITS["field_max"]
    for r in rows:
        if not isinstance(r, dict):
            skipped += 1
            continue
        label = str(r.get("label", "")).strip().lower()
        label = {"ham": "legit", "legitimate": "legit", "benign": "legit", "safe": "legit",
                 "phish": "phishing", "malicious": "phishing"}.get(label, label)
        sender = str(r.get("sender", "")).strip()[:500]
        if label not in ("phishing", "legit") or "@" not in sender:
            skipped += 1
            continue
        row = {k: str(r.get(k) or "")[:fm] for k in CUSTOM_FIELDS}
        row.update(label=label, sender=sender, category=str(r.get("category") or "")[:60], source="")
        row["list_id"] = bool(r.get("list_id"))
        row["attachments"] = [{"filename": str(a)[:200]} for a in (r.get("attachments") or [])[:25]] \
            if isinstance(r.get("attachments"), list) else []
        cleaned.append(row)
    if {c["label"] for c in cleaned} != {"phishing", "legit"}:
        raise ValueError("The file needs at least one 'phishing' and one 'legit' row with a valid sender "
                         f"(read {len(cleaned)} usable rows, skipped {skipped}).")
    return cleaned, skipped


# ── jobs ──────────────────────────────────────────────────────────────────────
def _save(result, spec):
    if result["kind"] == "custom":
        return
    try:
        os.makedirs(RUNS_DIR, exist_ok=True)
        key = spec["dataset"] + (f"_{spec['split']}" if spec["dataset"] == "real" else "")
        with open(os.path.join(RUNS_DIR, f"{key}.json"), "w", encoding="utf-8") as f:
            json.dump(result, f)
    except OSError:
        pass


def _run_worker(job_id, spec):
    job = _jobs[job_id]
    t0 = time.time()
    try:
        skipped = 0
        job.update(state="running", phase="loading")
        used = []
        if spec["dataset"] in PRIVATE:
            samples = _read_jsonl(os.path.join(BENCH_DIR, PRIVATE[spec["dataset"]]["file"]))
            meta = {"name": PRIVATE[spec["dataset"]]["name"], "kind": "private"}
        elif spec["dataset"] == "real":
            samples, used = engine.load_real(DATA_DIR, spec["split"], spec["n"], spec["include_spam"])
            meta = {"name": "Real public corpora", "kind": "real", "sources": used}
        else:
            samples, skipped = spec["rows"], spec.get("skipped", 0)
            meta = {"name": "Uploaded file", "kind": "custom"}
        job.update(phase="scoring", total=len(samples), done=0)

        scored, crashes, times = engine.score(samples, PhishingDetector(use_whois=False),
                                              progress=lambda i: job.__setitem__("done", i))
        if not any(r["label"] == "phishing" for r in scored) or not any(r["label"] == "legit" for r in scored):
            raise ValueError("The selection needs both phishing and legitimate emails.")
        meta.update(dataset=spec["dataset"], finished_at=_now(),
                    options={k: spec[k] for k in ("split", "n", "include_spam") if k in spec})
        result = engine.summarize(scored, meta, crashes, skipped, time.time() - t0, times,
                                  show_sender=meta["kind"] != "real")
        _save(result, spec)
        job.update(state="done", phase="done", result=result)
    except FileNotFoundError:
        job.update(state="error", error="Dataset files are missing. Download the public corpora first.")
    except Exception as exc:
        job.update(state="error", error=str(exc)[:300] or exc.__class__.__name__)


def _validate_spec(body):
    dataset = body.get("dataset")
    if dataset in PRIVATE:
        return {"dataset": dataset}
    if dataset == "real":
        split = body.get("split", "test")
        if split not in ("dev", "val", "test_seen", "test", "all"):
            raise ValueError("split must be dev, val, test_seen, test or all")
        try:
            n = int(body.get("n", LIMITS["real_default_n"]))
        except (TypeError, ValueError):
            raise ValueError("n must be a number")
        n = max(LIMITS["real_min_n"], min(n, LIMITS["real_max_n"]))
        spam = bool(body.get("include_spam", False))
        if not _split_ready(split, spam):
            raise ValueError("Download the public corpora for this split first.")
        return {"dataset": "real", "split": split, "n": n, "include_spam": spam}
    if dataset == "custom":
        rows, skipped = _clean_custom(body.get("rows"))
        return {"dataset": "custom", "rows": rows, "skipped": skipped}
    raise ValueError("Unknown dataset.")


def _job_view(job):
    return {k: job.get(k) for k in ("id", "state", "phase", "done", "total", "error", "result", "dataset", "created_at")}


# ── routes ────────────────────────────────────────────────────────────────────
@bp.route("/datasets", methods=["GET"])
def datasets():
    with _lock:
        dl = dict(_download)
    return jsonify({
        "private": _private_info(),
        "real": {
            "files": _real_files(), "groups": C.GROUPS,
            "ready": {sp: _split_ready(sp) for sp in ("dev", "val", "test_seen", "test", "all")}, "download": dl,
            "splits": {
                "test": "LOCKED: 2024-2025 phishing and legitimate mail that was never scored or inspected. The learned model was trained only on earlier years and other senders.",
                "dev": "2015, 2018, 2019, 2022 phishing with a quarter of the legitimate mail. Rules and the model are built here.",
                "val": "2016, 2017, 2020, 2021, 2023 phishing with another quarter of the legitimate mail: iteration checks and model training.",
                "test_seen": "2024-2025 emails that were scored once during development (so no longer unseen). Never used for training.",
                "all": "Everything above."},
            "note": "Public corpora are fetched on request from their original sites and are not redistributed with "
                    "this project. Phishing: J. Nazario corpus (CC BY 4.0). Legitimate mail: SpamAssassin ham (2002-03), "
                    "Enron corporate mail (1999-2002) and Apache mailing lists (2025). Marketing mail, receipts and "
                    "consumer webmail are NOT represented, so false alarms on them are unmeasured.",
        },
        "limits": LIMITS,
    })


@bp.route("/real/download", methods=["POST"])
def real_download():
    body = _body()
    group = body.get("group")
    if group not in ("core", "recent", "optional", "all"):
        return jsonify({"error": "group must be one of core, recent, optional, all"}), 400
    started = start_download(group)
    if started is None:
        return jsonify({"error": "A download is already running."}), 409
    if not started:
        return jsonify({"error": "nothing to download"}), 400
    return jsonify({"started": True}), 202


@bp.route("/real", methods=["DELETE"])
def real_delete():
    with _lock:
        if _download["state"] == "running":
            return jsonify({"error": "A download is running."}), 409
    removed = 0
    for src in C.SOURCES.values():
        path = os.path.join(DATA_DIR, src["file"])
        if os.path.exists(path):
            os.remove(path)
            removed += 1
    with _lock:
        _download.update(state="idle", current="", done=0, total=0, error="")
    return jsonify({"removed": removed})


@bp.route("/run", methods=["POST"])
def run():
    try:
        spec = _validate_spec(_body())
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    with _lock:
        if any(j["state"] in ("queued", "running") for j in _jobs.values()):
            return jsonify({"error": "A benchmark is already running."}), 409
        job_id = uuid.uuid4().hex[:12]
        _jobs[job_id] = {"id": job_id, "state": "queued", "phase": "queued", "done": 0, "total": 0,
                         "error": "", "result": None, "dataset": spec["dataset"], "created_at": _now()}
        while len(_jobs) > MAX_JOBS:
            _jobs.pop(next(iter(_jobs)))
    threading.Thread(target=_run_worker, args=(job_id, spec), daemon=True).start()
    return jsonify({"job_id": job_id}), 202


@bp.route("/jobs/<job_id>", methods=["GET"])
def job(job_id):
    j = _jobs.get(job_id)
    if not j:
        return jsonify({"error": "not found"}), 404
    return jsonify(_job_view(j))


@bp.route("/results", methods=["GET"])
def results():
    out = {}
    if os.path.isdir(RUNS_DIR):
        for name in sorted(os.listdir(RUNS_DIR)):
            if name.endswith(".json"):
                try:
                    with open(os.path.join(RUNS_DIR, name), encoding="utf-8") as f:
                        out[name[:-5]] = json.load(f)
                except (OSError, ValueError):
                    pass
    return jsonify(out)

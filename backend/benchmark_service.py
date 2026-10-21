"""
Benchmarks API (used by the dashboard's Benchmarks tab).

  GET    /api/benchmarks/datasets        what can be run + status of the public corpora
  POST   /api/benchmarks/real/download   fetch the public corpora (fixed, reviewed URLs only)
  DELETE /api/benchmarks/real            remove the downloaded corpora
  POST   /api/benchmarks/run             start a benchmark job  -> {job_id}
  GET    /api/benchmarks/jobs/<id>       progress / result of a job
  GET    /api/benchmarks/results         most recent saved result per dataset

Runs execute in a background thread, one at a time. They use the same
PhishingDetector.analyze() as /api/analyze, with WHOIS switched off per instance
(so live analysis is unaffected and results are repeatable).
Nothing from the public corpora is stored in results except sender domains.
"""
import json
import os
import random
import threading
import time
import urllib.request
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from detector import PhishingDetector
from benchmark import corpora as C
from benchmark import metrics as M

bp = Blueprint("benchmarks", __name__, url_prefix="/api/benchmarks")

BENCH_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark")
DATA_DIR = os.path.join(BENCH_DIR, "data", "real")
RUNS_DIR = os.path.join(BENCH_DIR, "runs")

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
LIMITS = {"custom_max_rows": 2000, "real_min_n": 20, "real_max_n": 1000, "real_default_n": 200, "field_max": 12000}
REAL_SEED = 11
MAX_ERRORS = 60
MAX_JOBS = 20

_lock = threading.Lock()
_jobs = {}
_download = {"state": "idle", "current": "", "done": 0, "total": 0, "error": ""}


# ── helpers ───────────────────────────────────────────────────────────────────
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
    files = []
    for key, src in C.SOURCES.items():
        path = os.path.join(DATA_DIR, src["file"])
        size = os.path.getsize(path) if os.path.exists(path) else 0
        files.append({"id": key, "name": src["name"], "url": src["page"], "present": size > 0,
                      "bytes": size, "required": key != "spam"})
    return files


def _real_ready(include_spam=False):
    need = {"phishing", "ham"} | ({"spam"} if include_spam else set())
    return all(f["present"] for f in _real_files() if f["id"] in need)


# ── public corpora download ───────────────────────────────────────────────────
def _download_worker(keys):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        for key in keys:
            src = C.SOURCES[key]
            dest = os.path.join(DATA_DIR, src["file"])
            if os.path.exists(dest) and os.path.getsize(dest) > 0:
                continue
            with _lock:
                _download.update(current=src["name"], done=0, total=0)
            req = urllib.request.Request(src["url"], headers={"User-Agent": "PhishGuard-benchmark/1.0"})
            tmp = dest + ".part"
            with urllib.request.urlopen(req, timeout=30) as resp, open(tmp, "wb") as out:
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


def start_download(include_spam):
    with _lock:
        if _download["state"] == "running":
            return False
        _download.update(state="running", current="", done=0, total=0, error="")
    keys = ["phishing", "ham"] + (["spam"] if include_spam else [])
    threading.Thread(target=_download_worker, args=(keys,), daemon=True).start()
    return True


# ── dataset loading ───────────────────────────────────────────────────────────
def _load_private(key):
    rows = _read_jsonl(os.path.join(BENCH_DIR, PRIVATE[key]["file"]))
    return rows, {"name": PRIVATE[key]["name"], "kind": "private"}


def _load_real(split, n, include_spam):
    rnd = random.Random(REAL_SEED)
    sets = {
        "phishing": ("phishing", C.read_mbox(os.path.join(DATA_DIR, C.SOURCES["phishing"]["file"]))),
        "legit": ("ham", C.read_tar(os.path.join(DATA_DIR, C.SOURCES["ham"]["file"]))),
    }
    if include_spam:
        sets["spam"] = ("spam", C.read_tar(os.path.join(DATA_DIR, C.SOURCES["spam"]["file"])))
    samples = []
    for label, (_, it) in sets.items():
        items = list(it)
        if split != "all":
            items = [s for s in items if C.half(s) == split]
        rnd.shuffle(items)
        for s in items[:n]:
            samples.append({**s, "label": label, "category": ""})
    return samples, {"name": "Real public corpora", "kind": "real"}


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
        cleaned.append({
            "label": label, "sender": sender, "reply_to": str(r.get("reply_to") or "")[:500],
            "subject": str(r.get("subject") or "")[:500], "content": str(r.get("content") or "")[:fm],
            "category": str(r.get("category") or "")[:60],
        })
    labels = {c["label"] for c in cleaned}
    if labels != {"phishing", "legit"}:
        raise ValueError("The file needs at least one 'phishing' and one 'legit' row with a valid sender "
                         f"(read {len(cleaned)} usable rows, skipped {skipped}).")
    return cleaned, skipped


# ── scoring + summary ─────────────────────────────────────────────────────────
def _summarize(scored, spec, meta, crashes, skipped, seconds):
    rows = [r for r in scored if r["label"] in ("phishing", "legit")]
    spam = [r for r in scored if r["label"] == "spam"]
    show_sender = meta["kind"] != "real"        # real corpora: only the sender domain is kept
    op = {"medium_or_above": M.metrics(rows, M.MEDIUM_T), "high_only": M.metrics(rows, M.HIGH_T)}

    per_cat = []
    cats = defaultdict(list)
    for r in rows:
        if r["category"]:
            cats[(r["label"], r["category"])].append(r)
    for (label, cat), items in sorted(cats.items()):
        correct = sum((r["score"] >= M.MEDIUM_T) == (label == "phishing") for r in items)
        per_cat.append({"label": label, "category": cat, "n": len(items), "correct": correct,
                        "rate": correct / len(items), "mean_score": sum(r["score"] for r in items) / len(items)})

    wrong = [r for r in rows if (r["score"] >= M.MEDIUM_T) != (r["label"] == "phishing")]
    wrong.sort(key=lambda r: -abs(r["score"] - M.MEDIUM_T))
    errors = [{"label": r["label"], "category": r["category"], "who": r["sender"] if show_sender else r["domain"],
               "score": r["score"], "level": r["level"], "signals": r["signals"]} for r in wrong[:MAX_ERRORS]]

    def top(pred):
        return Counter(s for r in rows if pred(r) for s in r["signals"]).most_common(8)

    result = {
        "dataset": spec["dataset"], "name": meta["name"], "kind": meta["kind"],
        "options": {k: spec[k] for k in ("split", "n", "include_spam") if k in spec},
        "finished_at": _now(), "duration_s": round(seconds, 1),
        "counts": {"phishing": sum(r["label"] == "phishing" for r in rows),
                   "legit": sum(r["label"] == "legit" for r in rows), "spam": len(spam),
                   "crashes": crashes, "skipped": skipped},
        "auc": M.auc(rows), "operating_points": op, "sweep": M.sweep(rows),
        "per_category": per_cat, "errors": errors, "error_total": len(wrong),
        "top_signals_missed": top(lambda r: r["label"] == "phishing" and r["score"] < M.MEDIUM_T),
        "top_signals_false_positive": top(lambda r: r["label"] == "legit" and r["score"] >= M.MEDIUM_T),
        "spam_flag_rate": (sum(r["score"] >= M.MEDIUM_T for r in spam) / len(spam)) if spam else None,
    }
    return result


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
        if spec["dataset"] in PRIVATE:
            samples, meta = _load_private(spec["dataset"])
        elif spec["dataset"] == "real":
            samples, meta = _load_real(spec["split"], spec["n"], spec["include_spam"])
        else:
            samples, skipped = spec["rows"], spec.get("skipped", 0)
            meta = {"name": "Uploaded file", "kind": "custom"}
        job.update(phase="scoring", total=len(samples), done=0)

        det = PhishingDetector(use_whois=False)
        scored, crashes = [], 0
        for i, s in enumerate(samples, 1):
            try:
                res = det.analyze({"sender": s["sender"], "reply_to": s.get("reply_to", ""),
                                   "subject": s.get("subject", ""), "content": s.get("content", "")})
                scored.append({"label": s["label"], "category": s.get("category", ""), "sender": s["sender"][:200],
                               "domain": res["domain"], "score": res["risk_level"], "level": res["risk_score"],
                               "signals": sorted({w["type"] for w in res["warnings"]})})
            except Exception:
                crashes += 1
            job["done"] = i
        if not any(r["label"] == "phishing" for r in scored) or not any(r["label"] == "legit" for r in scored):
            raise ValueError("The selection needs both phishing and legitimate emails.")
        result = _summarize(scored, spec, meta, crashes, skipped, time.time() - t0)
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
        if split not in ("dev", "test", "all"):
            raise ValueError("split must be dev, test or all")
        try:
            n = int(body.get("n", LIMITS["real_default_n"]))
        except (TypeError, ValueError):
            raise ValueError("n must be a number")
        n = max(LIMITS["real_min_n"], min(n, LIMITS["real_max_n"]))
        spam = bool(body.get("include_spam", False))
        if not _real_ready(spam):
            raise ValueError("Download the public corpora first.")
        return {"dataset": "real", "split": split, "n": n, "include_spam": spam}
    if dataset == "custom":
        rows, skipped = _clean_custom(body.get("rows"))
        return {"dataset": "custom", "rows": rows, "skipped": skipped}
    raise ValueError("Unknown dataset.")


def _job_view(job):
    keys = ("id", "state", "phase", "done", "total", "error", "result", "dataset", "created_at")
    return {k: job.get(k) for k in keys}


# ── routes ────────────────────────────────────────────────────────────────────
@bp.route("/datasets", methods=["GET"])
def datasets():
    with _lock:
        dl = dict(_download)
    return jsonify({
        "private": _private_info(),
        "real": {"files": _real_files(), "ready": _real_ready(False), "download": dl,
                 "note": "Public corpora are fetched on request from their original sites and are not "
                         "redistributed with this project. They are 2002-2015 era mail."},
        "limits": LIMITS,
    })


@bp.route("/real/download", methods=["POST"])
def real_download():
    body = request.get_json(silent=True) or {}
    if not start_download(bool(body.get("include_spam", True))):
        return jsonify({"error": "A download is already running."}), 409
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
        spec = _validate_spec(request.get_json(silent=True) or {})
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

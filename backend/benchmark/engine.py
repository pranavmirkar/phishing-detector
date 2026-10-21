"""Shared benchmark engine: load -> score -> summarize.

Used by the dashboard's /api/benchmarks service and by the command-line scripts so both
produce identical numbers.
"""
import os
import random
import time
from collections import Counter, defaultdict

from benchmark import corpora as C
from benchmark import metrics as M

MAX_ERRORS = 60
REAL_SEED = 11


# ── loading ───────────────────────────────────────────────────────────────────
def present_sources(data_dir):
    return {k: os.path.join(data_dir, v["file"]) for k, v in C.SOURCES.items()
            if os.path.exists(os.path.join(data_dir, v["file"])) and os.path.getsize(os.path.join(data_dir, v["file"])) > 0}


def load_real(data_dir, split, n, include_spam=False, seed=REAL_SEED):
    """Samples for a split ("dev" | "test" | "all"), at most `n` per class, plus the source ids used."""
    rnd = random.Random(seed)
    have = present_sources(data_dir)
    pools = {"phishing": [], "legit": [], "spam": []}
    used = []
    for key in C.wanted(split) + (["spam"] if include_spam else []):
        if key not in have:
            continue
        src = C.SOURCES[key]
        items = list(C.read_source(have[key], src["kind"]))
        if src["role"] == "hash" and split != "all":
            items = [s for s in items if C.half(s) == split]
        rnd.shuffle(items)
        if src.get("cap"):
            items = items[:src["cap"]]
        for s in items:
            s["source"], s["label"], s["category"] = key, src["label"], ""
        pools[src["label"]] += items
        used.append(key)
    samples = []
    for items in pools.values():
        rnd.shuffle(items)
        samples += items[:n]
    return samples, used


# ── scoring ───────────────────────────────────────────────────────────────────
def score(samples, detector, progress=None, drop=()):
    """`drop` names input fields to blank out (ablation), e.g. ("recipient", "auth_results")."""
    scored, crashes, times = [], 0, []
    for i, s in enumerate(samples, 1):
        t0 = time.perf_counter()
        try:
            res = detector.analyze({k: ("" if k in drop else s.get(k, "")) for k in (
                "sender", "reply_to", "subject", "content", "auth_results", "return_path", "attachments", "list_id", "recipient")})
            times.append((time.perf_counter() - t0) * 1000)
            scored.append({"label": s["label"], "category": s.get("category", ""), "source": s.get("source", ""),
                           "sender": s["sender"][:200], "domain": res["domain"], "score": res["risk_level"],
                           "level": res["risk_score"], "signals": sorted({w["type"] for w in res["warnings"]})})
        except Exception:
            crashes += 1
        if progress:
            progress(i)
    return scored, crashes, times


# ── summary ───────────────────────────────────────────────────────────────────
def _pctl(xs, q):
    if not xs:
        return None
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


def summarize(scored, meta, crashes=0, skipped=0, seconds=0.0, times=(), show_sender=True):
    rows = [r for r in scored if r["label"] in ("phishing", "legit")]
    spam = [r for r in scored if r["label"] == "spam"]
    op = {"medium_or_above": M.with_intervals(M.metrics(rows, M.MEDIUM_T)),
          "high_only": M.with_intervals(M.metrics(rows, M.HIGH_T))}

    cats = defaultdict(list)
    for r in rows:
        if r["category"]:
            cats[(r["label"], r["category"])].append(r)
    per_cat = []
    for (label, cat), items in sorted(cats.items()):
        correct = sum((r["score"] >= M.MEDIUM_T) == (label == "phishing") for r in items)
        per_cat.append({"label": label, "category": cat, "n": len(items), "correct": correct,
                        "rate": correct / len(items), "mean_score": sum(r["score"] for r in items) / len(items)})

    srcs = defaultdict(list)
    for r in scored:
        if r["source"]:
            srcs[r["source"]].append(r)
    per_source = []
    for key, items in sorted(srcs.items()):
        flagged = sum(r["score"] >= M.MEDIUM_T for r in items)
        label = items[0]["label"]
        per_source.append({"source": key, "name": C.SOURCES[key]["name"] if key in C.SOURCES else key, "label": label,
                           "n": len(items), "flagged": flagged, "rate": flagged / len(items),
                           "ci": M.wilson(flagged, len(items))})

    wrong = [r for r in rows if (r["score"] >= M.MEDIUM_T) != (r["label"] == "phishing")]
    wrong.sort(key=lambda r: -abs(r["score"] - M.MEDIUM_T))
    errors = [{"label": r["label"], "category": r["category"], "source": r["source"],
               "who": r["sender"] if show_sender else r["domain"],
               "score": r["score"], "level": r["level"], "signals": r["signals"]} for r in wrong[:MAX_ERRORS]]

    def top(pred):
        return Counter(s for r in rows if pred(r) for s in r["signals"] if s != "TRUSTED_VERIFIED").most_common(8)

    return {
        **meta,
        "schema": 2,                      # the dashboard ignores saved results from older schemas
        "duration_s": round(seconds, 1),
        "counts": {"phishing": sum(r["label"] == "phishing" for r in rows), "legit": sum(r["label"] == "legit" for r in rows),
                   "spam": len(spam), "crashes": crashes, "skipped": skipped},
        "auc": M.auc(rows), "operating_points": op, "sweep": M.sweep(rows),
        "fixed_fpr": [M.recall_at_fpr(rows, t) for t in M.FPR_TARGETS],
        "per_category": per_cat, "per_source": per_source,
        "errors": errors, "error_total": len(wrong),
        "top_signals_missed": top(lambda r: r["label"] == "phishing" and r["score"] < M.MEDIUM_T),
        "top_signals_false_positive": top(lambda r: r["label"] == "legit" and r["score"] >= M.MEDIUM_T),
        "spam_flag_rate": (sum(r["score"] >= M.MEDIUM_T for r in spam) / len(spam)) if spam else None,
        "latency_ms": {"mean": round(sum(times) / len(times), 1), "p50": round(_pctl(times, .5), 1),
                       "p95": round(_pctl(times, .95), 1)} if times else None,
    }

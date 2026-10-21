"""Pure metric helpers shared by the CLI benchmarks and the /api/benchmarks service.

Every function takes rows that carry a ground-truth ``label`` ("phishing" | "legit")
and a numeric ``score`` (0-100). Positive class = phishing.
"""
import random
from collections import defaultdict

MEDIUM_T, HIGH_T = 25, 55      # the detector's own MEDIUM / HIGH cut-offs


def confusion(rows, thr):
    tp = sum(r["label"] == "phishing" and r["score"] >= thr for r in rows)
    fn = sum(r["label"] == "phishing" and r["score"] < thr for r in rows)
    fp = sum(r["label"] == "legit" and r["score"] >= thr for r in rows)
    tn = sum(r["label"] == "legit" and r["score"] < thr for r in rows)
    return tp, fp, tn, fn


def metrics(rows, thr):
    tp, fp, tn, fn = confusion(rows, thr)
    n = tp + fp + tn + fn
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    spec = tn / (tn + fp) if tn + fp else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {
        "threshold": thr, "n": n, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": (tp + tn) / n if n else 0.0,
        "balanced_accuracy": (rec + spec) / 2,
        "precision": prec, "recall": rec, "specificity": spec, "f1": f1,
        "false_positive_rate": 1 - spec,
    }


def auc(rows):
    """ROC AUC via the rank-sum (Mann-Whitney) formulation. None if a class is missing."""
    pos = [r["score"] for r in rows if r["label"] == "phishing"]
    neg = [r["score"] for r in rows if r["label"] == "legit"]
    if not pos or not neg:
        return None
    wins = sum((p > q) + 0.5 * (p == q) for p in pos for q in neg)
    return wins / (len(pos) * len(neg))


def sweep(rows, step=5):
    return [metrics(rows, t) for t in range(step, 101, step)]


def stratified_split(rows, test_frac=0.3, seed=7):
    rnd = random.Random(seed)
    dev, test = [], []
    by = defaultdict(list)
    for r in rows:
        by[r["label"]].append(r)
    for items in by.values():
        items = items[:]
        rnd.shuffle(items)
        k = round(len(items) * test_frac)
        test += items[:k]
        dev += items[k:]
    return dev, test


def best_threshold(rows):
    best = None
    for t in range(5, 101, 5):
        m = metrics(rows, t)
        key = (m["f1"], t)
        if best is None or key > best[0]:
            best = (key, t)
    return best[1]


# ── Real-world oriented metrics ───────────────────────────────────────────────
def wilson(k, n, z=1.96):
    """95% Wilson score interval for a proportion k/n. (0, 1) when n == 0."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def precision_at_prevalence(recall, fpr, prevalence):
    """Precision you would see if only `prevalence` of all mail were phishing.

    Test sets are roughly balanced, so their raw precision hides how many false alarms a
    real inbox gets: with 1 phishing email per 100, even a 1% false-alarm rate halves precision.
    """
    tp = recall * prevalence
    fp = fpr * (1 - prevalence)
    return tp / (tp + fp) if tp + fp else 0.0


PREVALENCES = (0.01, 0.05, 0.20)


def with_intervals(m):
    """Add confidence intervals, false alarms per 1,000 legit mails and prevalence-adjusted precision."""
    out = dict(m)
    pos, neg = m["tp"] + m["fn"], m["fp"] + m["tn"]
    out["recall_ci"] = wilson(m["tp"], pos)
    out["false_positive_rate_ci"] = wilson(m["fp"], neg)
    out["precision_ci"] = wilson(m["tp"], m["tp"] + m["fp"])
    out["fp_per_1000"] = m["false_positive_rate"] * 1000
    out["fp_per_1000_ci"] = tuple(x * 1000 for x in out["false_positive_rate_ci"])
    out["precision_at_prevalence"] = {str(p): precision_at_prevalence(m["recall"], m["false_positive_rate"], p) for p in PREVALENCES}
    out["positives"], out["negatives"] = pos, neg
    return out


def recall_at_fpr(rows, target):
    """Highest-recall cut-off whose false-alarm rate is <= target (threshold chosen ON these rows)."""
    best = None
    for t in range(1, 101):
        m = metrics(rows, t)
        if m["false_positive_rate"] <= target:
            best = (t, m)
            break                              # thresholds ascend, so the first hit has the most recall
    if best is None:
        m = metrics(rows, 101)
        return {"target": target, "threshold": None, "recall": m["recall"], "fpr": m["false_positive_rate"]}
    t, m = best
    return {"target": target, "threshold": t, "recall": m["recall"], "fpr": m["false_positive_rate"]}


def threshold_for_fpr(rows, target):
    """Lowest cut-off meeting the false-alarm budget on `rows` (None if impossible)."""
    return recall_at_fpr(rows, target)["threshold"]


FPR_TARGETS = (0.01, 0.005, 0.001)

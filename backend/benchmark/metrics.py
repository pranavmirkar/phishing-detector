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

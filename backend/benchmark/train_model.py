"""
Train the scoring model (backend/model_v1.json).

    pip install -r requirements-dev.txt          # scikit-learn + numpy: training only, never at runtime
    python -P benchmark/train_model.py           # needs the public corpora (Benchmarks tab, or see corpora.py)

What it does
  1. Runs the rule engine (model off) over the DEV and VAL splits and records, for every email, the
     per-signal points and the era-neutral lexical features (model.featurize: identical code at train
     and serve time).
  2. Fits a small gradient-boosted-tree classifier.
  3. Calibrates the verdict thresholds from OUT-OF-FOLD predictions (5-fold, all mail from one sender
     in one fold): MEDIUM = raw score where 1% of legitimate mail would be flagged, HIGH = 0.1%.
  4. Exports the trees to JSON, verifies the pure-Python evaluator reproduces scikit-learn exactly,
     and reports recall / false alarms on `test_seen` (emails scored once before; never trained on).

The locked `test` split is never read here. See README, "Accuracy", for the protocol.
"""
import argparse
import datetime
import hashlib
import json
import os
import pickle
import sys
import time
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
os.chdir(BACKEND)
sys.path.insert(0, BACKEND)

import numpy as np  # noqa: E402
from sklearn.ensemble import HistGradientBoostingClassifier  # noqa: E402
from sklearn.model_selection import GroupKFold  # noqa: E402

import detector as D  # noqa: E402
import model as M  # noqa: E402
from benchmark import corpora as C, engine  # noqa: E402

DATA = os.path.join(BACKEND, "benchmark", "data", "real")
# Structural impersonation signals: whatever the training mix says, a homoglyph/lookalike of a protected brand keeps its rule points as a floor.
FLOOR_ALWAYS = ["LOOKALIKE_DOMAIN", "HOMOGLYPH_ATTACK"]
PARAMS = dict(max_depth=4, max_iter=250, learning_rate=0.05, l2_regularization=5.0, random_state=0, early_stopping=False)   # chosen by grouped CV on train data


def _code_hash():
    h = hashlib.md5()
    for f in ("detector.py", "brands.py", "emailparse.py", "model.py", "benchmark/corpora.py", "benchmark/engine.py"):
        h.update(open(os.path.join(BACKEND, f), "rb").read())
    return h.hexdigest()[:10]


def collect(split):
    """[(features, label, group, source)] for a split, from the rule engine. Cached per code version."""
    cache = os.path.join(DATA, ".cache", f"features-{split}-{_code_hash()}.pkl")
    if os.path.exists(cache):
        with open(cache, "rb") as f:
            return pickle.load(f)
    samples, _ = engine.load_real(DATA, split, 10 ** 6, False)
    det = D.PhishingDetector(use_whois=False, use_model=False, return_features=True)
    rows, t0 = [], time.time()
    for i, s in enumerate(samples, 1):
        r = det.analyze({k: s.get(k, "") for k in ("sender", "reply_to", "subject", "content", "auth_results",
                                                    "return_path", "attachments", "list_id", "recipient")})
        rows.append((r["model_features"], int(s["label"] == "phishing"), s["sender"].lower().split("<")[-1].strip(" >"), s["source"]))
        if i % 1000 == 0:
            print(f"  {split}: {i}/{len(samples)} ({time.time() - t0:.0f}s)", flush=True)
    os.makedirs(os.path.dirname(cache), exist_ok=True)
    with open(cache, "wb") as f:
        pickle.dump(rows, f, protocol=4)
    return rows


def matrix(rows, names):
    index = {n: i for i, n in enumerate(names)}
    X = np.zeros((len(rows), len(names)))
    for i, (feats, *_rest) in enumerate(rows):
        for k, v in feats.items():
            j = index.get(k)
            if j is not None:
                X[i, j] = v
    return X


def export_trees(gb):
    trees = []
    for preds in gb._predictors:
        nodes = preds[0].nodes
        t = {"f": [], "t": [], "l": [], "r": [], "v": []}
        for nd in nodes:
            leaf = bool(nd["is_leaf"])
            t["f"].append(-1 if leaf else int(nd["feature_idx"]))
            t["t"].append(0.0 if leaf else float(nd["num_threshold"]))
            t["l"].append(-1 if leaf else int(nd["left"]))
            t["r"].append(-1 if leaf else int(nd["right"]))
            t["v"].append(float(nd["value"]) if leaf else 0.0)
        trees.append(t)
    return trees


def rate(scores, labels, thr):
    pos, neg = scores[labels == 1], scores[labels == 0]
    return float((pos >= thr).mean()), float((neg >= thr).mean())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(BACKEND, "model_v1.json"))
    ap.add_argument("--dump-oof", type=int, default=0, help="print N out-of-fold misses / false alarms (training data) for error analysis")
    a = ap.parse_args()

    print("collecting features (dev, val, test_seen) ...")
    dev, val, seen = collect("dev"), collect("val"), collect("test_seen")
    train = dev + val
    sigs = sorted({k for feats, *_ in train for k in feats if k.startswith("sig:")})
    names = sigs + M.EXTRA_FEATURES + M.LEXICAL_FEATURES
    X, y = matrix(train, names), np.array([r[1] for r in train])
    groups = np.array([zlib.crc32(r[2].encode("utf-8", "ignore")) for r in train])
    print(f"training rows: {len(train)} ({int(y.sum())} phishing, {int((1 - y).sum())} legit), {len(names)} features")

    # out-of-fold scores -> honest threshold calibration (same sender never in train and held-out)
    oof = np.zeros(len(train))
    for k, (tr, te) in enumerate(GroupKFold(n_splits=5).split(X, y, groups)):
        m = HistGradientBoostingClassifier(**PARAMS).fit(X[tr], y[tr])
        oof[te] = m.decision_function(X[te])
    legit, phish = oof[y == 0], oof[y == 1]
    t_med = float(np.quantile(legit, 0.99))
    t_high = float(np.quantile(legit, 0.999))
    raw_lo = float(np.median(legit))
    raw_hi = max(float(np.quantile(phish, 0.9)), t_high + 1.0)
    t_high = max(t_high, t_med + 0.25)
    raw_lo = min(raw_lo, t_med - 1.0)
    print(f"out-of-fold: MEDIUM raw >= {t_med:.2f} (1% legit), HIGH raw >= {t_high:.2f} (0.1% legit); "
          f"recall {rate(oof, y, t_med)[0]*100:.1f}% / {rate(oof, y, t_high)[0]*100:.1f}%")

    if a.dump_oof:
        order = np.argsort(oof)
        print("--- phishing the model scores lowest out-of-fold (missed)")
        shown = 0
        for i in order:
            if y[i] == 1 and oof[i] < t_med and shown < a.dump_oof:
                f = train[i][0]
                print(f"  raw {oof[i]:5.2f} {train[i][3]:12s} {train[i][2][:40]:40s} signals={[k[4:] for k in f if k.startswith('sig:')][:5]}")
                shown += 1
        print("--- legitimate mail scored highest out-of-fold (false alarms)")
        shown = 0
        for i in order[::-1]:
            if y[i] == 0 and shown < a.dump_oof:
                f = train[i][0]
                print(f"  raw {oof[i]:5.2f} {train[i][3]:12s} {train[i][2][:40]:40s} signals={[k[4:] for k in f if k.startswith('sig:')][:5]}")
                shown += 1
    gb = HistGradientBoostingClassifier(**PARAMS).fit(X, y)
    spec = {
        "version": "1", "features": names, "baseline": float(np.ravel(gb._baseline_prediction)[0]), "trees": export_trees(gb),
        "anchors": {"raw": [raw_lo, t_med, t_high, raw_hi], "risk": [0, 25, 55, 100]},
        "meta": {
            "trained": datetime.date.today().isoformat(), "algorithm": "HistGradientBoostingClassifier", "params": PARAMS,
            "rows": len(train), "phishing": int(y.sum()), "legit": int((1 - y).sum()),
            "splits": ["dev", "val"], "oof_recall_medium": rate(oof, y, t_med)[0], "oof_recall_high": rate(oof, y, t_high)[0],
            "thresholds": {"medium_fpr": 0.01, "high_fpr": 0.001},
            "note": "Trained on public corpora only (see README). Thresholds are false-alarm budgets on that legitimate mail.",
        },
    }
    support = {}
    for feats, label, *_rest in train:
        if label:
            for k, v in feats.items():
                if k.startswith("sig:") and v > 0:
                    support[k[4:]] = support.get(k[4:], 0) + 1
    spec["support"], spec["min_support"] = support, 20
    spec["floor_always"] = FLOOR_ALWAYS
    model = M.Model(spec)

    # the exported pure-Python model must reproduce scikit-learn exactly
    sample = np.random.RandomState(0).choice(len(train), 300, replace=False)
    worst = max(abs(model.raw(train[i][0]) - float(gb.decision_function(X[i:i + 1])[0])) for i in sample)
    assert worst < 1e-5, f"exported trees differ from scikit-learn by {worst}"
    print(f"export check: max |difference| vs scikit-learn = {worst:.2e}")

    ys = np.array([r[1] for r in seen])
    def level(feats):
        pts = {k[4:]: v * 50.0 for k, v in feats.items() if k.startswith("sig:")}
        return max(model.risk(model.raw(feats)), min(100, int(round(model.unsupported_points(pts)))))

    sc = np.array([level(r[0]) for r in seen])
    for label, thr in (("MEDIUM (25)", 25), ("HIGH (55)", 55)):
        rec, fpr = rate(sc, ys, thr)
        print(f"test_seen {label}: recall {rec*100:.1f}%  false alarms {fpr*1000:.1f}/1000")
    spec["meta"]["test_seen"] = {"medium": dict(zip(("recall", "fpr"), rate(sc, ys, 25))), "high": dict(zip(("recall", "fpr"), rate(sc, ys, 55)))}

    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(spec, f, separators=(",", ":"))
    print(f"wrote {a.out} ({os.path.getsize(a.out) // 1024} KB)")


if __name__ == "__main__":
    main()

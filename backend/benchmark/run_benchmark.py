"""
Validation benchmark for the PhishGuard detector.

Runs every sample in dataset.jsonl through PhishingDetector.analyze() (the same
code path the /api/analyze endpoint uses) and reports accuracy metrics.

  python benchmark/run_benchmark.py

Outputs (next to this file): results.json, REPORT.md

Notes
- WHOIS lookups are disabled so results are deterministic and offline-friendly.
  (Domain-age scoring is therefore NOT exercised.)
- The trusted-domain list is read from phishing.db (Tranco top 50K), so exact
  numbers can shift slightly if that list is refreshed.
- Positive class = phishing.
"""
import json
import os
import random
import sys
from collections import defaultdict
from datetime import date

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
os.chdir(BACKEND)               # detector opens "phishing.db" relatively
sys.path.insert(0, BACKEND)

import detector as detector_mod  # noqa: E402
from domain_intel import get_intel_status  # noqa: E402

detector_mod.check_domain_age = lambda domain: {}   # offline: no WHOIS

MEDIUM_T, HIGH_T = 25, 55       # the detector's own MEDIUM / HIGH cut-offs
SEED = 7


def load():
    with open(os.path.join(HERE, "dataset.jsonl"), encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def run(rows):
    det = detector_mod.PhishingDetector()
    out = []
    for r in rows:
        res = det.analyze({
            "sender": r["sender"], "reply_to": r["reply_to"],
            "subject": r["subject"], "content": r["content"],
        })
        out.append({**r, "score": res["risk_level"], "level": res["risk_score"],
                    "signals": sorted({w["type"] for w in res["warnings"]})})
    return out


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
    pos = [r["score"] for r in rows if r["label"] == "phishing"]
    neg = [r["score"] for r in rows if r["label"] == "legit"]
    wins = sum((p > q) + 0.5 * (p == q) for p in pos for q in neg)
    return wins / (len(pos) * len(neg))


def stratified_split(rows, test_frac=0.3):
    rnd = random.Random(SEED)
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


def pct(x):
    return f"{x * 100:.1f}%"


def main():
    rows = run(load())
    intel = get_intel_status()
    total = len(rows)

    op = {"medium_or_above": metrics(rows, MEDIUM_T), "high_only": metrics(rows, HIGH_T)}
    sweep = [metrics(rows, t) for t in range(5, 101, 5)]

    dev, test = stratified_split(rows)
    tuned_t = best_threshold(dev)
    holdout = {
        "dev_n": len(dev), "test_n": len(test), "threshold_chosen_on_dev": tuned_t,
        "dev": metrics(dev, tuned_t), "test": metrics(test, tuned_t),
        "test_at_default_medium": metrics(test, MEDIUM_T),
    }

    cats = defaultdict(list)
    for r in rows:
        cats[(r["label"], r["category"])].append(r)
    per_cat = []
    for (label, cat), items in sorted(cats.items()):
        correct = sum((r["score"] >= MEDIUM_T) == (label == "phishing") for r in items)
        per_cat.append({"label": label, "category": cat, "n": len(items),
                        "correct": correct, "rate": correct / len(items),
                        "mean_score": sum(r["score"] for r in items) / len(items)})

    errors = [
        {"id": r["id"], "label": r["label"], "category": r["category"], "sender": r["sender"],
         "score": r["score"], "level": r["level"], "signals": r["signals"]}
        for r in rows if (r["score"] >= MEDIUM_T) != (r["label"] == "phishing")
    ]

    results = {
        "date": date.today().isoformat(), "samples": total,
        "phishing": sum(r["label"] == "phishing" for r in rows),
        "legit": sum(r["label"] == "legit" for r in rows),
        "tranco_domains": intel.get("domain_count"), "auc": auc(rows),
        "operating_points": op, "holdout": holdout, "per_category": per_cat,
        "errors": errors, "sweep": sweep,
    }
    with open(os.path.join(HERE, "results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    write_report(results)

    m = op["medium_or_above"]
    print(f"{total} samples | MEDIUM+ accuracy {pct(m['accuracy'])}  precision {pct(m['precision'])}  "
          f"recall {pct(m['recall'])}  F1 {pct(m['f1'])}  AUC {results['auc']:.3f}")
    h = op["high_only"]
    print(f"HIGH only          accuracy {pct(h['accuracy'])}  precision {pct(h['precision'])}  "
          f"recall {pct(h['recall'])}  F1 {pct(h['f1'])}")
    t = holdout["test"]
    print(f"held-out test ({holdout['test_n']}) @ threshold {tuned_t}: accuracy {pct(t['accuracy'])}  F1 {pct(t['f1'])}")
    print("report ->", os.path.join(HERE, "REPORT.md"))


def mrow(name, m):
    return (f"| {name} | {m['threshold']} | {pct(m['accuracy'])} | {pct(m['balanced_accuracy'])} | "
            f"{pct(m['precision'])} | {pct(m['recall'])} | {pct(m['specificity'])} | {pct(m['f1'])} |")


def write_report(r):
    op, ho = r["operating_points"], r["holdout"]
    L = []
    L.append("# PhishGuard validation benchmark\n")
    L.append(f"Run date: {r['date']}  |  Samples: {r['samples']} "
             f"({r['phishing']} phishing, {r['legit']} legitimate)  |  Trusted-domain list: "
             f"{r['tranco_domains']:,} Tranco domains  |  ROC AUC: **{r['auc']:.3f}**\n")
    L.append("## Overall results\n")
    L.append("Positive class = phishing. An email is flagged when its risk score is at or above the threshold.\n")
    L.append("| Operating point | Threshold | Accuracy | Balanced acc. | Precision | Recall | Specificity | F1 |")
    L.append("|---|---|---|---|---|---|---|---|")
    L.append(mrow("MEDIUM or HIGH flagged", op["medium_or_above"]))
    L.append(mrow("HIGH only flagged", op["high_only"]))
    L.append("")
    for name, m in (("MEDIUM or HIGH flagged", op["medium_or_above"]), ("HIGH only flagged", op["high_only"])):
        L.append(f"Confusion matrix, {name}: TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}  ")
    L.append("\n## Held-out validation\n")
    L.append(f"The dataset was split 70/30 (stratified, seed {SEED}). The score threshold was chosen on the "
             f"{ho['dev_n']}-sample development part by maximising F1, then applied once to the "
             f"{ho['test_n']}-sample test part. No detector rules were changed using the test part.\n")
    L.append("| Set | Threshold | Accuracy | Balanced acc. | Precision | Recall | Specificity | F1 |")
    L.append("|---|---|---|---|---|---|---|---|")
    L.append(mrow("Development", ho["dev"]))
    L.append(mrow("Test (held out)", ho["test"]))
    L.append(mrow("Test at default MEDIUM cut-off", ho["test_at_default_medium"]))
    L.append("\n## Per-category results (flagged at MEDIUM or above)\n")
    L.append("`rate` is the share classified correctly: detected for phishing categories, not flagged for legitimate ones.\n")
    L.append("| Class | Category | n | Correct | Rate | Mean score |")
    L.append("|---|---|---|---|---|---|")
    for c in r["per_category"]:
        L.append(f"| {c['label']} | {c['category']} | {c['n']} | {c['correct']} | {pct(c['rate'])} | {c['mean_score']:.0f} |")
    L.append("\n## Threshold sweep\n")
    L.append("| Threshold | Precision | Recall | FPR | F1 | Accuracy |")
    L.append("|---|---|---|---|---|---|")
    for m in r["sweep"]:
        L.append(f"| {m['threshold']} | {pct(m['precision'])} | {pct(m['recall'])} | {pct(m['false_positive_rate'])} | {pct(m['f1'])} | {pct(m['accuracy'])} |")
    L.append(f"\n## Misclassified samples at MEDIUM or above ({len(r['errors'])})\n")
    if r["errors"]:
        L.append("| id | Truth | Category | Sender | Score | Signals fired |")
        L.append("|---|---|---|---|---|---|")
        for e in r["errors"]:
            L.append(f"| {e['id']} | {e['label']} | {e['category']} | `{e['sender']}` | {e['score']} | {', '.join(e['signals']) or 'none'} |")
    else:
        L.append("None.")
    L.append("\n## How to reproduce\n")
    L.append("```bash\ncd backend\npython benchmark/build_dataset.py   # regenerates dataset.jsonl (seeded)\npython benchmark/run_benchmark.py   # writes results.json and this report\n```\n")
    L.append("## Limitations\n")
    L.append("- The dataset is synthetic and was written by the project author's tooling, not collected from real "
             "mailboxes or a public corpus. Real-world accuracy will differ; treat these numbers as a regression "
             "baseline and a validation of the rule logic, not a field accuracy estimate.\n"
             "- Several phishing categories (typosquats, homoglyphs) are exactly what the Levenshtein layer is built "
             "to catch, so high scores there are expected.\n"
             "- WHOIS domain-age scoring was disabled, so brand-new-domain detection is not evaluated.\n"
             "- Only the sender domain, subject and body are scored; attachments, headers (SPF/DKIM/DMARC) and "
             "message rendering are out of scope.\n")
    with open(os.path.join(HERE, "REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L))


if __name__ == "__main__":
    main()

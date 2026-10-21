"""
Real-world evaluation on public email corpora (not written by this project).

  python -P benchmark/eval_real.py --split dev        # older phishing (2015-2022) + legit: where rules are diagnosed
  python -P benchmark/eval_real.py --split test       # recent phishing (2023-2025): locked, time-held-out
  python -P benchmark/eval_real.py --split both       # dev, then test at a cut-off calibrated on dev

Download the corpora from the dashboard's Benchmarks tab (or place the files listed in
benchmark/corpora.py in benchmark/data/real/). Credits: J. Nazario phishing corpus (CC BY 4.0),
Apache SpamAssassin public corpus, Apache Software Foundation mailing-list archives.

Notes worth quoting next to any number this prints
  * Legitimate mail comes from public sources only: 2002-03 personal/list mail (SpamAssassin)
    and 2025 developer mailing lists (Apache). Marketing mail, receipts and corporate mail are
    NOT represented, so false-alarm rates on those cannot be measured here.
  * The corpora contain no SPF results for legitimate mail, so false alarms caused by
    authentication failures are not measured either.
  * WHOIS is off. The detector was not tuned on the test split.
  * X-Spam-* headers (another filter's verdict) are never read.
Only aggregates and sender domains are written to disk.
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.environ.get("PG_BACKEND", os.path.dirname(HERE))   # PG_BACKEND: evaluate another copy of the backend
REPO_BACKEND = os.path.dirname(HERE)
os.chdir(BACKEND)
sys.path.insert(0, BACKEND)
sys.path.append(REPO_BACKEND)

import detector as detector_mod  # noqa: E402
from benchmark import engine, metrics as M  # noqa: E402

DATA_DIR = os.path.join(REPO_BACKEND, "benchmark", "data", "real")


def make_detector():
    try:
        return detector_mod.PhishingDetector(use_whois=False)
    except TypeError:                      # older copies without the flag
        detector_mod.check_domain_age = lambda domain: {}
        return detector_mod.PhishingDetector()


def run_split(split, n, spam, drop=()):
    samples, used = engine.load_real(DATA_DIR, split, n, spam)
    if not any(s["label"] == "phishing" for s in samples) or not any(s["label"] == "legit" for s in samples):
        raise SystemExit(f"split '{split}' needs both phishing and legit files in {DATA_DIR} (found: {used})")
    t0 = time.time()
    scored, crashes, times = engine.score(samples, make_detector(), drop=drop)
    res = engine.summarize(scored, {"dataset": "real", "split": split, "sources": used},
                           crashes, 0, time.time() - t0, times, show_sender=False)
    return res, scored


def pct(x):
    return f"{x * 100:.1f}%"


def show(name, res):
    c = res["counts"]
    lat = res["latency_ms"]
    print(f"\n== {name}: {c['phishing']} phishing / {c['legit']} legit (crashes {c['crashes']})  "
          f"latency p50 {lat['p50']} ms, p95 {lat['p95']} ms")
    for key, label in (("medium_or_above", "MEDIUM+ (25)"), ("high_only", "HIGH (55)")):
        m = res["operating_points"][key]
        lo, hi = m["recall_ci"]
        flo, fhi = m["false_positive_rate_ci"]
        print(f"  {label:13} recall {pct(m['recall'])} [{pct(lo)}-{pct(hi)}]   false alarms {m['fp_per_1000']:.1f}/1000 "
              f"(fpr {pct(m['false_positive_rate'])} [{pct(flo)}-{pct(fhi)}])   precision {pct(m['precision'])}   "
              f"precision@1%prev {pct(m['precision_at_prevalence']['0.01'])}")
    print("  best recall at a false-alarm budget (cut-off chosen on THIS set):",
          "  ".join(f"<= {pct(f['target'])}: {pct(f['recall'])}" for f in res["fixed_fpr"]))
    for s in res["per_source"]:
        print(f"    {s['label']:8} {s['name'][:50]:50} n={s['n']:4}  flagged {pct(s['rate'])}")
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["dev", "val", "test_seen", "test", "all", "both"], default="both",
                    help="both = dev, val and the locked test, with the cut-off calibrated on val and applied once to test")
    ap.add_argument("--n", type=int, default=600, help="max emails per class (seeded sample)")
    ap.add_argument("--spam", action="store_true", help="also score SpamAssassin spam (reported separately)")
    ap.add_argument("--fpr", type=float, default=0.005, help="false-alarm budget for dev calibration (with --split both)")
    ap.add_argument("--drop", default="", help="comma-separated input fields to blank out (ablation), "
                    "e.g. recipient,auth_results,return_path,attachments")
    ap.add_argument("--no-write", action="store_true")
    a = ap.parse_args()

    out, scored_by = {}, {}
    for sp in (["dev", "val", "test"] if a.split == "both" else [a.split]):
        res, scored = run_split(sp, a.n, a.spam, tuple(x for x in a.drop.split(",") if x))
        out[sp] = show(sp, res)
        scored_by[sp] = scored

    if a.split == "both":
        dev_rows = [r for r in scored_by["val"] if r["label"] in ("phishing", "legit")]
        test_rows = [r for r in scored_by["test"] if r["label"] in ("phishing", "legit")]
        t = M.threshold_for_fpr(dev_rows, a.fpr)
        if t is not None:
            m = M.with_intervals(M.metrics(test_rows, t))
            out["calibrated"] = {"fpr_budget": a.fpr, "threshold_from_val": t, "test": m}
            print(f"\n== Cut-off {t} chosen on VAL for <= {pct(a.fpr)} false alarms, applied once to TEST:")
            print(f"   test recall {pct(m['recall'])} [{pct(m['recall_ci'][0])}-{pct(m['recall_ci'][1])}]   "
                  f"false alarms {m['fp_per_1000']:.1f}/1000   precision {pct(m['precision'])}   "
                  f"precision@1%prev {pct(m['precision_at_prevalence']['0.01'])}")

    if not a.no_write:
        tag = f"_drop-{a.drop.replace(',', '+')}" if a.drop else ""
        for k, v in out.items():
            with open(os.path.join(HERE, f"results_real_{k}{tag}.json"), "w", encoding="utf-8") as f:
                json.dump(v, f, indent=2)


if __name__ == "__main__":
    main()

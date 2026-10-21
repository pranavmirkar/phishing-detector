"""
Real-world sanity check on public email corpora (not written by this project).

  phishing : Jose Nazario's phishing corpus (mbox)          https://monkey.org/~jose/phishing/
  ham      : SpamAssassin public corpus, easy_ham (tar.bz2)  https://spamassassin.apache.org/old/publiccorpus/
  spam     : SpamAssassin public corpus, spam (tar.bz2)      (reported separately: it is spam, not phishing)

The corpora are NOT redistributed here. Download them, then run (the -P flag keeps
the interpreter from importing anything from the data directory):

  python -P benchmark/eval_real.py --phishing P.mbox --ham H.tar.bz2 --spam S.tar.bz2

Caveats worth stating next to any number this prints:
  * The messages are 2002-2015 era; senders/domains are mostly historical.
  * WHOIS is disabled and the Tranco list is current, so trust lookups on old
    domains are only approximate.
  * Messages were not edited. The detector was NOT tuned on this data.
Only aggregate metrics and sender domains (no message text) are written to disk.
"""
import argparse
import json
import os
import random
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.environ.get("PG_BACKEND", os.path.dirname(HERE))   # PG_BACKEND: evaluate another copy of the backend
os.chdir(BACKEND)
sys.path.insert(0, BACKEND)
sys.path.append(os.path.dirname(HERE))

import detector as detector_mod  # noqa: E402
from benchmark.corpora import read_mbox, read_tar, half  # noqa: E402
from benchmark.metrics import MEDIUM_T, HIGH_T  # noqa: E402


def make_detector():
    try:
        return detector_mod.PhishingDetector(use_whois=False)
    except TypeError:
        detector_mod.check_domain_age = lambda domain: {}
        return detector_mod.PhishingDetector()


def score(samples):
    det = make_detector()
    out = []
    for s in samples:
        try:
            r = det.analyze(s)
            out.append((r["risk_level"], r["domain"], sorted({w["type"] for w in r["warnings"]})))
        except Exception as exc:                      # a crash on real mail is itself a finding
            out.append((None, "", [f"CRASH:{type(exc).__name__}"]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phishing", required=True)
    ap.add_argument("--ham", required=True)
    ap.add_argument("--spam")
    ap.add_argument("--n", type=int, default=500, help="max messages per class (seeded sample)")
    ap.add_argument("--split", choices=["dev", "test", "all"], default="all",
                    help="deterministic half of each corpus (by hash of sender+subject). Diagnose on dev, report on test.")
    ap.add_argument("--dump-misses", action="store_true", help="print sender/subject of errors (use on dev only)")
    a = ap.parse_args()

    rnd = random.Random(11)
    sets = {"phishing": list(read_mbox(a.phishing)), "legit": list(read_tar(a.ham))}
    if a.spam:
        sets["spam"] = list(read_tar(a.spam))
    for k, v in sets.items():
        if a.split != "all":
            v = [s for s in v if half(s) == a.split]
            sets[k] = v
        rnd.shuffle(v)
        sets[k] = v[: a.n]
        print(f"{k}: {len(v)} parsed, evaluating {len(sets[k])}")

    scored = {k: score(v) for k, v in sets.items()}
    if a.dump_misses:
        for k in ("phishing", "legit"):
            for samp, (sc, dom, sig) in zip(sets[k], scored[k]):
                if sc is not None and (sc >= MEDIUM_T) != (k == "phishing"):
                    print(f"[{k} score={sc}] {samp['sender'][:60]!r} | {samp['subject'][:60]!r} | {sig}")
    crashes = sum(1 for k in scored for sc, _, _ in scored[k] if sc is None)

    def rate(k, t):
        vals = [sc for sc, _, _ in scored[k] if sc is not None]
        return sum(sc >= t for sc in vals) / len(vals), len(vals)

    res = {"n": {k: len(v) for k, v in scored.items()}, "crashes": crashes}
    for t, name in ((MEDIUM_T, "medium_or_above"), (HIGH_T, "high_only")):
        tp = rate("phishing", t)[0]
        fp = rate("legit", t)[0]
        npos, nneg = rate("phishing", t)[1], rate("legit", t)[1]
        TP, FP = tp * npos, fp * nneg
        prec = TP / (TP + FP) if TP + FP else 0.0
        f1 = 2 * prec * tp / (prec + tp) if prec + tp else 0.0
        res[name] = {"phishing_recall": tp, "legit_false_positive_rate": fp,
                     "precision": prec, "f1": f1, "balanced_accuracy": (tp + 1 - fp) / 2,
                     "spam_flag_rate": rate("spam", t)[0] if "spam" in scored else None}
    res["top_signals_on_missed_phishing"] = Counter(
        s for sc, _, sig in scored["phishing"] if sc is not None and sc < MEDIUM_T for s in sig).most_common(8)
    res["top_signals_on_false_positives"] = Counter(
        s for sc, _, sig in scored["legit"] if sc is not None and sc >= MEDIUM_T for s in sig).most_common(8)
    res["false_positive_sender_domains"] = sorted(
        {d for sc, d, _ in scored["legit"] if sc is not None and sc >= MEDIUM_T})[:25]
    with open(os.path.join(HERE, f"results_real{'_' + a.split if a.split != 'all' else ''}.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()

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
import email
import json
import mailbox
import os
import random
import sys
import zlib
import tarfile
from collections import Counter
from email import policy
from email.utils import parseaddr

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.environ.get("PG_BACKEND", os.path.dirname(HERE))   # PG_BACKEND: evaluate another copy of the backend
os.chdir(BACKEND)
sys.path.insert(0, BACKEND)

import detector as detector_mod  # noqa: E402

detector_mod.check_domain_age = lambda domain: {}

MEDIUM_T, HIGH_T = 25, 55


def body_of(msg):
    plain, html = "", ""
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            text = part.get_content()
        except Exception:
            continue
        if not isinstance(text, str):
            continue
        if ctype == "text/html":
            html += text
        else:
            plain += text
    return (html or plain)[:12000], plain[:4000]


def to_sample(msg):
    name, addr = parseaddr(str(msg.get("From", "")))
    if "@" not in addr:
        return None
    rt_name, rt_addr = parseaddr(str(msg.get("Reply-To", "")))
    body, _ = body_of(msg)
    sender = f'"{name}" <{addr}>' if name else addr
    return {"sender": sender, "reply_to": rt_addr if "@" in rt_addr else "",
            "subject": str(msg.get("Subject", ""))[:300], "content": body}


def read_mbox(path):
    for m in mailbox.mbox(path, factory=lambda f: email.message_from_binary_file(f, policy=policy.default)):
        s = to_sample(m)
        if s:
            yield s


def read_tar(path):
    with tarfile.open(path, "r:bz2") as tf:
        for member in tf:
            if not member.isfile() or member.name.endswith(("cmds", ".cmds")):
                continue
            data = tf.extractfile(member).read()
            s = to_sample(email.message_from_bytes(data, policy=policy.default))
            if s:
                yield s


def score(samples):
    det = detector_mod.PhishingDetector()
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
    def half(s):
        return "dev" if zlib.crc32((s["sender"] + s["subject"]).encode("utf-8", "ignore")) % 2 == 0 else "test"

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

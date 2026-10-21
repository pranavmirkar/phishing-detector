"""Catalogue and readers for the public email corpora used by the real-data benchmark.

Splits are defined here, once, so the CLI and the dashboard agree.

  phishing  Nazario corpus, by YEAR
              dev   2015, 2018, 2019, 2022     rules are diagnosed here
              val   2016, 2017, 2020, 2021, 2023   iteration checks AND model training (recent attacks)
              test  2024, 2025                 time-held-out: the model never sees a later year than 2023
  legit     SpamAssassin ham / hard ham (2002-03), Enron corporate mail (1999-2002), Apache
            mailing lists (2025). Items are assigned by a hash of the SENDER ADDRESS (test = half,
            dev = a quarter, val = a quarter), so all mail from one sender lands in one split and
            near-duplicate threads cannot leak; whole Apache list-months go to one split.
  spam      SpamAssassin spam: optional, reported separately (it is spam, not phishing)

"unseen": the 2023-25 test emails scored in the project's first test run were fingerprinted
(seen_test_v1.json) and are reported as the separate split `test_seen`. The locked split `test`
contains only emails nobody has scored or inspected.

Everything is parsed in memory with the standard ``email`` package (see emailparse.py);
nothing from a corpus is executed. Only sender domains are ever stored in results.
"""
import email
import json
import mailbox
import os
import re
import tarfile
import zlib
from email import policy

import emailparse

_NAZ = "https://monkey.org/~jose/phishing/"
_SA = "https://spamassassin.apache.org/old/publiccorpus/"
_ASF = "https://mail-archives.apache.org/mod_mbox/"
_ENRON = "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz"

NAZARIO = {"page": _NAZ, "credit": "J. Nazario, phishing corpus (CC BY 4.0)"}
SA = {"page": _SA, "credit": "Apache SpamAssassin public corpus"}
ASF = {"page": "https://lists.apache.org/", "credit": "Apache Software Foundation public mailing-list archives"}
ENRON = {"page": "https://www.cs.cmu.edu/~enron/", "credit": "Enron Email Dataset (public record), CMU"}

SPLITS = ("dev", "val", "test_seen", "test")


def _phish(year, role, mb, group):
    return {"file": f"phishing-{year}.mbox", "url": f"{_NAZ}phishing-{year}", "name": f"Nazario phishing {year}",
            "kind": "mbox", "label": "phishing", "role": role, "group": group, "max_bytes": mb * 1_000_000, **NAZARIO}


def _list(slug, role, group="recent", cap=150):
    lst, month = slug.rsplit("-", 1)
    return {"file": f"asf-{slug}.mbox", "url": f"{_ASF}{lst}/{month}.mbox", "name": f"Apache {lst} ({month[:4]}-{month[4:]})",
            "kind": "mbox", "label": "legit", "role": role, "group": group, "cap": cap, "max_bytes": 12_000_000, **ASF}


def _sa(file, url, name, group, max_mb=10):
    return {"file": file, "url": _SA + url, "name": name, "kind": "tar", "label": "legit", "role": "hash",
            "group": group, "max_bytes": max_mb * 1_000_000, **SA}


SOURCES = {
    "phish_2015": _phish(2015, "dev", 25, "core"),
    "phish_2018": _phish(2018, "dev", 25, "recent"),
    "phish_2019": _phish(2019, "dev", 25, "recent"),
    "phish_2022": _phish(2022, "dev", 25, "recent"),
    "phish_2016": _phish(2016, "val", 30, "extended"),
    "phish_2017": _phish(2017, "val", 30, "extended"),
    "phish_2020": _phish(2020, "val", 25, "extended"),
    "phish_2021": _phish(2021, "val", 25, "extended"),
    "phish_2023": _phish(2023, "val", 30, "recent"),
    "phish_2024": _phish(2024, "test", 40, "recent"),
    "phish_2025": _phish(2025, "test", 45, "recent"),
    "ham_easy": _sa("easy_ham_2.tar.bz2", "20030228_easy_ham_2.tar.bz2", "SpamAssassin easy ham (2002-03)", "core"),
    "ham_easy1": _sa("easy_ham_1.tar.bz2", "20021010_easy_ham.tar.bz2", "SpamAssassin easy ham (2002-10)", "extended"),
    "ham_hard": _sa("hard_ham.tar.bz2", "20030228_hard_ham.tar.bz2", "SpamAssassin hard ham (legit mail that looks like spam)", "recent"),
    "ham_hard1": _sa("hard_ham_1.tar.bz2", "20021010_hard_ham.tar.bz2", "SpamAssassin hard ham (2002-10)", "extended"),
    "enron": {"file": "enron-sample.mbox", "url": _ENRON, "name": "Enron corporate mail (sample, 1999-2002)", "kind": "enron",
              "label": "legit", "role": "hash", "group": "business", "max_bytes": 80_000_000, **ENRON},
    # modern (2025) legitimate mail: mailing-list traffic, whole list-months per split
    "asf_httpd-dev-202501": _list("httpd-dev-202501", "dev"),
    "asf_spark-dev-202509": _list("spark-dev-202509", "dev"),
    "asf_tomcat-users-202509": _list("tomcat-users-202509", "dev"),
    "asf_incubator-general-202509": _list("incubator-general-202509", "dev", "extended"),
    "asf_httpd-dev-202509": _list("httpd-dev-202509", "val"),
    "asf_spamassassin-users-202501": _list("spamassassin-users-202501", "val"),
    "asf_cloudstack-users-202509": _list("cloudstack-users-202509", "val", "extended"),
    "asf_kafka-users-202509": _list("kafka-users-202509", "test"),
    "asf_maven-users-202509": _list("maven-users-202509", "test"),
    "asf_lucene-dev-202509": _list("lucene-dev-202509", "test"),
    "asf_kafka-dev-202509": _list("kafka-dev-202509", "test"),
    "asf_flink-user-202509": _list("flink-user-202509", "test"),
    "asf_tomcat-dev-202509": _list("tomcat-dev-202509", "test", "extended"),
    "spam": {"file": "spam_2.tar.bz2", "url": _SA + "20050311_spam_2.tar.bz2", "name": "SpamAssassin spam (reported separately)",
             "kind": "tar", "label": "spam", "role": "hash", "group": "optional", "max_bytes": 15_000_000, **SA},
}
for _k, _v in SOURCES.items():
    _v["id"] = _k
    _v.setdefault("cap", 0)

GROUPS = {
    "core": "Core (~10 MB): 2015 phishing + 2002-03 ham",
    "recent": "Recent (~85 MB): 2018-25 phishing, hard ham, 2025 mailing lists",
    "extended": "Extended (~45 MB): validation phishing years 2016-21, more ham and lists",
    "business": "Business (~28 MB sample): Enron corporate mail, streamed from the start of a 443 MB archive",
    "optional": "Optional: SpamAssassin spam (reported separately)",
}


# ── fingerprints / roles ──────────────────────────────────────────────────────
def fingerprint(s):
    """Stable id of an email (used to keep already-scored emails out of the locked test split)."""
    return zlib.crc32((s["sender"] + "\x00" + s["subject"] + "\x00" + s["content"][:300]).encode("utf-8", "ignore"))


_SEEN = None


def seen_fingerprints():
    global _SEEN
    if _SEEN is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seen_test_v1.json")
        try:
            with open(path, encoding="utf-8") as f:
                _SEEN = set(json.load(f)["fingerprints"])
        except (OSError, ValueError, KeyError):
            _SEEN = set()
    return _SEEN


def sender_address(sample):
    m = re.search(r"<([^>]+)>", sample["sender"])
    return (m.group(1) if m else sample["sender"]).strip().lower()


def bucket(sample):
    """dev / val / test for sources whose items are assigned by hash of the sender address."""
    v = zlib.crc32(sender_address(sample).encode("utf-8", "ignore"))
    if v % 2:
        return "test"
    return "val" if (v // 2) % 2 else "dev"


def half(sample):                       # kept for older scripts: dev/test halves
    return "test" if bucket(sample) == "test" else "dev"


def split_of(src, sample):
    """Which split an email belongs to: dev | val | test_seen | test."""
    role = bucket(sample) if src["role"] == "hash" else src["role"]
    if role == "test":
        return "test_seen" if fingerprint(sample) in seen_fingerprints() else "test"
    return role


def sources_for(split):
    """Source ids that can contribute to a split."""
    out = []
    for k, v in SOURCES.items():
        if v["label"] == "spam":
            continue
        if split == "all" or v["role"] == "hash" or v["role"] == split or (split in ("test", "test_seen") and v["role"] == "test"):
            out.append(k)
    return out


def wanted(split):                      # backwards-compatible name
    return sources_for(split)


# ── readers ───────────────────────────────────────────────────────────────────
_INVALID = re.compile(r"\.invalid(?=[>\s\"]|$)", re.I)


def _clean(s):
    """The Apache archives append '.INVALID' to every address (a spam-harvesting guard, and a
    reserved TLD that never occurs in real mail). Remove it so domains read as they were."""
    s["sender"] = _INVALID.sub("", s["sender"])
    s["reply_to"] = _INVALID.sub("", s["reply_to"])
    return s


def _read_mbox(path):
    for m in mailbox.mbox(path, factory=lambda f: email.message_from_binary_file(f, policy=policy.default)):
        s = _clean(emailparse.from_message(m))
        if "@" in s["sender"]:
            yield s


def _read_tar(path):
    with tarfile.open(path, "r:bz2") as tf:
        for member in tf:
            if not member.isfile() or member.name.endswith(("cmds", ".cmds")):
                continue
            data = tf.extractfile(member).read(2_000_000)
            s = _clean(emailparse.from_message(email.message_from_bytes(data, policy=policy.default)))
            if "@" in s["sender"]:
                yield s


def read_source(path, kind):
    return _read_tar(path) if kind == "tar" else _read_mbox(path)      # "mbox" and the Enron sample (an mbox)


# Backwards-compatible names used by the older CLI scripts
read_mbox = _read_mbox
read_tar = _read_tar

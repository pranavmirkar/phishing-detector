"""Catalogue and readers for the public email corpora used by the real-data benchmark.

Splits are defined here, once, so the CLI and the dashboard agree:

  phishing   Nazario corpus by YEAR  : 2015, 2018, 2019, 2022 = development
                                       2023, 2024, 2025       = TEST (recent, time-held-out)
  legit      SpamAssassin ham        : split by a hash of sender+subject (dev/test halves)
             Apache mailing lists    : whole months, assigned to dev or test
  spam       SpamAssassin spam       : optional, reported separately (it is spam, not phishing)

Everything is parsed in memory with the standard ``email`` package (see emailparse.py);
nothing from a corpus is executed or extracted to disk. Only sender domains are ever
stored in results.
"""
import email
import mailbox
import re
import tarfile
import zlib
from email import policy

import emailparse

_NAZ = "https://monkey.org/~jose/phishing/"
_SA = "https://spamassassin.apache.org/old/publiccorpus/"
_ASF = "https://mail-archives.apache.org/mod_mbox/"

NAZARIO = {"page": _NAZ, "credit": "J. Nazario, phishing corpus (CC BY 4.0)"}
SA = {"page": _SA, "credit": "Apache SpamAssassin public corpus"}
ASF = {"page": "https://lists.apache.org/", "credit": "Apache Software Foundation public mailing-list archives"}


def _phish(year, role, mb):
    return {"file": f"phishing-{year}.mbox", "url": f"{_NAZ}phishing-{year}", "name": f"Nazario phishing {year}",
            "kind": "mbox", "label": "phishing", "role": role, "group": "core" if year == 2015 else "recent",
            "max_bytes": mb * 1_000_000, **NAZARIO}


def _list(slug, role, cap=150):
    lst, month = slug.rsplit("-", 1)
    return {"file": f"asf-{slug}.mbox", "url": f"{_ASF}{lst}/{month}.mbox", "name": f"Apache {lst} ({month[:4]}-{month[4:]})",
            "kind": "mbox", "label": "legit", "role": role, "group": "recent", "cap": cap, "max_bytes": 12_000_000, **ASF}


SOURCES = {
    "phish_2015": _phish(2015, "dev", 25),
    "phish_2018": _phish(2018, "dev", 25),
    "phish_2019": _phish(2019, "dev", 25),
    "phish_2022": _phish(2022, "dev", 25),
    "phish_2023": _phish(2023, "test", 30),
    "phish_2024": _phish(2024, "test", 40),
    "phish_2025": _phish(2025, "test", 45),
    "ham_easy": {"file": "easy_ham_2.tar.bz2", "url": _SA + "20030228_easy_ham_2.tar.bz2", "name": "SpamAssassin easy ham (2002-03)",
                 "kind": "tar", "label": "legit", "role": "hash", "group": "core", "max_bytes": 10_000_000, **SA},
    "ham_hard": {"file": "hard_ham.tar.bz2", "url": _SA + "20030228_hard_ham.tar.bz2", "name": "SpamAssassin hard ham (legit mail that looks like spam)",
                 "kind": "tar", "label": "legit", "role": "hash", "group": "recent", "max_bytes": 10_000_000, **SA},
    # modern (2025) legitimate mail: mailing-list traffic, split by whole list
    "asf_httpd-dev-202501": _list("httpd-dev-202501", "dev"),
    "asf_httpd-dev-202509": _list("httpd-dev-202509", "dev"),
    "asf_spamassassin-users-202501": _list("spamassassin-users-202501", "dev"),
    "asf_spark-dev-202509": _list("spark-dev-202509", "dev"),
    "asf_tomcat-users-202509": _list("tomcat-users-202509", "dev"),
    "asf_kafka-users-202509": _list("kafka-users-202509", "test"),
    "asf_maven-users-202509": _list("maven-users-202509", "test"),
    "asf_lucene-dev-202509": _list("lucene-dev-202509", "test"),
    "asf_kafka-dev-202509": _list("kafka-dev-202509", "test"),
    "asf_flink-user-202509": _list("flink-user-202509", "test"),
    "spam": {"file": "spam_2.tar.bz2", "url": _SA + "20050311_spam_2.tar.bz2", "name": "SpamAssassin spam (reported separately)",
             "kind": "tar", "label": "spam", "role": "hash", "group": "optional", "max_bytes": 15_000_000, **SA},
}
for _k, _v in SOURCES.items():
    _v["id"] = _k
    if _k.startswith("asf_"):                      # file name is derived from the key's list-month
        _v["file"] = f"{_k.replace('asf_', 'asf-')}.mbox"
    _v.setdefault("cap", 0)
GROUPS = {"core": "Core (~10 MB: 2015 phishing + 2002 ham)", "recent": "Recent (~85 MB: 2018-2025 phishing, hard ham, 2025 mailing lists)"}


def wanted(split):
    """Source ids a split draws from. 'hash' sources contribute their dev or test half."""
    if split == "all":
        return [k for k, v in SOURCES.items() if v["label"] != "spam"]
    return [k for k, v in SOURCES.items() if v["label"] != "spam" and v["role"] in (split, "hash")]


def half(sample):
    """Deterministic dev/test half of a corpus, by hash of sender+subject."""
    key = (sample["sender"] + sample["subject"]).encode("utf-8", "ignore")
    return "dev" if zlib.crc32(key) % 2 == 0 else "test"


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
    return _read_mbox(path) if kind == "mbox" else _read_tar(path)


# Backwards-compatible names used by the older CLI scripts
read_mbox = _read_mbox
read_tar = _read_tar

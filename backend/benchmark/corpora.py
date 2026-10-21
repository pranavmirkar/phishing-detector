"""Readers for the public email corpora used by the real-data benchmark.

All parsing happens in memory with the standard ``email`` package; nothing from a
corpus is executed or extracted to disk, and only text parts are looked at.
"""
import email
import mailbox
import tarfile
import zlib
from email import policy
from email.utils import parseaddr

# Fixed, reviewed sources. Nothing user-supplied is ever fetched.
SOURCES = {
    "phishing": {
        "file": "phishing-2015.mbox",
        "url": "https://monkey.org/~jose/phishing/phishing-2015",
        "name": "Nazario phishing corpus (2015)",
        "kind": "mbox",
        "max_bytes": 25_000_000,
        "page": "https://monkey.org/~jose/phishing/",
    },
    "ham": {
        "file": "easy_ham_2.tar.bz2",
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2",
        "name": "SpamAssassin public corpus: easy ham",
        "kind": "tar",
        "max_bytes": 10_000_000,
        "page": "https://spamassassin.apache.org/old/publiccorpus/",
    },
    "spam": {
        "file": "spam_2.tar.bz2",
        "url": "https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2",
        "name": "SpamAssassin public corpus: spam (reported separately)",
        "kind": "tar",
        "max_bytes": 15_000_000,
        "page": "https://spamassassin.apache.org/old/publiccorpus/",
    },
}


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
    return (html or plain)[:12000]


def to_sample(msg):
    name, addr = parseaddr(str(msg.get("From", "")))
    if "@" not in addr:
        return None
    _, rt_addr = parseaddr(str(msg.get("Reply-To", "")))
    sender = f'"{name}" <{addr}>' if name else addr
    return {"sender": sender, "reply_to": rt_addr if "@" in rt_addr else "",
            "subject": str(msg.get("Subject", ""))[:300], "content": body_of(msg)}


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
            data = tf.extractfile(member).read(2_000_000)
            s = to_sample(email.message_from_bytes(data, policy=policy.default))
            if s:
                yield s


def half(sample):
    """Deterministic dev/test half of a corpus, by hash of sender+subject."""
    key = (sample["sender"] + sample["subject"]).encode("utf-8", "ignore")
    return "dev" if zlib.crc32(key) % 2 == 0 else "test"

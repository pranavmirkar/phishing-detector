"""
Builds a compact sample of the Enron corporate mail corpus (real business email, 1999-2002).

The full archive is 443 MB; this streams only the first `max_compressed` bytes (a handful of
employees' mailboxes), keeps a deterministic sample of messages and writes them as one mbox.
Nothing is extracted to disk except that mbox; only sender domains and aggregate statistics
ever leave it.

Source: https://www.cs.cmu.edu/~enron/  (Enron Email Dataset, released into the public record).
"""
import email
import mailbox
import os
import tarfile
import urllib.request
from urllib.parse import urlparse
import zlib
from email import policy

URL = "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz"
SKIP_FOLDERS = {"all_documents", "discussion_threads", "notes_inbox"}      # mostly duplicates of other folders


class _Limited:
    """File-like wrapper that reports EOF after `limit` bytes (stops the stream early)."""

    def __init__(self, raw, limit, on_progress=None):
        self.raw, self.left, self.total, self.cb = raw, limit, 0, on_progress

    def read(self, n=-1):
        if self.left <= 0:
            return b""
        n = self.left if n is None or n < 0 else min(n, self.left)
        chunk = self.raw.read(n)
        self.left -= len(chunk)
        self.total += len(chunk)
        if self.cb:
            self.cb(self.total)
        return chunk


def build_sample(dest, max_compressed=45_000_000, keep_one_in=2, max_msgs=3500, on_progress=None):
    tmp = dest + ".part"
    if os.path.exists(tmp):
        os.remove(tmp)
    box = mailbox.mbox(tmp)
    req = urllib.request.Request(URL, headers={"User-Agent": "PhishGuard-benchmark/1.0"})
    seen, kept = set(), 0
    with urllib.request.urlopen(req, timeout=60) as resp:
        if (urlparse(resp.geturl()).hostname or "") != "www.cs.cmu.edu":
            raise ValueError("Enron download redirected to an unexpected host")
        limited = _Limited(resp, max_compressed, on_progress)
        try:
            with tarfile.open(fileobj=limited, mode="r|gz") as tf:
                for member in tf:
                    if not member.isfile() or member.size > 300_000:
                        continue
                    parts = member.name.split("/")
                    if len(parts) < 4 or parts[-2].lower() in SKIP_FOLDERS:
                        continue
                    if zlib.crc32(member.name.encode()) % keep_one_in:
                        continue
                    data = tf.extractfile(member).read()
                    msg = email.message_from_bytes(data, policy=policy.default)
                    mid = str(msg.get("Message-ID", ""))
                    if not msg.get("From") or (mid and mid in seen):
                        continue
                    seen.add(mid)
                    box.add(mailbox.mboxMessage(msg))
                    kept += 1
                    if kept >= max_msgs:
                        break
        except (EOFError, tarfile.ReadError, OSError):
            pass                                     # the stream was cut at max_compressed: expected
    box.flush()
    box.close()
    if kept == 0:
        os.remove(tmp)
        raise ValueError("no Enron messages could be read")
    os.replace(tmp, dest)
    return kept

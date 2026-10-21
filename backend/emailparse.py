"""
Turn a raw RFC 822 message (an .eml file, or "show original" text) into the dict that
PhishingDetector.analyze() takes.

What is extracted
  sender / reply_to / subject / content  display name + address, text or HTML body
  auth_results      SPF / DKIM / DMARC verdicts from the TOPMOST Authentication-Results
                    header (the one added by the receiving server; lower ones can be forged)
  return_path       envelope sender domain
  attachments       [{filename, type, size}] (names only, content is never opened)
  list_id           True for mailing-list traffic (List-Id header)
  unsubscribe       True when a List-Unsubscribe header is present (bulk / marketing mail)

Deliberately NOT used: X-Spam-* or any other header that records another filter's verdict.
"""
import email
import re
from email import policy
from email.utils import parseaddr

MAX_BYTES = 5_000_000
MAX_CONTENT = 60_000
MAX_ATTACHMENTS = 25
_AUTH = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)


def _text_of(part):
    try:
        text = part.get_content()
    except Exception:
        return ""
    return text if isinstance(text, str) else ""


def body_of(msg):
    """HTML body if there is one (links and forms live there), else plain text."""
    plain, html = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_filename():
            continue
        ctype = part.get_content_type()
        if ctype == "text/html":
            html.append(_text_of(part))
        elif ctype == "text/plain":
            plain.append(_text_of(part))
    return ("".join(html) or "".join(plain))[:MAX_CONTENT]


def attachments_of(msg):
    out = []
    for part in msg.walk():
        name = part.get_filename()
        if not name or part.is_multipart():
            continue
        try:
            size = len(part.get_payload(decode=True) or b"")
        except Exception:
            size = 0
        out.append({"filename": str(name)[:200], "type": part.get_content_type(), "size": size})
        if len(out) >= MAX_ATTACHMENTS:
            break
    return out


def auth_results_of(msg):
    """Verdicts from the topmost Authentication-Results (+ Received-SPF if SPF is missing there)."""
    found = {}
    ar = msg.get_all("Authentication-Results") or []
    if ar:
        for k, v in _AUTH.findall(str(ar[0])):
            found.setdefault(k.lower(), v.lower())
    if "spf" not in found:
        rs = msg.get_all("Received-SPF") or []
        if rs:
            m = re.match(r"\s*([a-z]+)", str(rs[0]), re.I)
            if m:
                found["spf"] = m.group(1).lower()
    return " ".join(f"{k}={v}" for k, v in found.items())


def recipient_of(msg):
    """The mailbox this message was delivered to (so org-impersonation can be recognised)."""
    for h in ("Delivered-To", "X-Original-To", "To"):
        v = msg.get(h)
        if v:
            _, a = parseaddr(str(v))
            if "@" in a:
                return a.lower()
    return ""


def from_message(msg) -> dict:
    name, addr = parseaddr(str(msg.get("From", "")))
    _, rt = parseaddr(str(msg.get("Reply-To", "")))
    _, ret = parseaddr(str(msg.get("Return-Path", "")))
    return {
        "sender": f'"{name}" <{addr}>' if name else addr,
        "reply_to": rt if "@" in rt else "",
        "subject": str(msg.get("Subject", ""))[:500],
        "content": body_of(msg),
        "auth_results": auth_results_of(msg),
        "return_path": ret if "@" in ret else "",
        "attachments": attachments_of(msg),
        "list_id": bool(msg.get("List-Id")),
        "unsubscribe": bool(msg.get("List-Unsubscribe")),
        "recipient": recipient_of(msg),
    }


def parse_raw(data) -> dict:
    """Parse raw bytes or str. Raises ValueError when it does not look like an email."""
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    if len(data) > MAX_BYTES:
        raise ValueError("Message is larger than 5 MB.")
    msg = email.message_from_bytes(data, policy=policy.default)
    out = from_message(msg)
    if "@" not in out["sender"]:
        raise ValueError("Could not find a From address. Paste the full raw message including headers.")
    return out

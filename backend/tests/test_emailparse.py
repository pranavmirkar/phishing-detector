import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import emailparse as E  # noqa: E402

RAW = """Return-Path: <bounce@random-host.xyz>
Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=random-host.xyz; dkim=none; dmarc=fail header.from=paypal.com
Authentication-Results: forged.example; spf=pass dmarc=pass
Received-SPF: pass (forged)
X-Spam-Status: Yes, score=9.0
From: "PayPal Support" <billing@paypal.com>
Reply-To: help@other-domain.xyz
Subject: Verify your account
List-Unsubscribe: <mailto:u@x.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: text/html; charset=utf-8

<p>Please <a href="http://paypa1.com/x">sign in</a></p>
--b
Content-Type: application/octet-stream; name="invoice.html"
Content-Disposition: attachment; filename="invoice.html"

<html></html>
--b--
"""


def test_parse_headers_body_and_attachments():
    d = E.parse_raw(RAW)
    assert d["sender"] == '"PayPal Support" <billing@paypal.com>'
    assert d["reply_to"] == "help@other-domain.xyz" and d["return_path"] == "bounce@random-host.xyz"
    assert "paypa1.com" in d["content"] and d["subject"] == "Verify your account"
    assert [a["filename"] for a in d["attachments"]] == ["invoice.html"]
    assert d["unsubscribe"] is True and d["list_id"] is False


def test_only_topmost_authentication_results_is_used():
    d = E.parse_raw(RAW)
    assert "spf=fail" in d["auth_results"] and "dmarc=fail" in d["auth_results"]
    assert "pass" not in d["auth_results"]          # the forged lower header and Received-SPF are ignored


def test_spam_verdict_headers_are_never_used():
    d = E.parse_raw(RAW)
    assert "score=9.0" not in repr(d)               # X-Spam-Status carries another filter's verdict


def test_garbage_and_oversize_are_rejected():
    with pytest.raises(ValueError):
        E.parse_raw("this is not an email")
    with pytest.raises(ValueError):
        E.parse_raw(b"From: a@b.com\n\n" + b"x" * 5_000_001)


def test_end_to_end_with_detector(monkeypatch):
    import detector as D
    monkeypatch.setattr(D, "tranco_is_trusted", lambda d: (d in ("paypal.com", "nytimes.com"), 5))
    monkeypatch.setattr(D, "get_levenshtein_pool", lambda: ["paypal.com"])
    monkeypatch.setattr(D, "check_domain_age", lambda d: {})
    r = D.PhishingDetector().analyze(E.parse_raw(RAW))
    kinds = {w["type"] for w in r["warnings"]}
    assert r["risk_score"] == "HIGH"
    assert {"AUTH_FAILURE", "RETURN_PATH_MISMATCH", "RISKY_ATTACHMENT"} <= kinds

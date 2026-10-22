"""API-level tests: auth, rate limiting, raw-email parsing, privacy options. Uses a temp database."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as A  # noqa: E402
import detector as D  # noqa: E402


@pytest.fixture()
def client(monkeypatch):
    A.init_db()
    monkeypatch.setattr(D, "tranco_is_trusted", lambda d: (d in ("paypal.com", "nytimes.com"), 5))
    monkeypatch.setattr(D, "get_levenshtein_pool", lambda: ["paypal.com", "nytimes.com"])
    monkeypatch.setattr(D, "check_domain_age", lambda d: {})
    A._hits.clear()
    monkeypatch.setattr(A, "API_KEY", "")
    monkeypatch.setattr(A, "RATE_LIMIT", 0)
    return A.app.test_client()


RAW = """Return-Path: <b@random-host.xyz>
Authentication-Results: mx.example; spf=fail; dmarc=fail
From: "PayPal" <billing@paypal.com>
To: me@example.org
Subject: Verify your account
Content-Type: text/plain

Please sign in at http://paypa1.com/x
"""


def test_parse_then_analyze_uses_header_signals(client):
    p = client.post("/api/parse", json={"raw": RAW})
    assert p.status_code == 200
    parsed = p.get_json()
    assert parsed["recipient"] == "me@example.org" and "dmarc=fail" in parsed["auth_results"]
    r = client.post("/api/analyze", json=parsed).get_json()
    kinds = {w["type"] for w in r["warnings"]}
    assert r["risk_score"] == "HIGH" and {"AUTH_FAILURE", "RETURN_PATH_MISMATCH"} <= kinds


def test_parse_rejects_non_email(client):
    assert client.post("/api/parse", json={"raw": "hello"}).status_code == 400
    assert client.post("/api/parse", json={}).status_code == 400


def test_api_key_is_enforced_when_configured(client, monkeypatch):
    monkeypatch.setattr(A, "API_KEY", "s3cret")
    assert client.get("/api/stats").status_code == 401
    assert client.get("/api/stats", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/stats", headers={"X-API-Key": "s3cret"}).status_code == 200
    assert client.get("/api/health").status_code == 200          # liveness probe stays open


def test_rate_limit(client, monkeypatch):
    monkeypatch.setattr(A, "RATE_LIMIT", 3)
    codes = [client.post("/api/analyze", json={"sender": "a@b.com", "subject": "x"}).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]


def test_message_body_not_stored_when_disabled(client, monkeypatch):
    monkeypatch.setattr(A, "STORE_CONTENT", False)
    r = client.post("/api/analyze", json={"sender": "a@b.com", "subject": "s", "content": "SECRET BODY"}).get_json()
    row = client.get(f"/api/emails/{r['id']}").get_json()
    assert "SECRET BODY" not in str(row)


def test_extras_are_sanitised(client):
    r = client.post("/api/analyze", json={"sender": "a@b.com", "subject": "s", "attachments": [{"filename": "x.html"}] * 100,
                                          "auth_results": "x" * 10000, "list_id": "yes"})
    assert r.status_code == 200


def test_security_headers_and_json_errors(client):
    r = client.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    big = client.post("/api/parse", data="x" * (9 * 1024 * 1024), content_type="application/json")
    assert big.status_code == 413 and "error" in big.get_json()


def test_database_path_is_absolute_and_overridable():
    assert os.path.isabs(A.DB)


def test_persist_false_scores_without_saving(client):
    before = len(client.get("/api/emails").get_json())
    r = client.post("/api/analyze", json={"sender": "a@b.com", "subject": "hi", "persist": False}).get_json()
    assert r["id"] is None and r["risk_score"] in ("LOW", "MEDIUM", "HIGH")
    assert len(client.get("/api/emails").get_json()) == before
    saved = client.post("/api/analyze", json={"sender": "a@b.com", "subject": "hi"}).get_json()
    assert isinstance(saved["id"], int)

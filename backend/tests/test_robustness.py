"""Regression tests for bugs found by adversarial testing: slow regexes, type confusion, resource limits."""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as A  # noqa: E402
import detector as D  # noqa: E402
import domain_intel as DI  # noqa: E402


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setattr(D, "tranco_is_trusted", lambda d: (False, None))
    monkeypatch.setattr(D, "get_levenshtein_pool", lambda: ["paypal.com"])
    monkeypatch.setattr(D, "check_domain_age", lambda d: {})


N = 60_000
ADVERSARIAL = {
    "unclosed anchors": '<a href="http://x.example/a">' * 3000,
    "anchors with text": '<a href="http://x.example/a">link ' * 3000,
    "tag soup": "<div " * 12000,
    "unclosed script": "<script>" + "x" * N + "<style>" * 2000,
    "many styles": "<style>x" * 6000,
    "many forms": '<form action="http://e.xyz/x"><input type="text">' * 1500,
    "many urls": " ".join(f"http://host{i}.example.xyz/p" for i in range(3000)),
    "confusable words": " ".join("pаypal" for _ in range(N // 7)),
    "keyword flood": "verify your account " * 3000,
}


@pytest.mark.parametrize("name", list(ADVERSARIAL))
def test_adversarial_input_is_analysed_quickly(name):
    body = ADVERSARIAL[name]
    t0 = time.perf_counter()
    D.PhishingDetector(use_whois=False).analyze({"sender": "a@b.com", "subject": body[:500], "content": body[:N]})
    assert time.perf_counter() - t0 < 1.5, f"{name} took too long (quadratic regex?)"


@pytest.mark.parametrize("bad", [
    {"sender": None}, {"sender": 123}, {"sender": ["a@b.com"]},
    {"sender": "a@b.com", "subject": None, "content": None},
    {"sender": "a@b.com", "subject": 5, "content": {"x": 1}},
    {"sender": "a@b.com", "attachments": "x.html"},
    {"sender": "a@b.com", "attachments": [None, 5, {"filename": None}, {"filename": ["x"]}]},
    {"sender": "a@b.com", "auth_results": {"spf": ["x"], 5: None}},
    {"sender": "a@b.com", "recipient": 5, "reply_to": 5, "return_path": ["x"]},
    {"sender": "a@b.com", "own_domains": "example.com"},
    {"sender": "a@b.com", "own_domains": [None, 5, "example.com"]},
    None, [], "text",
])
def test_wrong_types_never_crash_the_detector(bad):
    r = D.PhishingDetector(use_whois=False).analyze(bad)
    assert r["risk_score"] in ("LOW", "MEDIUM", "HIGH")


def test_long_tags_are_still_stripped_from_visible_text():
    html = '<img src="data:image/png;base64,' + "A" * 5000 + '"> Verify your account now'
    assert "verify your account now" in D._visible_text(html).lower()
    assert "AAAA" not in D._visible_text(html)


def test_style_and_script_blocks_are_removed_linearly():
    assert D._visible_text("<style>.a{color:red}</style>Hello<script>evil()</script> world") == "Hello world"
    assert D._visible_text("Hi <script>never closed") == "Hi"


# ── API ───────────────────────────────────────────────────────────────────────
@pytest.fixture()
def client():
    A.init_db()
    A._hits.clear()
    A.RATE_LIMIT = 0
    return A.app.test_client()


@pytest.mark.parametrize("path", ["/api/analyze", "/api/parse", "/api/matrix", "/api/report", "/api/intel/whois",
                                  "/api/benchmarks/run", "/api/benchmarks/real/download"])
@pytest.mark.parametrize("body", ["[]", '"x"', "null", "5", "{bad json"])
def test_non_object_json_is_a_client_error_not_a_crash(client, path, body):
    r = client.post(path, data=body, content_type="application/json")
    assert 400 <= r.status_code < 500, (path, body, r.status_code)


def test_analyze_rejects_non_string_sender(client):
    for sender in (None, 5, ["a@b.com"], {"x": 1}):
        assert client.post("/api/analyze", json={"sender": sender}).status_code == 400


def test_matrix_size_is_capped(client):
    assert client.post("/api/matrix", json={"s1": "a" * 5000, "s2": "b" * 5000}).status_code == 400
    assert client.post("/api/matrix", json={"s1": "abc", "s2": "abd"}).status_code == 200
    assert client.post("/api/matrix", json={"s1": 5, "s2": ["x"]}).status_code == 400


def test_rate_limit_table_does_not_grow_without_bound(client):
    A.RATE_LIMIT = 1000
    for i in range(5200):
        A._hits[f"10.0.{i // 250}.{i % 250}"].append(time.time() - 120)   # idle clients
    client.post("/api/analyze", json={"sender": "a@b.com"})
    assert len(A._hits) < 5200
    A.RATE_LIMIT = 0


# ── WHOIS ─────────────────────────────────────────────────────────────────────
def test_whois_wait_is_bounded_and_failures_are_cached(monkeypatch):
    import types
    DI.init_intel_tables()
    calls = []

    def slow_whois(domain):
        calls.append(domain)
        time.sleep(3)

    monkeypatch.setitem(sys.modules, "whois", types.SimpleNamespace(whois=slow_whois))
    monkeypatch.setattr(DI, "WHOIS_TIMEOUT_S", 0.3)
    monkeypatch.delenv("PG_WHOIS", raising=False)
    t0 = time.perf_counter()
    r = DI.check_domain_age("slow-registry-example.com")
    assert time.perf_counter() - t0 < 1.5 and r["error"] == "whois_timeout"
    t1 = time.perf_counter()
    again = DI.check_domain_age("slow-registry-example.com")           # served from the failure cache
    assert time.perf_counter() - t1 < 0.2 and again.get("from_cache") and len(calls) == 1


def test_whois_rejects_junk_domains_and_can_be_disabled(monkeypatch):
    assert DI.check_domain_age("not a domain")["error"] == "invalid_domain"
    assert DI.check_domain_age("a" * 300 + ".com")["error"] == "invalid_domain"
    monkeypatch.setenv("PG_WHOIS", "0")
    assert DI.check_domain_age("example.com").get("disabled")


# ── performance helpers keep exact semantics ──────────────────────────────────
def test_bounded_levenshtein_matches_full_distance():
    import random
    from levenshtein import levenshtein_distance
    rnd = random.Random(1)
    alphabet = "abcdeil01-."
    for _ in range(3000):
        a = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 14)))
        b = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 14)))
        full = levenshtein_distance(a, b)
        got = D._lev_bounded(a, b, 6)
        assert got == (full if full <= 6 else 7), (a, b, full, got)


def test_brand_mentions_found_in_one_pass():
    det = D.PhishingDetector(use_whois=False, use_model=False)
    found = det.brands_in_text("Please confirm your PayPal account, or contact Wells Fargo / Bank of America.")
    assert {"paypal", "wellsfargo", "bankofamerica"} <= found
    assert "paypal" not in det.brands_in_text("Learn about papaya growing")
    assert det.brands_in_text("We ordered an orange from the target store") == set()      # ordinary words, not brands


def test_character_signature_is_a_valid_lower_bound():
    import random
    from levenshtein import levenshtein_distance
    rnd = random.Random(2)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-."
    for _ in range(4000):
        a = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 16)))
        b = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 16)))
        assert (D._mask(a) ^ D._mask(b)).bit_count() <= 2 * levenshtein_distance(a, b)


# ── malformed links found in real phishing (2025) ─────────────────────────────
@pytest.mark.parametrize("url", [
    "http://[", "http://[::1", "http://[abc]:xyz/", "http://wetransfer/x", "http://a b/c", "http://user@", "http://:80/",
    "http://exa mple.com", "https://[2001:db8::1]:99999/p", "http://xn--/x", "http://.../", "http://" + "a" * 300 + ".com/x",
    "http://wetransfer", "http://paypal/login", "http://‮evil.com",
])
def test_malformed_urls_never_crash(url):
    body = f'<a href="{url}">https://www.paypal.com/login</a> visit {url} now. <form action="{url}"><input type="password"></form>'
    for sender in ("a@b.com", "info@wetransfer", '"WeTransfer file share" <info@ruocean.com>', "x@localhost"):
        r = D.PhishingDetector(use_whois=False).analyze({"sender": sender, "subject": "s", "content": body, "recipient": "me@example.org"})
        assert r["risk_score"] in ("LOW", "MEDIUM", "HIGH")


def test_dotless_sender_domain_does_not_crash():
    assert D.PhishingDetector(use_whois=False).analyze({"sender": "x@wetransfer"})["risk_score"] in ("LOW", "MEDIUM", "HIGH")

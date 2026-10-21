"""Tests for the /api/benchmarks service. Offline: only bundled datasets and tiny custom uploads."""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import benchmark_service as B  # noqa: E402
from app import app  # noqa: E402


@pytest.fixture()
def client():
    B._jobs.clear()
    yield app.test_client()
    B._jobs.clear()


def wait(client, job_id, timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        j = client.get(f"/api/benchmarks/jobs/{job_id}").get_json()
        if j["state"] in ("done", "error"):
            return j
        time.sleep(0.2)
    raise AssertionError("job did not finish")


ROWS = [
    {"label": "phishing", "sender": "support@paypa1.com", "subject": "Urgent verify your account", "content": "sign in now"},
    {"label": "phishing", "sender": "ceo.office@gmail.com", "subject": "Quick favor",
     "content": "Are you available? Buy gift cards today. Keep this confidential."},
    {"label": "legit", "sender": "someone@acme-widgets.io", "subject": "Invoice", "content": "Please find the invoice attached."},
    {"label": "legit", "sender": "friend@example.org", "subject": "Dinner?", "content": "Free on Saturday?"},
]


def test_datasets_lists_bundled_sets_and_real_status(client):
    d = client.get("/api/benchmarks/datasets").get_json()
    ids = {p["id"] for p in d["private"]}
    assert {"private_dev", "private_holdout"} <= ids
    assert all(p["samples"] == p["phishing"] + p["legit"] for p in d["private"])
    assert {f["id"] for f in d["real"]["files"]} == {"phishing", "ham", "spam"}
    assert d["limits"]["custom_max_rows"] > 0


def test_custom_run_produces_metrics(client):
    r = client.post("/api/benchmarks/run", json={"dataset": "custom", "rows": ROWS})
    assert r.status_code == 202
    j = wait(client, r.get_json()["job_id"])
    assert j["state"] == "done"
    res = j["result"]
    assert res["counts"]["phishing"] == 2 and res["counts"]["legit"] == 2
    m = res["operating_points"]["medium_or_above"]
    assert m["tp"] + m["fn"] == 2 and m["fp"] + m["tn"] == 2
    assert 0 <= res["auc"] <= 1 and len(res["sweep"]) == 20


def test_custom_labels_are_normalised_and_bad_rows_skipped(client):
    rows = [{**ROWS[0], "label": "PHISH"}, {**ROWS[2], "label": "ham"}, {"label": "x", "sender": "nope"}]
    j = wait(client, client.post("/api/benchmarks/run", json={"dataset": "custom", "rows": rows}).get_json()["job_id"])
    assert j["state"] == "done" and j["result"]["counts"]["skipped"] == 1


@pytest.mark.parametrize("body", [
    {"dataset": "nope"},
    {"dataset": "custom", "rows": []},
    {"dataset": "custom", "rows": [ROWS[0]]},                 # only one class
    {"dataset": "custom", "rows": "not a list"},
    {"dataset": "custom", "rows": [ROWS[0]] * 2001},          # over the row limit
])
def test_invalid_runs_are_rejected(client, body):
    assert client.post("/api/benchmarks/run", json=body).status_code == 400


def test_real_run_requires_download(client, monkeypatch):
    monkeypatch.setattr(B, "_real_ready", lambda include_spam=False: False)
    r = client.post("/api/benchmarks/run", json={"dataset": "real"})
    assert r.status_code == 400 and "Download" in r.get_json()["error"]


def test_only_one_run_at_a_time(client):
    B._jobs["busy"] = {"id": "busy", "state": "running"}
    assert client.post("/api/benchmarks/run", json={"dataset": "custom", "rows": ROWS}).status_code == 409


def test_unknown_job_is_404(client):
    assert client.get("/api/benchmarks/jobs/doesnotexist").status_code == 404


def test_real_n_is_clamped(monkeypatch):
    monkeypatch.setattr(B, "_real_ready", lambda include_spam=False: True)
    assert B._validate_spec({"dataset": "real", "n": 10 ** 9})["n"] == B.LIMITS["real_max_n"]
    assert B._validate_spec({"dataset": "real", "n": 1})["n"] == B.LIMITS["real_min_n"]
    with pytest.raises(ValueError):
        B._validate_spec({"dataset": "real", "split": "weird"})


def test_download_is_limited_to_fixed_sources():
    from benchmark import corpora
    assert all(s["url"].startswith("https://") for s in corpora.SOURCES.values())
    assert {s["url"].split("/")[2] for s in corpora.SOURCES.values()} == {"monkey.org", "spamassassin.apache.org"}

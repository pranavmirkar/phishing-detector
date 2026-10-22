"""Tests for the learned scoring layer (model.py) and its integration in the detector. No scikit-learn needed."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import detector as D  # noqa: E402
import emailparse as E  # noqa: E402
import model as M  # noqa: E402

BUNDLED = M.DEFAULT_PATH
TRUSTED = {"paypal.com", "amazon.com", "nytimes.com", "google.com", "github.com"}


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setattr(D, "tranco_is_trusted", lambda d: (d.lower() in TRUSTED, 5))
    monkeypatch.setattr(D, "get_levenshtein_pool", lambda: ["paypal.com", "amazon.com", "google.com"])
    monkeypatch.setattr(D, "check_domain_age", lambda d: {})
    yield
    monkeypatch.undo()
    M.reset()


def tiny_model(path, feature="sig:LOOKALIKE_DOMAIN"):
    """One stump: raw = baseline + (-2 if feature <= 0.5 else +3)."""
    feats = [feature, "spam"]
    spec = {"version": "test", "features": feats, "baseline": 0.0,
            "trees": [{"f": [0, -1, -1], "t": [0.5, 0.0, 0.0], "l": [1, -1, -1], "r": [2, -1, -1], "v": [0.0, -2.0, 3.0]}],
            "anchors": {"raw": [-2.0, 0.0, 1.0, 3.0], "risk": [0, 25, 55, 100]}}
    path.write_text(json.dumps(spec), encoding="utf-8")
    return spec


def test_tree_evaluation_and_risk_mapping(tmp_path):
    tiny_model(tmp_path / "m.json")
    m = M.load(str(tmp_path / "m.json"))
    assert m.raw({}) == -2.0 and m.raw({"sig:LOOKALIKE_DOMAIN": 1.1}) == 3.0
    assert m.raw({"unknown:feature": 9}) == -2.0                      # features the model never saw are ignored
    assert [m.risk(x) for x in (-5, -2, 0, 1, 2, 3, 9)] == [0, 0, 25, 55, 78, 100, 100]
    assert all(m.risk(a) <= m.risk(b) for a, b in zip([-3, -1, 0.5, 1.5, 4], [-1, 0.5, 1.5, 4, 8]))   # monotone


def test_featurize_has_the_documented_inputs():
    f = M.featurize({"LOOKALIKE_DOMAIN": 55, "SUSPICIOUS_KEYWORDS": 12}, 40, False, True, "info8378806", "bmi-institute.co",
                    "RE: URGENT account", 3, 2, {"n_untrusted_dom": 2, "url_maxlen": 1.4})
    assert f["sig:LOOKALIKE_DOMAIN"] == 1.1 and f["spam"] == 0.4 and f["free"] == 1.0 and f["trusted"] == 0.0
    assert f["dom_hyph"] == 1 and f["loc_digit"] > 0.6 and f["subj_re"] == 1.0 and f["n_untrusted_dom"] == 2
    assert set(M.LEXICAL_FEATURES) <= set(f)
    assert M.featurize({}, 0, False, False, "", "x.co", "", 0, 0)["subj_caps"] == 0.0       # empty inputs are safe


def test_model_off_missing_or_broken_never_breaks_analysis(tmp_path, monkeypatch):
    monkeypatch.setenv("PG_MODEL", "off")
    M.reset()
    assert M.get_model() is None
    monkeypatch.setenv("PG_MODEL", str(tmp_path / "does-not-exist.json"))
    M.reset()
    assert M.get_model() is None
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("PG_MODEL", str(bad))
    M.reset()
    assert M.get_model() is None
    assert D.PhishingDetector(use_whois=False).analyze({"sender": "a@b.com"})["model"] is None


def test_detector_uses_the_model_and_keeps_the_rule_score(tmp_path, monkeypatch):
    tiny_model(tmp_path / "m.json")
    monkeypatch.setenv("PG_MODEL", str(tmp_path / "m.json"))
    M.reset()
    det = D.PhishingDetector(use_whois=False)
    bad = det.analyze({"sender": "security@paypa1.com", "subject": "Verify", "content": "Sign in now"})
    assert bad["risk_score"] == "HIGH" and bad["risk_level"] == 100 and bad["model"]["version"] == "test"
    assert bad["rule_score"] >= 55 and bad["warnings"]                       # rules still explain the verdict
    good = det.analyze({"sender": "news@nytimes.com", "subject": "Hi", "content": "Today's stories"})
    assert good["risk_score"] == "LOW" and good["risk_level"] == 0
    assert D.PhishingDetector(use_whois=False, use_model=False).analyze({"sender": "a@b.com"})["model"] is None


def test_broken_model_at_scoring_time_falls_back_to_rules(tmp_path, monkeypatch):
    tiny_model(tmp_path / "m.json")
    monkeypatch.setenv("PG_MODEL", str(tmp_path / "m.json"))
    M.reset()
    det = D.PhishingDetector(use_whois=False)
    det.model.trees = [{"f": [0], "t": [0.0], "l": [99], "r": [99], "v": [0.0]}]          # points outside the tree
    r = det.analyze({"sender": "security@paypa1.com", "subject": "Verify", "content": "Sign in now"})
    assert r["model"] is None and r["risk_score"] == "HIGH" and r["risk_level"] == r["rule_score"]


def test_return_features_exposes_model_inputs():
    r = D.PhishingDetector(use_whois=False, use_model=False, return_features=True).analyze(
        {"sender": "a@bmi-institute.co", "subject": "Hello", "content": '<a href="http://odd-host.example.xyz/a/b?x=1">x</a>'})
    f = r["model_features"]
    assert f["n_untrusted_dom"] == 1 and f["untrusted_ratio"] == 1.0 and f["http_ratio"] == 1.0 and f["dom_hyph"] == 1
    assert "model_features" not in D.PhishingDetector(use_whois=False, use_model=False).analyze({"sender": "a@b.com"})


# ── the bundled model ─────────────────────────────────────────────────────────
@pytest.mark.skipif(not os.path.exists(BUNDLED), reason="bundled model not present")
class TestBundledModel:
    @pytest.fixture(autouse=True)
    def use_bundled(self, monkeypatch):
        monkeypatch.setenv("PG_MODEL", BUNDLED)
        M.reset()

    def test_loads_and_matches_the_feature_contract(self):
        m = M.get_model()
        assert m is not None and m.trees
        assert set(M.EXTRA_FEATURES + M.LEXICAL_FEATURES) <= set(m.features)
        xs = m.anchors["raw"]
        assert xs == sorted(xs) and m.anchors["risk"] == [0, 25, 55, 100]
        assert m.meta["rows"] > 1000 and m.meta["thresholds"] == {"medium_fpr": 0.01, "high_fpr": 0.001}

    def test_forged_brand_email_with_header_evidence_is_high(self):
        raw = open(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                "docs", "samples", "forged-paypal.eml"), encoding="utf-8").read()
        r = D.PhishingDetector(use_whois=False).analyze(E.parse_raw(raw))
        assert r["risk_score"] == "HIGH" and r["model"]["version"]

    def test_ordinary_trusted_mail_is_low(self):
        det = D.PhishingDetector(use_whois=False)
        for sender, subject, body in (
            ("auto-confirm@amazon.com", "Your order has shipped", "Your order #123 has shipped. Track it at https://www.amazon.com/orders"),
            ("noreply@github.com", "[repo] Pull request merged", "Your pull request was merged. https://github.com/org/repo/pull/5"),
            ("news@nytimes.com", "Your morning briefing", "Top stories: https://www.nytimes.com/today"),
        ):
            assert det.analyze({"sender": sender, "subject": subject, "content": body})["risk_score"] == "LOW"


def test_unsupported_signals_keep_their_rule_points_as_a_floor(tmp_path, monkeypatch):
    spec = tiny_model(tmp_path / "m.json", feature="sig:SUSPICIOUS_KEYWORDS")
    spec["support"] = {"SUSPICIOUS_KEYWORDS": 500, "BEC_SCAM_PATTERN": 3}      # the model has seen BEC wording only 3 times
    spec["min_support"] = 20
    (tmp_path / "m.json").write_text(json.dumps(spec), encoding="utf-8")
    m = M.load(str(tmp_path / "m.json"))
    assert m.unsupported_points({"SUSPICIOUS_KEYWORDS": 24, "BEC_SCAM_PATTERN": 50, "NEVER_SEEN": 10}) == 60
    assert m.unsupported_points({"SUSPICIOUS_KEYWORDS": 24}) == 0

    monkeypatch.setenv("PG_MODEL", str(tmp_path / "m.json"))
    M.reset()
    det = D.PhishingDetector(use_whois=False)
    r = det.analyze({"sender": "ceo.office@gmail.com", "subject": "Quick favor",
                     "content": "Are you available? Buy gift cards today. Keep this confidential."})
    assert r["model"]["rule_floor"] >= 50 and r["risk_level"] >= 50 and r["risk_score"] == "HIGH"     # the model alone would say LOW


def test_brand_lookalike_keeps_its_rule_points_whatever_the_training_support(tmp_path, monkeypatch):
    """A homoglyph of a protected brand must never be scored below its rule points by the model."""
    spec = tiny_model(tmp_path / "m.json", feature="spam")          # a model that rates everything LOW
    spec["support"] = {"LOOKALIKE_DOMAIN": 500, "HOMOGLYPH_ATTACK": 500}   # ... and has "plenty of evidence" for the signals
    (tmp_path / "m.json").write_text(json.dumps({**spec, "floor_always": ["LOOKALIKE_DOMAIN", "HOMOGLYPH_ATTACK"]}), encoding="utf-8")
    monkeypatch.setenv("PG_MODEL", str(tmp_path / "m.json"))
    M.reset()
    mail = {"sender": "support@paypa1.com", "subject": "Verify your account", "content": "sign in now"}
    with_floor = D.PhishingDetector(use_whois=False).analyze(mail)
    assert with_floor["risk_score"] in ("MEDIUM", "HIGH"), with_floor["model"]

    (tmp_path / "m.json").write_text(json.dumps(spec), encoding="utf-8")   # same model without floor_always
    M.reset()
    assert D.PhishingDetector(use_whois=False).analyze(mail)["risk_level"] < with_floor["risk_level"]


def test_bundled_model_flags_a_plain_brand_homoglyph(monkeypatch):
    monkeypatch.setenv("PG_MODEL", BUNDLED)             # the suite runs with the model off by default
    M.reset()
    r = D.PhishingDetector(use_whois=False).analyze({"sender": "support@paypa1.com", "subject": "Verify your account", "content": "sign in now"})
    assert r["risk_score"] in ("MEDIUM", "HIGH"), r["model"]

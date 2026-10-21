"""
Offline unit tests for the detector rules. No network, no database: the trusted-domain
lookup, lookalike pool and WHOIS are replaced with small fixed fakes.

    cd backend && python -m pytest -q
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import detector as D  # noqa: E402

TRUSTED = {
    "google.com": 1, "amazon.com": 27, "paypal.com": 168, "nytimes.com": 157, "gmail.com": 277,
    "yahoo.com": 61, "comcast.net": 900, "github.com": 29, "microsoft.com": 8, "apple.com": 9,
    "facebook.com": 4, "netflix.com": 46, "t-online.de": 800,
}
POOL = ["google.com", "amazon.com", "paypal.com", "gmail.com", "yahoo.com", "microsoft.com",
        "apple.com", "facebook.com", "netflix.com", "github.com", "t-online.de"]


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setattr(D, "tranco_is_trusted", lambda d: (d.lower() in TRUSTED, TRUSTED.get(d.lower())))
    monkeypatch.setattr(D, "get_levenshtein_pool", lambda: POOL)
    monkeypatch.setattr(D, "check_domain_age", lambda d: {})


def run(sender, subject="", content="", **kw):
    return D.PhishingDetector().analyze({"sender": sender, "subject": subject, "content": content, **kw})


def types(r):
    return {w["type"] for w in r["warnings"]}


# ── helpers ───────────────────────────────────────────────────────────────────
def test_registered_domain_handles_two_part_suffixes():
    assert D.registered_domain("mail.google.com") == "google.com"
    assert D.registered_domain("shop.example.co.uk") == "example.co.uk"
    assert D.registered_domain("yahoo.com.au") == "yahoo.com.au"


def test_osa_counts_adjacent_swap_as_one_edit():
    assert D._osa("paypla.com", "paypal.com") == 1
    assert D._osa("paypal.com", "paypal.com") == 0
    assert D._osa("abc", "xyz") == 3


# ── sender identity ───────────────────────────────────────────────────────────
def test_digit_typosquat_is_high_risk():
    r = run("security@paypa1.com", "Verify your account", "Please sign in to confirm your identity.")
    assert r["risk_score"] == "HIGH" and "LOOKALIKE_DOMAIN" in types(r)


def test_transposition_typosquat_is_caught():
    assert "LOOKALIKE_DOMAIN" in types(run("a@paypla.com"))


def test_trusted_brand_receipt_is_low():
    r = run("auto-confirm@amazon.com", "Your order", "Thanks for your order. It ships tomorrow.")
    assert r["risk_score"] == "LOW"


def test_freemail_is_never_trusted():
    r = run("someone@gmail.com", "hello", "see you tomorrow")
    assert not r["domain_analysis"]["is_trusted"]
    assert "FREEMAIL_SENDER" in types(r) and "TRUSTED_VERIFIED" not in types(r)


def test_freemail_posing_as_brand_is_flagged():
    r = run('"PayPal Support" <help.desk@gmail.com>', "Account notice", "Please verify your account.")
    assert "BRAND_IMPERSONATION" in types(r)


def test_split_brand_name_in_display_name_is_flagged():
    assert "BRAND_IMPERSONATION" in types(run('"Pay Pal Support" <x@gmail.com>'))


def test_trusted_isp_domain_cannot_claim_a_brand():
    assert "BRAND_IMPERSONATION" in types(run('"Amazon.com" <bob2010@comcast.net>', "Important Security Update"))


def test_person_named_like_a_brand_is_not_impersonation():
    assert "BRAND_IMPERSONATION" not in types(run('"Chase Williams" <chase@gmail.com>', "lunch?"))
    assert "BRAND_IMPERSONATION" not in types(run('"Apple Johnson" <apple@comcast.net>', "hi"))


def test_brand_plus_lure_word_domain_is_flagged_but_substring_is_not():
    assert "BRAND_IN_DOMAIN" in types(run("a@paypal-secure.com"))
    assert "BRAND_IN_DOMAIN" in types(run("a@paypal.xyz"))
    assert "BRAND_IN_DOMAIN" not in types(run("a@applecross-dental.co.uk"))
    assert "BRAND_IN_DOMAIN" not in types(run("a@chasecreekfarm.com"))


def test_regional_brand_site_is_not_flagged():
    assert "BRAND_IN_DOMAIN" not in types(run("a@yahoo.com.au"))


def test_subdomain_abuse():
    r = run("alerts@paypal.secure-login-check.xyz", "Account notice", "Please log in.")
    assert "SUBDOMAIN_ABUSE" in types(r) and r["risk_score"] == "HIGH"


def test_generic_host_words_are_not_brands():
    # "mail" is the label of mail.ru (a popular domain): it must not turn every mail.<host> into subdomain abuse
    assert "SUBDOMAIN_ABUSE" not in types(run("bob@mail.somecompany.com", "hi", "see you"))
    assert "SUBDOMAIN_ABUSE" not in types(run("bob@tele-punt-22.mail.demon.net", "hi", "see you"))


def test_homoglyph_domain_not_triggered_by_innocent_digits_or_cl():
    assert "HOMOGLYPH_ATTACK" not in types(run("a@harborviewclinic.org"))
    assert "HOMOGLYPH_ATTACK" not in types(run("a@web3-tools.io"))


def test_cyrillic_lookalike():
    r = run("a@pаypal.com")   # Cyrillic 'а'
    assert "HOMOGLYPH_ATTACK" in types(r) and r["risk_score"] == "HIGH"


def test_two_edit_match_needs_high_similarity():
    # f1online.de is 2 edits from t-online.de (82 %): worth a note, not a verdict
    r = run("kiosk@f1online.de", "list mail", "see the archive")
    assert r["risk_score"] == "LOW"


# ── content ───────────────────────────────────────────────────────────────────
def test_bec_wording_from_freemail():
    r = run("ceo.office@gmail.com", "Quick favor",
            "Are you available? I need you to buy gift cards today. Keep this confidential.")
    assert r["risk_score"] in ("MEDIUM", "HIGH") and "BEC_SCAM_PATTERN" in types(r)


def test_single_weak_phrase_does_not_flag():
    r = run("dev@gmail.com", "OOP question", "Explain class inheritance in Python.")
    assert "BEC_SCAM_PATTERN" not in types(r)


def test_generic_account_lure_from_unknown_domain():
    r = run("info@somewhere-co.biz", "Your mailbox is full",
            "Your mailbox exceeded its limit. Verify your e-mail account within 24 hours or it will be closed.")
    assert "ACCOUNT_ACTION_LURE" in types(r)


def test_admin_display_name_with_click_prompt():
    r = run('"Webmail Admin" <info@random-host.io>', "Confirm Your e-mail Account",
            "Upgrade your email account. Click here to proceed.")
    assert "ADMIN_IMPERSONATION" in types(r)


def test_brand_mentioned_with_account_action_from_unrelated_sender():
    r = run("care@some-shop.io", "Notice", "Your PayPal account is limited. Sign in to confirm your details.")
    assert "BRAND_MISMATCH" in types(r)


def test_security_alert_from_real_google_domain_stays_low():
    r = run("no-reply@google.com", "Security alert",
            "We noticed unusual activity. If this was you no action is needed. You can reset your password anytime.")
    assert r["risk_score"] == "LOW"


def test_marketing_newsletter_from_trusted_sender_is_low():
    r = run("news@nytimes.com", "Today only: weekend sale",
            "Limited time offer. Congratulations! Unsubscribe | Manage preferences.")
    assert r["risk_score"] == "LOW"


# ── links ─────────────────────────────────────────────────────────────────────
def test_same_organisation_tracking_link_is_not_a_mismatch():
    body = '<a href="https://click.nytimes.com/r/123">https://www.nytimes.com/story</a>'
    assert not run("news@nytimes.com", "Story", body)["link_mismatches"]


def test_deceptive_link_is_a_mismatch():
    body = '<a href="http://evil.example.xyz/x">https://www.paypal.com/verify</a>'
    r = run("a@unknown-shop.io", "Hi", body)
    assert r["link_mismatches"] and "LINK_MISMATCH" in types(r)


def test_automated_brand_mailbox_linking_to_unrelated_domain():
    r = run("billing@paypal.com", "Payment", "Review it here: https://payments-review.example-host.net/x")
    assert "SUSPICIOUS_LINK" in types(r)


def test_employee_of_brand_linking_out_is_fine():
    r = run("jane.doe@google.com", "Interesting read", "Have a look: https://some-blog.example.org/post")
    assert "SUSPICIOUS_LINK" not in types(r)


# ── headers ───────────────────────────────────────────────────────────────────
def test_reply_to_hijack_of_brand_sender_is_high():
    r = run("billing@paypal.com", "Invoice", "Hello", reply_to="help@totally-other.xyz")
    assert "REPLY_TO_MISMATCH" in types(r) and r["phishing_score"] >= 30


def test_mailing_list_reply_to_is_not_overweighted():
    r = run("someone@nytimes.com", "Re: thread", "ok", reply_to="list@lists.example.org")
    assert r["phishing_score"] <= 10


def test_failed_authentication_is_high():
    r = run("billing@paypal.com", "Invoice", "Hello", auth_results="spf=fail dkim=pass dmarc=fail")
    assert "AUTH_FAILURE" in types(r) and r["phishing_score"] >= 45


def test_passing_authentication_adds_no_risk():
    r = run("billing@paypal.com", "Invoice", "Hello", auth_results="spf=pass dkim=pass dmarc=pass")
    assert "AUTH_FAILURE" not in types(r)


# ── API contract used by the frontend ─────────────────────────────────────────
def test_result_shape_is_stable():
    r = run("security@paypa1.com", "Verify", "Sign in now")
    for k in ("risk_score", "risk_level", "warnings", "domain_analysis", "domain", "spam"):
        assert k in r
    da = r["domain_analysis"]
    for k in ("is_trusted", "normalized", "best_match", "top_matches", "matrix", "edit_operations"):
        assert k in da


# ── raw-email signals ─────────────────────────────────────────────────────────
def test_return_path_mismatch_for_brand_sender():
    r = run("billing@paypal.com", "Invoice", "Hello", return_path="bounce@random-host.xyz")
    assert "RETURN_PATH_MISMATCH" in types(r)
    assert "RETURN_PATH_MISMATCH" not in types(run("billing@paypal.com", "Invoice", "Hello", return_path="bounce@paypal.com"))
    assert "RETURN_PATH_MISMATCH" not in types(run("billing@paypal.com", "Invoice", "Hello", return_path="b@nytimes.com"))


def test_html_and_executable_attachments():
    r = run("a@unknown-shop.io", "Invoice", "see attached", attachments=[{"filename": "Invoice_482.html"}])
    assert "RISKY_ATTACHMENT" in types(r) and r["risk_score"] in ("MEDIUM", "HIGH")
    assert "RISKY_ATTACHMENT" in types(run("a@unknown-shop.io", "x", "y", attachments=["statement.pdf.exe"]))
    assert "RISKY_ATTACHMENT" not in types(run("a@unknown-shop.io", "x", "y", attachments=[{"filename": "photo.jpg"}, {"filename": "report.pdf"}]))


def test_password_field_in_email_body():
    body = '<form action="http://evil.example.xyz/p"><input type="password" name="pw"></form>'
    assert "CREDENTIAL_FORM" in types(run("a@unknown-shop.io", "Sign in", body))


def test_mailing_list_reply_to_is_ignored():
    r = run("dev@some-project.org", "Re: thread", "ok", reply_to="dev@lists.some-project.org", list_id=True)
    assert "REPLY_TO_MISMATCH" not in types(r)

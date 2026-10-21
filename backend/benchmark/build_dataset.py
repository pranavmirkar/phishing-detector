"""
Builds a labeled validation dataset for the PhishGuard detector.

Output: dataset.jsonl  (one JSON object per line)
  id, label ("phishing" | "legit"), category, sender, reply_to, subject, content

The data is synthetic (no real mailboxes were used) but written to be varied:
each category has several subject/body templates, and brand names are drawn from
real services. Generation is seeded, so the file is reproducible.

Categories deliberately include cases the detector is NOT designed to catch
(e.g. text-only fraud from a freemail address) and legitimate mail that looks
spammy (newsletters), so the reported accuracy is not trivially 100%.
"""
import json
import os
import random
import sqlite3

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "..", "phishing.db")
SEED = 42
rng = random.Random(SEED)

# Brands attackers impersonate. Mix of domains inside / outside the detector's
# top-1000 lookalike pool (chase, wellsfargo, hdfcbank rank well below 1000).
BRANDS = [
    ("paypal.com", "PayPal"), ("amazon.com", "Amazon"), ("netflix.com", "Netflix"),
    ("apple.com", "Apple"), ("microsoft.com", "Microsoft"), ("google.com", "Google"),
    ("facebook.com", "Facebook"), ("instagram.com", "Instagram"), ("linkedin.com", "LinkedIn"),
    ("dropbox.com", "Dropbox"), ("spotify.com", "Spotify"), ("yahoo.com", "Yahoo"),
    ("bankofamerica.com", "Bank of America"), ("chase.com", "Chase"),
    ("wellsfargo.com", "Wells Fargo"), ("hdfcbank.com", "HDFC Bank"),
    ("docusign.com", "DocuSign"), ("fedex.com", "FedEx"), ("dhl.com", "DHL"),
    ("coinbase.com", "Coinbase"), ("binance.com", "Binance"), ("steampowered.com", "Steam"),
]

PHISH_SUBJECTS = [
    "Urgent: Your {b} account has been suspended",
    "Action required: verify your {b} account",
    "{b} security alert - unusual activity detected",
    "Your {b} payment failed - update your billing information",
    "Confirm your identity to keep your {b} account active",
    "Final notice: {b} account will be closed",
    "Unusual login attempt on your {b} account",
]
PHISH_BODIES = [
    "Dear Customer,\n\nWe detected unusual activity on your {b} account. Please verify your account immediately: {url}\n\nIf you do not act now your account will be suspended.\n\n{b} Security Team",
    "Dear user, your {b} account has been limited. Confirm your identity within 24 hours to restore access. Click here: {url}",
    "Action required. We could not process your last payment. Update your billing information to avoid interruption: {url}\nThis is your last chance.",
    "Hello,\n\nA login attempt from a new device was blocked. Reset your password now: {url}\n\nThank you,\n{b} Support",
    "Your {b} account needs attention. Please confirm your identity and credit card details here {url} to avoid closure.",
]
LEGIT_PROFESSIONAL = [
    ("Meeting notes from Tuesday", "Hi,\n\nAttached are the notes from Tuesday's meeting. Let me know if I missed anything and I'll update them.\n\nThanks,\n{n}"),
    ("Invoice #{i} for October", "Hello,\n\nPlease find invoice #{i} attached for the work completed in October. Payment terms are net 30.\n\nBest regards,\n{n}"),
    ("Re: project timeline", "Thanks for the update. I think the revised timeline works. Can we sync on Thursday to confirm the deliverables?\n\n{n}"),
    ("Question about your application", "Hi,\n\nThank you for applying. We would like to schedule a short call next week. Are you free Monday or Wednesday afternoon?\n\nRegards,\n{n}"),
    ("Your appointment on Friday", "This is a reminder that your appointment is scheduled for Friday at 10:30. Reply to this email if you need to reschedule.\n\n{n}"),
    ("Quote for the renovation", "Hi,\n\nFollowing our site visit, I've attached the quote for the kitchen renovation. It is valid for 30 days. Happy to answer any questions.\n\n{n}"),
]
NAMES = ["Priya", "Daniel", "Meera", "Tom", "Aisha", "Carlos", "Neha", "Oliver", "Sara", "Ravi"]
SMALL_ORGS = [  # plausible small-business / org domains, verified below not to be in Tranco 50k
    "brightleafdental.com", "riverstonebakery.co.uk", "northwindplumbing.net", "oakhillschool.org",
    "kestrelconsulting.io", "bluepinelegal.com", "maplecourtcafe.ca", "ironbridgefitness.com",
    "harborviewclinic.org", "sundialdesignstudio.com", "greenfieldfarmsupply.com", "quillandink.co",
    "tidewaterlogistics.net", "lumenarchitects.com", "pinecrestrealty.com", "foxglovefloral.co.uk",
]
RANDOM_BAD = [  # throwaway-looking phishing hosts
    "secure-login-verify.xyz", "account-update-center.top", "verify-id-portal.info", "mailer-support.click",
    "auth-service-check.online", "billing-review-desk.site", "helpdesk-alerts.work", "login-confirm.live",
    "secure-pay-center.icu", "support-notice-team.shop", "id-verification-hub.cfd", "accounts-safety.buzz",
]
CYR = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у", "i": "і"}

rows = []


def add(label, category, sender, subject, content, reply_to=""):
    rows.append({
        "id": len(rows) + 1, "label": label, "category": category,
        "sender": sender, "reply_to": reply_to, "subject": subject, "content": content,
    })


def typo_variants(domain):
    name, tld = domain.rsplit(".", 1)
    out = {}
    digit = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}
    idx = [i for i, ch in enumerate(name) if ch in digit]
    if idx:
        i = rng.choice(idx)
        out["typo_digit"] = name[:i] + digit[name[i]] + name[i + 1:] + "." + tld
    if len(name) > 4:
        i = rng.randrange(1, len(name) - 1)
        out["typo_delete"] = name[:i] + name[i + 1:] + "." + tld
        i = rng.randrange(1, len(name))
        out["typo_insert"] = name[:i] + name[i - 1] + name[i:] + "." + tld
        i = rng.randrange(0, len(name) - 1)
        out["typo_swap"] = name[:i] + name[i + 1] + name[i] + name[i + 2:] + "." + tld
    out["tld_swap"] = name + "." + rng.choice(["co", "net", "org", "info", "xyz"])
    out["brand_hyphen"] = name + rng.choice(["-secure", "-support", "-verify", "-login"]) + ".com"
    return out


def cyrillic(domain):
    name, tld = domain.rsplit(".", 1)
    cand = [i for i, ch in enumerate(name) if ch in CYR]
    if not cand:
        return None
    i = rng.choice(cand)
    return name[:i] + CYR[name[i]] + name[i + 1:] + "." + tld


# ── Phishing ──────────────────────────────────────────────────────────────────
for domain, brand in BRANDS:
    for cat, fake in typo_variants(domain).items():
        if cat in ("typo_delete", "typo_insert", "typo_swap") and rng.random() < 0.5:
            continue
        subj = rng.choice(PHISH_SUBJECTS).format(b=brand)
        body = rng.choice(PHISH_BODIES).format(b=brand, url=f"http://{fake}/verify?id={rng.randint(1000,9999)}")
        add("phishing", cat, f"security@{fake}", subj, body)
    fake = cyrillic(domain)
    if fake:
        subj = rng.choice(PHISH_SUBJECTS).format(b=brand)
        body = rng.choice(PHISH_BODIES).format(b=brand, url=f"http://{fake}/signin")
        add("phishing", "homoglyph_unicode", f"no-reply@{fake}", subj, body)
    # subdomain abuse: brand in the subdomain of an attacker domain
    host = f"{domain.split('.')[0]}.{rng.choice(RANDOM_BAD)}"
    subj = rng.choice(PHISH_SUBJECTS).format(b=brand)
    add("phishing", "subdomain_abuse", f"alerts@{host}", subj,
        rng.choice(PHISH_BODIES).format(b=brand, url=f"http://{host}/login"))

for i, bad in enumerate(RANDOM_BAD):
    brand = rng.choice(BRANDS)[1]
    real = [d for d, b in BRANDS if b == brand][0]
    # link mismatch: shows the real brand URL, points elsewhere
    body = (f"Dear Customer,\n\nYour {brand} account has been suspended. Verify your account now:\n"
            f'<a href="http://{bad}/v?{rng.randint(100,999)}">https://www.{real}/account/verify</a>\n\n{brand} Security Team')
    add("phishing", "unknown_domain_link_mismatch", f"support@{bad}",
        rng.choice(PHISH_SUBJECTS).format(b=brand), body)
    # unknown domain, no deceptive link, urgency text only
    add("phishing", "unknown_domain_text_only", f"notice@{bad}",
        f"Important notice regarding your {brand} account",
        f"Hello,\n\nPlease review your account details at http://{bad}/review and confirm your information.\n\nThank you.")

for domain, brand in rng.sample(BRANDS, 12):
    # freemail impersonation with mismatched reply-to
    add("phishing", "reply_to_spoof", f"{brand.lower().replace(' ', '')}.support@gmail.com",
        rng.choice(PHISH_SUBJECTS).format(b=brand),
        rng.choice(PHISH_BODIES).format(b=brand, url="http://bit.ly/3xYz12"),
        reply_to=f"claims@{rng.choice(RANDOM_BAD)}")
    # reply-to mismatch on a trusted sender domain (spoofed From)
    add("phishing", "spoofed_trusted_from", f"billing@{domain}",
        rng.choice(PHISH_SUBJECTS).format(b=brand),
        rng.choice(PHISH_BODIES).format(b=brand, url=f"http://{rng.choice(RANDOM_BAD)}/x"),
        reply_to=f"help@{rng.choice(RANDOM_BAD)}")

BEC = [
    ("Quick favor", "Hi, are you available? I need you to handle a task for me discreetly. I'm in a meeting and can't talk. Reply when you see this.\n\nThanks"),
    ("Updated bank details", "Hello,\n\nOur bank account details have changed. Please send the next payment to the new account below and confirm once the wire transfer is done."),
    ("Gift cards needed", "Hi, I need you to purchase 5 gift cards for a client today. I'll reimburse you. Please keep this between us and send me the codes."),
    ("Payroll update", "Hi HR, I changed banks. Please update my direct deposit before the next pay run. New account details attached."),
]
for subj, body in BEC:
    for sender in ("john.mcallister.ceo@gmail.com", "m.harris.director@outlook.com", "finance.dept.office@yahoo.com"):
        add("phishing", "bec_freemail_text_only", sender, subj, body)

# ── Legitimate ────────────────────────────────────────────────────────────────
TRUSTED_SENDERS = [
    ("receipts@amazon.com", "Your Amazon order has shipped", "Hello,\n\nYour order #{i} has shipped and will arrive Thursday. Track your package in Your Orders.\n\nAmazon.com"),
    ("noreply@github.com", "[repo] Pull request merged", "Your pull request #{i} was merged into main by a maintainer."),
    ("no-reply@accounts.google.com", "Security alert", "A new sign-in was detected on your account. If this was you, no action is needed."),
    ("service@paypal.com", "You received a payment", "You received a payment of $45.00. The funds are available in your balance. View details in your PayPal account."),
    ("info@mailchimp.com", "Your monthly report", "Here is your campaign summary for the month. Open rate was 31%."),
    ("hello@stripe.com", "Your Stripe receipt", "Thanks for your payment. Receipt #{i} is attached."),
    ("team@slack.com", "New message in #general", "You have a new message in #general. Open Slack to reply."),
    ("noreply@linkedin.com", "You appeared in 12 searches", "See who's looking at your profile this week."),
    ("support@spotify.com", "Your Spotify receipt", "Thanks for subscribing to Premium. Your next billing date is Nov 3."),
    ("orders@walmart.com", "Order delivered", "Your order #{i} was delivered today at 2:14 PM."),
    ("noreply@booking.com", "Booking confirmation", "Your stay is confirmed. Check-in starts at 3 PM. Free cancellation until Friday."),
    ("registrar@mit.edu", "Course registration open", "Registration for the spring term opens Monday at 9 AM. Please review the schedule of classes."),
    ("notices@stanford.edu", "Library hours update", "The library will have extended hours during exam week."),
    ("noreply@irs.gov", "Your tax transcript is ready", "Your requested transcript is available in your online account."),
]
for sender, subj, body in TRUSTED_SENDERS:
    for _ in range(2):
        add("legit", "trusted_transactional", sender, subj, body.format(i=rng.randint(10000, 99999)))

NEWS = [
    ("newsletter@nytimes.com", "Your morning briefing", "Top stories today. Read more online.\n\nTo stop receiving these emails, unsubscribe at any time. Manage preferences."),
    ("hello@medium.com", "Stories picked for you", "Congratulations to this week's featured writers! Free to read. Unsubscribe | Manage preferences."),
    ("offers@booking.com", "Limited time: 20% off weekend stays", "Limited time offer, guaranteed best price. You are receiving this email because you signed up. Unsubscribe."),
    ("news@substack.com", "Weekly digest", "This week's top posts. Free subscribers get access to the archive. Unsubscribe | View this email in your browser."),
    ("deals@target.com", "Today only: weekend sale", "Today only! Save big on home essentials. No obligation. Unsubscribe anytime. Click here to shop."),
    ("promo@uber.com", "Ride more, save more", "Your free ride credit expires soon. Terms apply. Opt out any time."),
    ("marketing@airbnb.com", "Congratulations, you've been selected for early access", "You've been selected to try our new features. See inside. Manage preferences."),
]
for sender, subj, body in NEWS:
    for _ in range(3):
        add("legit", "trusted_marketing", sender, subj, body)

for i in range(8):  # legit newsletters with tracking links (visible URL != href)
    sender = rng.choice(["news@nytimes.com", "hello@medium.com", "team@mailchimp.com", "digest@substack.com"])
    body = (f'Read the full story here:\n<a href="https://track.{sender.split("@")[1]}/c/{rng.randint(100000,999999)}">'
            f'https://www.{sender.split("@")[1]}/story/{rng.randint(10,99)}</a>\n\nUnsubscribe')
    add("legit", "trusted_tracking_links", sender, "This week's story", body)

for _ in range(18):
    subj, body = rng.choice(LEGIT_PROFESSIONAL)
    add("legit", "personal_freemail", f"{rng.choice(NAMES).lower()}.{rng.choice(['shah','miller','nair','lopez','khan'])}@{rng.choice(['gmail.com','outlook.com','yahoo.com'])}",
        subj.format(i=rng.randint(100, 999)), body.format(n=rng.choice(NAMES), i=rng.randint(100, 999)))

for dom in SMALL_ORGS:
    for _ in range(2):
        subj, body = rng.choice(LEGIT_PROFESSIONAL)
        add("legit", "small_org_unknown_domain", f"{rng.choice(NAMES).lower()}@{dom}",
            subj.format(i=rng.randint(100, 999)), body.format(n=rng.choice(NAMES), i=rng.randint(100, 999)))

# Real services that are short / similar to popular names but legitimate
COLLISIONS = ["zoomin.io", "slackline.org", "applegatefarms.com", "googol.org", "metalworks.net", "amazonia-travel.com"]
for dom in COLLISIONS:
    subj, body = rng.choice(LEGIT_PROFESSIONAL)
    add("legit", "legit_name_collision", f"info@{dom}", subj.format(i=rng.randint(100, 999)), body.format(n=rng.choice(NAMES), i=rng.randint(100, 999)))

# ── Record whether each sender domain is in the trusted list (for the report) ─
conn = sqlite3.connect(DB)
trusted = {r[0] for r in conn.execute("SELECT domain FROM trusted_domains")}
conn.close()
bad_small = [d for d in SMALL_ORGS + COLLISIONS if d in trusted]
assert not bad_small, f"'unknown' legit domains are actually in Tranco: {bad_small}"

rng.shuffle(rows)
for n, r in enumerate(rows, 1):
    r["id"] = n

out = os.path.join(HERE, "dataset.jsonl")
with open(out, "w", encoding="utf-8") as f:
    for r in rows:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

ph = sum(r["label"] == "phishing" for r in rows)
print(f"wrote {len(rows)} samples -> {out}  (phishing={ph}, legit={len(rows) - ph})")

"""
Builds a SECOND, independent labeled dataset (dataset_v2.jsonl) used as a
hold-out check. It is deliberately different from dataset.jsonl:
  - different random seed, wording templates and mutation operators
  - extra brands (banks in India/US, couriers, payments) and new attack styles
  - harder legitimate mail (real security alerts, ESP tracking links, hyphenated
    small-business domains, personal mail that mentions banks and transfers)

It was written BEFORE the detector improvements and is not used to tune rules.
Some categories (e.g. spoofed sender with no other signal) are known to be
undetectable without SPF/DKIM headers and are kept on purpose.
"""
import json
import os
import random
import sqlite3

HERE = os.path.dirname(os.path.abspath(__file__))
rng = random.Random(2024)
_conn = sqlite3.connect(os.path.join(HERE, "..", "phishing.db"))
TRUSTED = {r[0] for r in _conn.execute("SELECT domain FROM trusted_domains")}
_conn.close()
rows = []


def add(label, category, sender, subject, content, reply_to=""):
    rows.append({"label": label, "category": category, "sender": sender,
                 "reply_to": reply_to, "subject": subject, "content": content})


BRANDS = [
    ("paypal.com", "PayPal"), ("amazon.com", "Amazon"), ("microsoft.com", "Microsoft"),
    ("apple.com", "Apple"), ("google.com", "Google"), ("icicibank.com", "ICICI Bank"),
    ("axisbank.com", "Axis Bank"), ("sbi.co.in", "SBI"), ("paytm.com", "Paytm"),
    ("hsbc.com", "HSBC"), ("americanexpress.com", "American Express"), ("capitalone.com", "Capital One"),
    ("usps.com", "USPS"), ("ups.com", "UPS"), ("whatsapp.com", "WhatsApp"),
    ("adobe.com", "Adobe"), ("venmo.com", "Venmo"), ("robinhood.com", "Robinhood"),
    ("telegram.org", "Telegram"), ("intuit.com", "Intuit"),
]
HOSTS = ["account-secure-portal.top", "id-check-service.click", "verifyme-now.xyz", "customer-care-desk.online",
         "alert-center-support.site", "myaccount-review.icu", "billing-help-line.work", "safe-login-gateway.cfd",
         "trust-confirm.buzz", "update-profile-info.shop"]

LURE_SUBJ = [
    "{b}: we noticed a problem with your account",
    "Your {b} access will be restricted",
    "Re: {b} payment could not be completed",
    "{b} - confirm it's you",
    "Immediate attention needed: {b} profile",
    "Your {b} statement is ready - sign in to view",
]
LURE_BODY = [
    "Hi,\n\nTo keep using {b} you must confirm your details today. Sign in here: {url}\n\nIgnore this and your account may be limited.\n\n{b} Customer Care",
    "Your recent transaction was declined. Please verify your account and update your card details at {url} to avoid suspension.",
    "We have locked your {b} profile after a suspicious sign-in. Restore access within 12 hours: {url}",
    "Dear valued member,\n\nAction required: your password expires soon. Reset your password immediately: {url}\n\nThank you for your prompt attention.",
]


def mutate(domain):
    name, tld = domain.split(".", 1)
    out = {}
    if len(name) > 4:
        i = rng.randrange(1, len(name))
        out["typo_double"] = name[:i] + name[i - 1] + name[i:] + "." + tld
    if "m" in name:
        out["typo_rn"] = name.replace("m", "rn", 1) + "." + tld
    if "w" in name:
        out["typo_vv"] = name.replace("w", "vv", 1) + "." + tld
    vowels = [i for i, c in enumerate(name) if c in "aeiou"]
    if vowels:
        i = rng.choice(vowels)
        out["typo_vowel"] = name[:i] + rng.choice([v for v in "aeiou" if v != name[i]]) + name[i + 1:] + "." + tld
    out["combosquat"] = rng.choice(["my", "secure", "login", "update"]) + "-" + name + "." + rng.choice(["com", "net", "co"])
    out["suffix_squat"] = name + rng.choice(["-online", "-portal", "-help", "-service"]) + ".com"
    out["tld_squat"] = name + "." + rng.choice(["co", "info", "biz", "xyz", "top"])
    return out


for domain, brand in BRANDS:
    for cat, fake in mutate(domain).items():
        if rng.random() < 0.45:
            continue
        if fake in TRUSTED:      # a real, popular domain is not a phishing lookalike
            continue
        add("phishing", cat, f"{rng.choice(['support', 'noreply', 'alerts', 'service'])}@{fake}",
            rng.choice(LURE_SUBJ).format(b=brand),
            rng.choice(LURE_BODY).format(b=brand, url=f"https://{fake}/signin?s={rng.randint(10**5, 10**6)}"))
    # punycode / IDN lookalike
    if rng.random() < 0.5:
        name = domain.split(".")[0]
        fake = f"xn--{name[:-1]}-{rng.choice(['9ua', '4ve', 'eua', 'pta'])}.com"
        add("phishing", "punycode_idn", f"security@{fake}", rng.choice(LURE_SUBJ).format(b=brand),
            rng.choice(LURE_BODY).format(b=brand, url=f"https://{fake}/"))
    # brand in subdomain / path of an attacker host
    host = rng.choice(HOSTS)
    sub = f"{domain.split('.')[0]}-{rng.choice(['login', 'secure', 'verify'])}.{host}"
    add("phishing", "subdomain_brand", f"help@{sub}", rng.choice(LURE_SUBJ).format(b=brand),
        rng.choice(LURE_BODY).format(b=brand, url=f"https://{sub}/"))

for host in HOSTS:
    brand = rng.choice(BRANDS)[1]
    add("phishing", "throwaway_domain_lure", f"care@{host}", rng.choice(LURE_SUBJ).format(b=brand),
        rng.choice(LURE_BODY).format(b=brand, url=f"https://{host}/auth"))
    add("phishing", "shipping_lure", f"tracking@{host}", "Delivery attempt failed - reschedule your parcel",
        f"Your parcel could not be delivered. A small redelivery fee applies. Pay and reschedule here: https://{host}/pay\n\nCourier Services")
    add("phishing", "crypto_giveaway", f"promo@{host}", "You have won 2 BTC - claim now",
        f"Congratulations! You've been selected as a lucky winner of our giveaway. Claim your prize now: https://{host}/claim\nLimited time, act now.")

for brand_domain, brand in rng.sample(BRANDS, 10):
    # free-mail display-name spoof
    local = rng.choice(["help.desk", "customer.care", "support.team", "billing.dept"]) + str(rng.randint(10, 99))
    add("phishing", "display_name_spoof", f'"{brand} Support" <{local}@{rng.choice(["gmail.com", "outlook.com", "yahoo.com"])}>',
        rng.choice(LURE_SUBJ).format(b=brand), rng.choice(LURE_BODY).format(b=brand, url="https://tinyurl.com/" + str(rng.randint(10**4, 10**5))))
    # trusted sender but attacker reply-to + lure
    add("phishing", "spoofed_trusted_reply_to", f"no-reply@{brand_domain}", rng.choice(LURE_SUBJ).format(b=brand),
        rng.choice(LURE_BODY).format(b=brand, url=f"https://{rng.choice(HOSTS)}/x"), reply_to=f"resolve@{rng.choice(HOSTS)}")

SCAM_TEXT = [
    ("Are you available?", "Hello, I need a quick favour. Are you at your desk? I am tied up in a conference and need you to buy some gift cards for clients. Will refund you today."),
    ("Urgent wire transfer", "Please process an urgent wire transfer to the vendor today. Bank account details are below. Keep this confidential until I confirm."),
    ("Change of banking details", "Our company has changed banks. All future invoices should be paid to the new bank account. Please confirm by return."),
    ("Part-time job offer", "Earn extra income working from home, no experience needed. Make money fast - reply with your phone number to start today."),
    ("Refund pending", "Your refund of $349 is pending. Please send your bank account and social security number so we can release the funds."),
    ("Inheritance notification", "I am a barrister handling the estate of a deceased client who shares your surname. You will receive a share. Reply with your full name and bank account."),
]
for subj, body in SCAM_TEXT:
    for sender in ("mr.richard.hale@gmail.com", "claims.office.dept@outlook.com"):
        add("phishing", "freemail_scam_text", sender, subj, body)

KNOWN_HARD = [  # no detectable signal without SPF/DKIM headers: kept to keep the score honest
    ("billing@paypal.com", "Payment review", "Hi, please review the attached payment summary and reply with any questions."),
    ("security@microsoft.com", "Document shared with you", "A colleague shared a document with you. Open it from your inbox."),
    ("no-reply@amazon.com", "Your order update", "Your order status has changed. Check Your Orders for details."),
]
for sender, subj, body in KNOWN_HARD * 2:
    add("phishing", "spoofed_trusted_no_signal", sender, subj, body)

# ── Legitimate ────────────────────────────────────────────────────────────────
SEC_ALERTS = [
    ("no-reply@accounts.google.com", "Security alert", "We noticed a new sign-in to your Google Account on a Windows device. If this was you, you don't need to do anything. If not, please reset your password."),
    ("account-security-noreply@accountprotection.microsoft.com", "Microsoft account security info", "We detected unusual sign-in activity on your account. Please verify it was you in your account settings."),
    ("noreply@github.com", "[GitHub] Please verify your email address", "To finish setting up your account, verify your email address using the link in your settings."),
    ("no_reply@email.apple.com", "Your Apple ID was used to sign in", "Your Apple ID was used to sign in to a new browser. If this was you, no action is required."),
    ("service@paypal.com", "Your PayPal receipt", "You sent a payment of $120.00. Transaction ID 8K2.. This is a confirmation for your records."),
    ("auto-confirm@amazon.com", "Your Amazon.com order", "Thanks for your order. We'll send a confirmation when your item ships."),
    ("noreply@uber.com", "Your Friday trip", "Thanks for riding. Here is your receipt for the trip."),
]
for s, subj, body in SEC_ALERTS:
    for _ in range(2):
        add("legit", "trusted_security_alert", s, subj, body)

RETAIL = [
    ("deals@target.com", "Limited time: free shipping on orders over $35", "Limited time only. Free shipping, no cost to join. Unsubscribe | Manage preferences."),
    ("offers@walmart.com", "Last chance: weekend savings", "Last chance to save. Guaranteed low prices. You are receiving this email because you subscribed. Opt out."),
    ("news@spotify.com", "Congratulations - your year in music", "Congratulations! See inside for your personalised summary. Manage preferences."),
    ("promo@booking.com", "Today only: genie deals", "Today only: save on your next stay. Satisfaction guaranteed. Unsubscribe."),
    ("hello@airbnb.com", "You've been selected: early access", "You've been selected to try new features. Click here to learn more. Unsubscribe."),
]
for s, subj, body in RETAIL:
    for _ in range(3):
        add("legit", "trusted_retail_marketing", s, subj, body)

for dom in ("nytimes.com", "medium.com", "mailchimp.com", "substack.com", "stripe.com", "github.com"):
    for _ in range(2):  # same-organisation tracking subdomain: registrable domain matches
        add("legit", "trusted_same_org_tracking", f"news@{dom}", "This week",
            f'Story: <a href="https://click.{dom}/r/{rng.randint(10**5, 10**6)}">https://www.{dom}/p/{rng.randint(1, 99)}</a>\n\nUnsubscribe')
for dom in ("target.com", "booking.com", "uber.com"):  # ESP redirect on a different domain (genuinely ambiguous)
    add("legit", "trusted_esp_redirect", f"deals@{dom}", "Weekend offers",
        f'See offers: <a href="https://links.esp-mail-delivery.net/c/{rng.randint(10**5, 10**6)}">https://www.{dom}/offers</a>\n\nUnsubscribe')

PERSONAL = [
    ("Rent this month", "Hi, I've sent the rent by bank transfer this morning from my bank account. Let me know once it arrives."),
    ("Wire details for the house", "Hi, the solicitor asked me to confirm the wire transfer details by phone before we send the deposit. Can you call me?"),
    ("Dinner Saturday?", "Are you free on Saturday? We booked a table for 8. Let me know and I'll confirm."),
    ("Photos from the trip", "Here are the photos from last weekend. The credit card thing at the hotel was a mess, tell you about it later!"),
    ("Re: tax documents", "I've uploaded the tax documents to the shared folder. Check the bank statements are the right year."),
    ("Study group", "Can everyone send me their notes by Thursday? I'll merge them into one document."),
]
for subj, body in PERSONAL:
    for dom in rng.sample(["gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "icloud.com"], 2):
        add("legit", "personal_freemail_hard", f"{rng.choice(['asha', 'ben', 'carla', 'dev', 'ella'])}.{rng.choice(['rao', 'turner', 'gomez', 'iyer'])}@{dom}", subj, body)

SMALL = ["kiteflyer.io", "lotus-yoga-studio.in", "greenvalley-clinic.org", "tandoor-house.co.uk", "ledgerlane.co",
         "maplebridge-schools.edu.in", "ashwoodvets.com", "pixelforge-games.dev", "urbanroots-cafe.com", "bluelagoon-travel.net"]
for dom in SMALL:
    for subj, body in rng.sample([
        ("Booking confirmation", "Hi, your booking for next Tuesday at 6pm is confirmed. Reply if you need to change it. Thanks, the team."),
        ("Monthly newsletter", "Here's what's new this month. Hope to see you soon! Unsubscribe if you'd rather not receive these."),
        ("Your invoice", "Hello, please find your invoice for this month attached. Payment is due in 14 days. Thank you."),
        ("Quick question", "Hi, could you confirm the delivery address before we dispatch? Thanks."),
    ], 2):
        add("legit", "small_org_unknown_domain", f"hello@{dom}", subj, body)

HYPHENATED = ["securepoint-it.com", "safe-harbor-insurance.com", "account-ease-bookkeeping.com", "verifyed-training.org",
              "login-labs.io", "trustworthy-movers.com"]
for dom in HYPHENATED:  # plausible real businesses whose names contain 'security'-style words
    add("legit", "hyphenated_business_hard", f"info@{dom}", "Welcome to our service",
        "Thanks for getting in touch. A member of our team will reply within one working day.")

for dom in ("paypointsystems.net", "applecross-dental.co.uk", "chasecreekfarm.com", "netfleet.io", "microtech-solutions.com", "googleplexcafe.com"):
    add("legit", "legit_name_collision", f"office@{dom}", "Opening hours",
        "Hi, just a note that we're open 9 to 5 on weekdays. Walk-ins welcome.")

for dom, subj in (("cs.ox.ac.uk", "Seminar this Thursday"), ("iitb.ac.in", "Admission schedule"), ("nic.in", "Portal maintenance notice"),
                  ("gov.uk", "Your application update"), ("nhs.uk", "Appointment reminder")):
    add("legit", "institution", f"admin@{dom}", subj, "This is a notification regarding your recent request. No action is needed unless stated.")

rng.shuffle(rows)
for n, r in enumerate(rows, 1):
    r["id"] = n
with open(os.path.join(HERE, "dataset_v2.jsonl"), "w", encoding="utf-8") as f:
    for r in rows:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
ph = sum(r["label"] == "phishing" for r in rows)
print(f"wrote {len(rows)} samples (phishing={ph}, legit={len(rows) - ph})")

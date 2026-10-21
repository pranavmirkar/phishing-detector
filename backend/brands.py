"""
Static threat-intelligence data used by the detector.

Kept separate from detector.py so it can be reviewed and extended without
touching scoring logic.
"""

# Shared mailbox providers. A message from gmail.com proves nothing about who
# sent it: anyone can register an address, so these never earn "trusted" status.
FREEMAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "yahoo.co.in", "yahoo.co.uk", "ymail.com", "rocketmail.com", "icloud.com",
    "me.com", "mac.com", "aol.com", "proton.me", "protonmail.com", "pm.me", "gmx.com",
    "gmx.net", "mail.com", "zoho.com", "yandex.com", "yandex.ru", "mail.ru", "rediffmail.com",
    "fastmail.com", "tutanota.com", "hey.com",
}

# Registrable domains that sit under a two-part public suffix.
TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "co.in", "org.in", "ac.in", "gov.in",
    "edu.in", "net.in", "res.in", "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz",
    "co.jp", "ne.jp", "com.br", "com.mx", "com.ar", "co.za", "com.sg", "com.hk", "com.cn",
    "com.tr", "com.pk", "com.bd", "com.my", "co.id", "co.kr", "co.il", "com.ng", "com.eg",
    "edu.sg", "edu.hk", "edu.cn", "edu.pk",
}

# Brands that attackers impersonate. label -> real domains owned by that brand.
# Includes brands outside the top-1000 popularity list (banks, couriers) because
# popularity rank says nothing about how often a brand is phished.
PROTECTED = {
    "paypal": {"paypal.com", "paypal.me", "paypal.co.uk", "paypal.in", "paypal-communication.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.com.au", "amazonaws.com", "amazon.jobs"},
    "apple": {"apple.com", "apple.co", "icloud.com", "me.com", "itunes.com"},
    "icloud": {"icloud.com", "apple.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com", "outlook.com", "windows.com", "azure.com", "msn.com", "skype.com", "xbox.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "googlemail.com", "google.co.in", "google.co.uk"},
    "facebook": {"facebook.com", "facebookmail.com", "fb.com", "meta.com", "messenger.com", "instagram.com", "whatsapp.com"},
    "instagram": {"instagram.com", "facebook.com", "meta.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net", "facebook.com"},
    "telegram": {"telegram.org", "t.me", "telegram.me"},
    "linkedin": {"linkedin.com"},
    "twitter": {"twitter.com", "twittermail.com", "x.com", "t.co"},
    "netflix": {"netflix.com"},
    "spotify": {"spotify.com"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "adobe": {"adobe.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "zoom": {"zoom.us", "zoom.com"},
    "github": {"github.com", "githubusercontent.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com", "binance.us"},
    "robinhood": {"robinhood.com"},
    "venmo": {"venmo.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "intuit": {"intuit.com", "turbotax.com", "quickbooks.com"},
    "ebay": {"ebay.com", "ebay.co.uk", "ebay.in"},
    "yahoo": {"yahoo.com", "yahoo.co.in", "yahoo.co.uk"},
    # banks / cards
    "bankofamerica": {"bankofamerica.com", "bofa.com", "merrilledge.com"},
    "chase": {"chase.com", "jpmorgan.com", "jpmorganchase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "citibank": {"citibank.com", "citi.com", "citigroup.com"},
    "capitalone": {"capitalone.com"},
    "americanexpress": {"americanexpress.com", "aexp.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk", "hsbc.co.in"},
    "barclays": {"barclays.com", "barclays.co.uk"},
    "santander": {"santander.com", "santander.co.uk"},
    "usbank": {"usbank.com"},
    "discover": {"discover.com"},
    "mastercard": {"mastercard.com"},
    "visa": {"visa.com"},
    "hdfcbank": {"hdfcbank.com", "hdfc.com"},
    "icicibank": {"icicibank.com"},
    "axisbank": {"axisbank.com"},
    "sbi": {"sbi.co.in", "onlinesbi.com", "onlinesbi.sbi", "sbi.bank.in"},
    "kotak": {"kotak.com", "kotakbank.com"},
    "paytm": {"paytm.com", "paytmbank.com"},
    "phonepe": {"phonepe.com"},
    "razorpay": {"razorpay.com"},
    "usaa": {"usaa.com"},
    "navyfederal": {"navyfederal.org"},
    "itau": {"itau.com.br", "itau.com.ar", "itau.cl", "itau.com"},
    "bradesco": {"bradesco.com.br", "bradesco.com"},
    "bancodobrasil": {"bb.com.br"},
    "caixa": {"caixa.gov.br", "caixa.com.br"},
    "lloyds": {"lloydsbank.com", "lloydsbankinggroup.com", "lloydsbank.co.uk"},
    "natwest": {"natwest.com", "rbs.co.uk"},
    "scotiabank": {"scotiabank.com"},
    "rbc": {"rbc.com", "rbcroyalbank.com"},
    "bmo": {"bmo.com"},
    "deutschebank": {"deutsche-bank.de", "db.com"},
    "commerzbank": {"commerzbank.de"},
    "sparkasse": {"sparkasse.de"},
    "att": {"att.com", "att.net", "sbcglobal.net"},
    "verizon": {"verizon.com", "verizonwireless.com", "verizon.net"},
    "comcast": {"comcast.com", "comcast.net", "xfinity.com"},
    "aol": {"aol.com"},
    "alibaba": {"alibaba.com", "aliexpress.com", "alibabagroup.com"},
    "wetransfer": {"wetransfer.com"},
    "shopify": {"shopify.com"},
    "squarespace": {"squarespace.com"},
    "godaddy": {"godaddy.com"},
    "namecheap": {"namecheap.com"},
    # couriers / government
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "usps": {"usps.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "royalmail": {"royalmail.com"},
    "irs": {"irs.gov"},
    "incometax": {"incometax.gov.in", "incometaxindia.gov.in"},
    "irctc": {"irctc.co.in"},
}

# Words attackers append to / prepend to a brand to build a plausible domain.
LURE_WORDS = {
    "secure", "security", "verify", "verification", "login", "signin", "logon", "account", "accounts",
    "update", "support", "help", "helpdesk", "billing", "payment", "payments", "auth", "authenticate",
    "alert", "alerts", "confirm", "recover", "recovery", "unlock", "wallet", "service", "services",
    "customer", "care", "online", "portal", "official", "my", "web", "app", "mail", "id", "team",
    "refund", "claim", "safe", "trust", "center", "centre", "desk", "notice", "review",
}

# TLDs heavily abused for throw-away phishing hosts (cheap/free registration).
ABUSED_TLDS = {
    "xyz", "top", "click", "icu", "cfd", "buzz", "sbs", "rest", "cam", "work", "live", "online",
    "site", "shop", "loan", "gq", "tk", "ml", "cf", "ga", "zip", "mov", "monster", "quest",
    "fun", "vip", "support", "bid", "country", "stream", "download", "review", "date", "men",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly", "tiny.cc",
    "t.ly", "shorturl.at", "rb.gy", "buff.ly", "s.id", "v.gd",
}

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


# ── Extended protected-brand list (most-phished organisations worldwide) ──────────────────────
# label -> the organisation's real domains. A sender whose display name or domain *uses* the label
# without owning one of these domains is treated as impersonating it.
PROTECTED.update({
    # webmail / hosting / enterprise software
    "zimbra": {"zimbra.com"}, "cpanel": {"cpanel.net", "cpanel.com"}, "roundcube": {"roundcube.net"},
    "office365": {"office365.com", "microsoft.com", "office.com", "microsoftonline.com"},
    "onedrive": {"onedrive.com", "live.com", "microsoft.com", "1drv.ms"},
    "sharepoint": {"sharepoint.com", "microsoft.com"},
    "outlook": {"outlook.com", "microsoft.com", "live.com", "office.com"},
    "salesforce": {"salesforce.com", "force.com"}, "workday": {"workday.com"}, "adp": {"adp.com"},
    "norton": {"norton.com", "symantec.com", "nortonlifelock.com", "gendigital.com"}, "mcafee": {"mcafee.com"},
    "avast": {"avast.com"}, "kaspersky": {"kaspersky.com"}, "bluehost": {"bluehost.com"}, "hostgator": {"hostgator.com"},
    "wix": {"wix.com"}, "wordpress": {"wordpress.com", "wordpress.org", "automattic.com"}, "xero": {"xero.com"},
    "quickbooks": {"quickbooks.com", "intuit.com"}, "zoho": {"zoho.com"}, "dhgate": {"dhgate.com"},
    "globalsources": {"globalsources.com"}, "aliexpress": {"aliexpress.com", "alibaba.com"},
    "rakuten": {"rakuten.com", "rakuten.co.jp", "rakuten.ne.jp"}, "naver": {"naver.com", "navercorp.com"},
    "mercadolibre": {"mercadolibre.com", "mercadopago.com", "mercadolivre.com.br"}, "flipkart": {"flipkart.com"},
    "walmart": {"walmart.com"}, "costco": {"costco.com"}, "bestbuy": {"bestbuy.com"}, "target": {"target.com"},
    "homedepot": {"homedepot.com"}, "lowes": {"lowes.com"}, "etsy": {"etsy.com"}, "shopee": {"shopee.com", "shopee.sg"},
    "lazada": {"lazada.com"}, "temu": {"temu.com"}, "shein": {"shein.com"}, "airbnb": {"airbnb.com"},
    "booking": {"booking.com"}, "expedia": {"expedia.com"}, "uber": {"uber.com"}, "lyft": {"lyft.com"},
    "ticketmaster": {"ticketmaster.com"}, "stripe": {"stripe.com"}, "square": {"squareup.com", "square.com"},
    "wise": {"wise.com", "transferwise.com"}, "revolut": {"revolut.com"}, "klarna": {"klarna.com"},
    "westernunion": {"westernunion.com"}, "moneygram": {"moneygram.com"}, "zelle": {"zellepay.com"},
    "cashapp": {"cash.app", "square.com"}, "metamask": {"metamask.io"}, "blockchain": {"blockchain.com"},
    "trustwallet": {"trustwallet.com"}, "kraken": {"kraken.com"}, "bitcoin": {"bitcoin.org"},
    "ledger": {"ledger.com"}, "opensea": {"opensea.io"}, "crypto": {"crypto.com"}, "gemini": {"gemini.com"},
    # telecom / ISP / media
    "tmobile": {"t-mobile.com"}, "spectrum": {"spectrum.com", "charter.com", "charter.net"},
    "xfinity": {"xfinity.com", "comcast.com", "comcast.net"}, "cox": {"cox.com", "cox.net"},
    "vodafone": {"vodafone.com", "vodafone.co.uk"}, "orange": {"orange.com", "orange.fr", "orange.co.uk", "orange.es"},
    "telstra": {"telstra.com", "telstra.com.au"}, "bt": {"bt.com", "btinternet.com"}, "sky": {"sky.com"},
    "telekom": {"telekom.de", "telekom.com", "t-online.de"}, "airtel": {"airtel.in", "airtel.com"}, "jio": {"jio.com"},
    "disney": {"disney.com", "disneyplus.com"}, "hulu": {"hulu.com"}, "hbo": {"hbo.com", "hbomax.com", "max.com"},
    "twitch": {"twitch.tv"}, "tiktok": {"tiktok.com"}, "snapchat": {"snapchat.com"}, "pinterest": {"pinterest.com"},
    "reddit": {"reddit.com", "redditmail.com"}, "discord": {"discord.com", "discordapp.com"}, "skype": {"skype.com", "microsoft.com"},
    "playstation": {"playstation.com", "sony.com"}, "xbox": {"xbox.com", "microsoft.com"}, "nintendo": {"nintendo.com"},
    "epicgames": {"epicgames.com"}, "roblox": {"roblox.com"}, "blizzard": {"blizzard.com", "battle.net"},
    # banks and card networks, worldwide
    "ing": {"ing.com", "ing.nl", "ing.de", "ing.be"}, "abnamro": {"abnamro.nl", "abnamro.com"}, "rabobank": {"rabobank.nl", "rabobank.com"},
    "bbva": {"bbva.com", "bbva.es", "bbva.mx"}, "caixabank": {"caixabank.es", "caixabank.com"}, "unicredit": {"unicredit.it", "unicreditgroup.eu"},
    "intesasanpaolo": {"intesasanpaolo.com"}, "creditagricole": {"credit-agricole.fr", "credit-agricole.com"},
    "bnpparibas": {"bnpparibas.com", "bnpparibas.fr"}, "societegenerale": {"societegenerale.com", "societegenerale.fr"},
    "postbank": {"postbank.de"}, "volksbank": {"volksbank.de"}, "n26": {"n26.com"},
    "westpac": {"westpac.com.au"}, "commbank": {"commbank.com.au"}, "anz": {"anz.com", "anz.com.au"}, "nab": {"nab.com.au"},
    "cibc": {"cibc.com"}, "td": {"td.com", "tdbank.com"}, "tsb": {"tsb.co.uk", "tsb.com"}, "nationwide": {"nationwide.co.uk"},
    "halifax": {"halifax.co.uk"}, "monzo": {"monzo.com"}, "starling": {"starlingbank.com"}, "metrobank": {"metrobankonline.co.uk"},
    "standardbank": {"standardbank.com", "standardbank.co.za"}, "absa": {"absa.co.za", "absa.africa"}, "nedbank": {"nedbank.co.za"},
    "capitec": {"capitecbank.co.za"}, "fnb": {"fnb.co.za", "firstnational.co.za"}, "ecobank": {"ecobank.com"},
    "emiratesnbd": {"emiratesnbd.com"}, "adcb": {"adcb.com"}, "mashreq": {"mashreqbank.com"}, "qnb": {"qnb.com"},
    "pnb": {"pnbindia.in", "pnb.co.in"}, "canarabank": {"canarabank.com"}, "bankofindia": {"bankofindia.co.in"},
    "unionbank": {"unionbankofindia.co.in", "unionbank.com"}, "indusind": {"indusind.com"}, "yesbank": {"yesbank.in"},
    "santanderbr": {"santander.com.br"}, "nubank": {"nubank.com.br"}, "inter": {"bancointer.com.br"},
    "banorte": {"banorte.com"}, "bancolombia": {"bancolombia.com"}, "mufg": {"mufg.jp"}, "mizuho": {"mizuhobank.co.jp", "mizuho-fg.co.jp"},
    "smbc": {"smbc.co.jp"}, "rakutenbank": {"rakuten-bank.co.jp"}, "dbs": {"dbs.com", "dbs.com.sg"}, "ocbc": {"ocbc.com"},
    "uob": {"uob.com.sg"}, "maybank": {"maybank.com", "maybank2u.com.my"}, "cimb": {"cimb.com"}, "kbank": {"kasikornbank.com"},
    "citizens": {"citizensbank.com"}, "pnc": {"pnc.com"}, "truist": {"truist.com"}, "fifththird": {"53.com"}, "regions": {"regions.com"},
    "ally": {"ally.com"}, "synchrony": {"synchrony.com"}, "marcus": {"marcus.com"}, "schwab": {"schwab.com"}, "fidelity": {"fidelity.com"},
    "vanguard": {"vanguard.com"}, "etrade": {"etrade.com"}, "tdameritrade": {"tdameritrade.com"}, "paypalcredit": {"paypal.com"},
    "psecu": {"psecu.com"}, "suncorp": {"suncorp.com.au"}, "kiwibank": {"kiwibank.co.nz"}, "asb": {"asb.co.nz"},
    # post, couriers, government
    "canadapost": {"canadapost.ca", "canadapost-postescanada.ca"}, "auspost": {"auspost.com.au"}, "hermes": {"myhermes.co.uk", "evri.com"},
    "dpd": {"dpd.com", "dpd.de", "dpd.co.uk"}, "gls": {"gls-group.eu", "gls-group.com"}, "aramex": {"aramex.com"}, "tnt": {"tnt.com"},
    "postnl": {"postnl.nl"}, "deutschepost": {"deutschepost.de", "dhl.de"}, "laposte": {"laposte.fr"}, "correos": {"correos.es"},
    "poste": {"poste.it", "posteitaliane.it"}, "indiapost": {"indiapost.gov.in"}, "bluedart": {"bluedart.com"},
    "hmrc": {"hmrc.gov.uk", "gov.uk"}, "dvla": {"dvla.gov.uk", "gov.uk"}, "ssa": {"ssa.gov"}, "dmv": {"dmv.gov"},
    "ato": {"ato.gov.au"}, "centrelink": {"servicesaustralia.gov.au"}, "mygov": {"my.gov.au"}, "cra": {"canada.ca"},
    "ministeriodelinterior": {"interior.gob.es"}, "sat": {"sat.gob.mx"}, "dian": {"dian.gov.co"}, "receita": {"receita.fazenda.gov.br"},
})

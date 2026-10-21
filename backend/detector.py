import itertools
import re
import unicodedata
from urllib.parse import ParseResult, urlparse as _urlparse

from levenshtein import (
    levenshtein_distance,
    get_dp_matrix,
    get_edit_operations,
    similarity_percent,
)
from domain_intel import (
    is_trusted as tranco_is_trusted,
    get_levenshtein_pool,
    check_domain_age,
)
import model as scoring_model
from brands import (
    FREEMAIL, TWO_PART_SUFFIXES, PROTECTED, LURE_WORDS, ABUSED_TLDS, URL_SHORTENERS,
)

# Unicode and visual homoglyphs that bypass naive string comparison
HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ѕ": "s", "ј": "j", "һ": "h", "ԁ": "d", "ɡ": "g", "ո": "n",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "@": "a", "$": "s",
}
MULTI_CHAR_HOMOGLYPHS = {"rn": "m", "vv": "w", "cl": "d"}

SUSPICIOUS_KEYWORDS = [
    # Urgency / pressure
    "urgent", "act now", "action required", "immediately", "don't delay",
    "limited time", "expires soon", "last chance", "today only", "respond now",
    # Identity phishing
    "verify your account", "confirm your identity", "account suspended",
    "account on hold", "unusual activity", "login attempt",
    "update your info", "reset your password",
    "dear customer", "dear user", "dear valued member", "dear account holder",
    # Financial fraud
    "update your payment", "billing information", "credit card",
    "bank account", "social security", "wire transfer",
    "make money fast", "earn $", "extra income", "double your money",
    "investment opportunity", "financial freedom",
    # Prize / lottery
    "you have won", "you've won", "winner", "prize", "free gift",
    "congratulations", "you've been selected", "lucky winner",
    "lottery", "sweepstakes", "jackpot", "claim now", "claim your",
    # Delivery / fee scams
    "redelivery fee", "delivery attempt failed", "could not be delivered",
    "reschedule your parcel", "reschedule your delivery", "customs fee",
    # Clickbait
    "click here", "click now", "open now", "see inside",
    # Marketing spam
    "risk-free", "guaranteed", "100% free", "no obligation",
    "satisfaction guaranteed", "money back", "no cost",
    # Health spam
    "lose weight", "miracle cure", "no prescription",
]

# Keywords that are still worth a (small) penalty when the sender is a verified
# brand domain. Real brands legitimately send security alerts and password
# resets; marketing words from them are normal and are ignored.
TRUSTED_SENDER_KEYWORDS = {
    "verify your account", "confirm your identity", "account suspended", "account on hold",
    "update your payment", "billing information", "social security", "wire transfer",
    "you have won", "you've won", "lucky winner", "lottery",
}

# Account-takeover wording: asks the reader to sign in, confirm or reset something.
INTENT_RE = re.compile(
    r"(verify|confirm|validate|update|review|restore|unlock|secure)\s+(your|the)\s+"
    r"(account|identity|information|info|details|password|profile|payment|billing|card|login|access)"
    r"|\b(sign|log)[\s-]?in\b|\blogin\b|\bpassword\b"
    r"|(account|profile|access)\s+(has been\s+|is\s+|was\s+|will be\s+)?(suspended|locked|limited|restricted|closed|disabled|on hold)"
    r"|card details|billing information|restore access|suspicious (sign|log)",
    re.I,
)

# Business-email-compromise and advance-fee wording. Each distinct hit counts.
SCAM_PHRASES = [
    "gift card", "gift cards", "new bank account", "changed banks", "changed our bank",
    "banking details", "bank account details", "new account below",
    "keep this confidential", "keep this between us", "are you available", "are you at your desk",
    "handle a task", "reply when you see this",
    "work from home", "no experience needed", "next of kin", "barrister",
    "deceased client", "social security number", "processing fee", "western union",
    "send your bank account", "claim your prize", "pay and reschedule",
]
# Phrases with ordinary innocent uses ("class inheritance", "tied up in meetings"):
# they only add a little, so one of them alone never flags a message.
WEAK_SCAM_PHRASES = ["inheritance", "tied up in", "in a conference and", "bitcoin", " btc", "direct deposit"]

ADMIN_DISPLAY_RE = re.compile(
    r"\b(admin(istrator)?|webmail|postmaster|(mail|message|help|support|service|document) (center|centre|support|delivery|server|notification)s?|"
    r"human resources?( team)?|hr (team|dept|department)|payroll|accounts? (payable|department)|(e-?)?mail (service|system|team|admin\w*)|help ?desk|it support|it'?s? help|"
    r"system (admin\w*)|account (support|team|service|warning)|security team|support team)\b", re.I)
CLICK_RE = re.compile(r"click here|follow the (link|below)|link below|click (the )?(link|button)|proceed with|click on", re.I)

BULK_SENDER_PATTERNS = [
    "unsubscribe", "opt-out", "opt out",
    "you are receiving this email because",
    "this email was sent to", "manage preferences",
    "view this email in your browser", "add us to your address book",
]

ROLE_WORDS = {
    "support", "care", "help", "team", "service", "security", "billing", "alert", "alerts",
    "noreply", "desk", "dept", "admin", "official", "customer", "verify", "account", "accounts",
    "helpdesk", "notification", "notifications",
}

# Extra names people write for a brand in prose / display names.
BRAND_ALIASES = {
    "bankofamerica": ["bank of america", "bofa"], "wellsfargo": ["wells fargo"],
    "americanexpress": ["american express", "amex"], "hdfcbank": ["hdfc bank", "hdfc"],
    "icicibank": ["icici bank", "icici"], "axisbank": ["axis bank"],
    "sbi": ["state bank of india", "sbi"], "citibank": ["citi bank", "citibank"],
    "capitalone": ["capital one"], "usbank": ["us bank", "u.s. bank"],
    "microsoft": ["microsoft", "office 365"], "royalmail": ["royal mail"],
    "incometax": ["income tax department"], "kotak": ["kotak mahindra", "kotak"],
}
MENTION_EXCLUDE = {"discover", "ups", "visa", "outlook", "office365", "onedrive", "sharepoint", "skype"}   # common words: too noisy to count as a brand mention



def _strip_blocks(s: str) -> str:
    """Remove <style> / <script> blocks in one linear pass (a regex here is quadratic on unclosed tags)."""
    low = s.lower()
    out, i, n = [], 0, len(s)
    nxt = {"<style": low.find("<style"), "<script": low.find("<script")}
    while i < n:
        for k in nxt:
            if 0 <= nxt[k] < i:
                nxt[k] = low.find(k, i)
        starts = [v for v in nxt.values() if v >= 0]
        if not starts:
            out.append(s[i:])
            break
        a = min(starts)
        out.append(s[i:a])
        tag = "</style" if low.startswith("<style", a) else "</script"
        end = low.find(tag, a)
        if end < 0:
            break                                    # unclosed: the rest is code, not text
        gt = low.find(">", end)
        i = n if gt < 0 else gt + 1
    return "".join(out)


def _visible_text(content: str, limit: int = 1500) -> str:
    """Tag/CSS-stripped start of the message: where lures state their demand."""
    t = TAG_RE.sub(" ", _strip_blocks(content[:60000]))
    return re.sub(r"\s+", " ", t).strip()[:limit]


# Attachment types that have no business in ordinary mail (HTML pages that open a fake login,
# disk images / scripts / shortcuts used to deliver malware).
HTML_ATTACH = {"html", "htm", "shtml", "xhtml", "xht", "svg", "mht", "mhtml"}
EXEC_ATTACH = {"exe", "scr", "com", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "hta", "lnk", "iso", "img",
               "jar", "msi", "ps1", "dll", "apk", "chm", "reg"}
ARCHIVE_ATTACH = {"zip", "rar", "7z", "gz", "tar", "ace", "arj", "cab"}
FORM_RE = re.compile(r"<form\b[^>]{0,500}?action\s*=\s*[\"']?(https?://[^\s\"'>]+)", re.I | re.S)
PASSWORD_INPUT_RE = re.compile(r"<input\b[^>]{0,300}?type\s*=\s*[\"']?password", re.I | re.S)

# Phrases that are specific to credential / payment fraud. Generic pressure and marketing wording
# ("urgent", "limited time", "free gift", "guaranteed") is common in legitimate newsletters, so it
# counts for much less.
CORE_KEYWORDS = TRUSTED_SENDER_KEYWORDS | {
    "login attempt", "unusual activity", "update your info", "reset your password", "credit card", "bank account",
    "dear customer", "dear user", "dear valued member", "dear account holder", "claim your", "claim now",
    "redelivery fee", "delivery attempt failed", "could not be delivered", "reschedule your parcel",
    "reschedule your delivery", "customs fee", "make money fast", "earn $", "double your money", "lottery",
}

# Words that make a domain name look like a credential-harvesting host. (Common words such as "online",
# "mail" or "service" are deliberately absent: they appear in countless legitimate names.)
DOMAIN_CRED_WORDS = {
    "secure", "security", "verify", "verification", "login", "signin", "logon", "account", "accounts", "update",
    "support", "helpdesk", "billing", "payment", "payments", "auth", "authenticate", "alert", "alerts", "confirm",
    "recover", "recovery", "unlock", "wallet", "customer", "care", "refund", "claim", "safe", "trust", "notice", "review",
}

# Legitimate platforms that attackers routinely abuse to host a fake login page or file.
HOSTING_PLATFORMS = {
    "sites.google.com", "forms.gle", "docs.google.com", "storage.googleapis.com", "firebasestorage.googleapis.com",
    "dropboxusercontent.com", "1drv.ms", "onedrive.live.com", "sharepoint.com", "weebly.com", "wixsite.com",
    "blogspot.com", "wordpress.com", "github.io", "netlify.app", "vercel.app", "pages.dev", "web.app",
    "firebaseapp.com", "glitch.me", "herokuapp.com", "typeform.com", "jotform.com", "formspree.io", "ipfs.io",
    "weeblysite.com", "webflow.io", "000webhostapp.com", "azurewebsites.net", "r2.dev", "workers.dev", "carrd.co",
}

DOCSHARE_RE = re.compile(
    r"shared (a|the|an)? ?(document|file|folder)|"
    r"(document|file|contract|proposal|invoice|statement|paystub|pay stub|voice ?mail|fax)s?\b[^.]{0,40}"
    r"\b(shared with you|has arrived|have arrived|is waiting|are waiting|pending|encrypted)|"
    r"you have (\(?\d+\)?|new|unread|pending|encrypted)[^.]{0,25}(mail|message|email|voice ?mail|fax)s?|"
    r"\b(pending|unread|incoming|encrypted|blocked|held|quarantined) (incoming )?(mail|message|email)s?\b", re.I)
SENSITIVE_FIELD_RE = re.compile(r"<input\b[^>]{0,300}?name\s*=\s*[\"']?[a-z_]*(passw|pwd|cvv|ssn|cardnum|card_number)", re.I | re.S)

# Characters from other scripts that are used to disguise Latin words ("Rɵsɵt", "Pаypal").
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ѕ": "s", "ј": "j", "һ": "h",
    "ԁ": "d", "ɡ": "g", "ո": "n", "ɵ": "o", "ο": "o", "α": "a", "ε": "e", "ι": "i", "ν": "v", "ρ": "p", "τ": "t",
    "υ": "u", "κ": "k", "ɑ": "a", "ɛ": "e", "ı": "i", "ᴏ": "o", "ԍ": "g", "ⅼ": "l", "ǀ": "l", "Ι": "I", "Ο": "O",
    "Α": "A", "Ε": "E", "Ρ": "P", "Τ": "T", "Χ": "X", "Ѕ": "S", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
}
CONFUSABLE_TABLE = str.maketrans(CONFUSABLES)
CONFUSABLE_WORD_RE = re.compile(r"\b(?=\w*[A-Za-z])(?=\w*[" + "".join(CONFUSABLES) + r"])\w{3,}\b")

PAYMENT_LURE_RE = re.compile(
    r"(trouble|problem|issue)s? with your (current )?(billing|payment)|update your (payment|billing)( details| information| method)?|"
    r"(card|payment) (has been |was |is )?(declined|blocked|failed|expired)|"
    r"(membership|subscription|account) (will be |has been |is )?(cancel+ed|suspended|expired|on hold)|"
    r"(unauthori[sz]ed|unrecogni[sz]ed|suspicious) (access|transaction|activity|login|sign.?in)", re.I)

# Brand names that are also ordinary words: a domain such as "orange-county-dental.com" is not
# impersonation, so these only count together with a lure word ("orange-login.com").
AMBIGUOUS_BRANDS = {
    "apple", "orange", "target", "chase", "discover", "visa", "square", "slack", "zoom", "meta", "office", "windows",
    "outlook", "live", "steam", "gold", "citi", "ing", "inter", "ally", "sky", "wise", "td", "bt", "ato", "sat", "cra",
    "regions", "citizens", "marcus", "gemini", "ledger", "crypto", "poste", "nationwide", "halifax", "starling", "sharepoint",
}

DEAR_RE = re.compile(r"\bdear\s+(email|e-mail|mail|webmail|account|valued|beloved|esteemed)?\s*"
                     r"(user|customer|member|subscriber|client|holder|friend|sir|madam|sir/madam|email user)s?\b", re.I)
NEWFILE_RE = re.compile(r"\b(new|you have a|you've got a|you have received a|you received a)\s+"
                        r"(recording|voice ?message|voicemail|fax|file|document|invoice|payment|order|shipment|parcel)\b|"
                        r"\b(received|got)\s+(a\s+|an\s+)?(new\s+)?(file|document|message|fax|voicemail|recording)\b", re.I)

# Non-English account/credential phrases. Two distinct hits in one message are needed.
INTL_PHRASES = {
    "es": ["verifique su cuenta", "su cuenta ha sido", "cuenta suspendida", "actualice su", "contraseña", "haga clic", "multa", "tarjeta de crédito", "banco", "confirme su"],
    "pt": ["verifique sua conta", "sua conta", "conta suspensa", "conta bloqueada", "atualize seus dados", "atualização", "senha", "clique aqui", "cartão", "confirme seu"],
    "fr": ["vérifiez votre compte", "votre compte", "compte suspendu", "mot de passe", "cliquez ici", "mettre à jour", "confirmez votre"],
    "de": ["ihr konto", "bestätigen sie", "passwort", "jetzt aktualisieren", "gesperrt", "klicken sie hier", "ihr paket", "zahlung"],
    "it": ["verifica il tuo account", "il tuo account", "conto sospeso", "clicca qui", "aggiorna", "conferma"],
    "nl": ["uw account", "bevestig", "wachtwoord", "klik hier", "geblokkeerd"],
    "ru": ["ваш аккаунт", "пароль", "подтвердите", "заблокирован", "нажмите"],
    "ja": ["アカウント", "パスワード", "確認", "更新", "停止", "ログイン", "お客様"],
    "zh": ["账户", "帐户", "密码", "验证", "更新", "暂停", "登录", "登陆", "需要采取", "您的邮箱"],
    "tr": ["hesabınız", "şifre", "doğrulayın", "tıklayın"],
}

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
ANCHOR_RE = re.compile(r"<a\b[^>]{0,500}?href\s*=\s*[\"']([^\"']{1,2000})[\"'][^>]{0,500}>(.{0,400}?)</a>", re.I | re.S)
TAG_RE = re.compile(r"<[^<>]*>")   # [^<>] cannot cross another "<", so unclosed tags cost O(n) overall
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)

PROTECTED_DOMAINS = {d for ds in PROTECTED.values() for d in ds}

# "paypal.<tld>" is only treated as an imitation on generic / risky TLDs. Country
# sites (yahoo.com.au, amazon.es) are normal and would otherwise be false positives.
SAME_NAME_RISKY_TLDS = ABUSED_TLDS | {"info", "biz", "net", "org", "co", "cc", "ws", "pw", "tech", "store",
                                      "link", "email", "pro", "mobi", "name"}

# Host labels that say what a machine does, not who owns it.
GENERIC_HOST_WORDS = LURE_WORDS | {
    "mail", "email", "www", "smtp", "imap", "webmail", "static", "cloud", "cdn", "api", "server", "ftp",
    "news", "blog", "shop", "store", "video", "media", "images", "files", "download", "update", "updates",
    "search", "maps", "drive", "docs", "play", "games", "music", "photos", "radio", "live", "world",
}

GENERIC_DISPLAY = ROLE_WORDS | {
    "com", "net", "online", "express", "inc", "corp", "corporation", "llc", "ltd", "bank", "banking",
    "group", "mobile", "web", "mail", "email", "financial", "credit", "union", "federal", "the", "of",
    "from", "via", "and", "center", "centre", "member", "fdic", "my", "e", "id", "no", "reply",
    "update", "updates", "notice", "notices", "info", "information", "new", "important",
    "feedback", "protection", "assistance", "secure", "inc", "rewards", "offers", "shipping", "delivery", "tracking",
    "payments", "orders", "receipts", "invoice", "statement", "news", "promo", "international", "global", "worldwide",
    "logistics", "courier", "services", "customer", "relations", "co", "jp", "uk", "de", "fr", "in", "ca", "au", "us", "es",
    "it", "nl", "br", "mx", "ru", "cn", "kr", "eu", "support", "online", "team", "billing",
}

# Generic "your account/mailbox is in trouble, act now" structure (brand-independent).
THREAT_RE = re.compile(
    r"expir(e|es|ed|ing|ation)\b|suspend|blocked|deactivat|shut\s?down|terminat|limit(ed)?\s+exceeded|"
    r"exceeded\s+(your\s+)?(storage|mailbox|quota|limit)|(mailbox|inbox|storage)\s+(is\s+)?(almost\s+)?(full|over)|"
    r"violation|compromis|unauthori[sz]ed|restricted|locked|disabled|will be (closed|deleted|removed)|"
    r"security (alert|warning|upgrade)|account (alert|warning)|failed to deliver|undelivered", re.I)
ACTION_RE = re.compile(
    r"(verify|confirm|validate|re-?validate|update|upgrade|reactivate|restore|secure|unlock|renew|login|log in|sign in)"
    r"\b.{0,30}\b(account|e-?mail|mailbox|password|webmail|identity|information|details|profile|credentials)"
    r"|\b(account|e-?mail|mailbox|webmail|password)\s+(update|upgrade|verification|validation|re-?validation|confirmation|security)", re.I)
URGENCY_RE = re.compile(
    r"within\s+\d+\s+(hours|days)|\b(24|48|72)\s*(hours|hrs)\b|final (warning|notice|reminder)|immediately|"
    r"right away|do not ignore|deadline|act now|urgent|as soon as possible", re.I)


def urlparse(url: str):
    """urllib's urlparse, but malformed links ('http://[', bad ports) give an empty result instead of raising."""
    try:
        return _urlparse(url)
    except ValueError:
        return ParseResult("", "", "", "", "", "")


def _safe_port_host(p) -> str:
    try:
        return (p.hostname or "").lower()
    except ValueError:
        return ""


def registered_domain(host: str) -> str:
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _fold_ascii(text: str) -> str:
    """Strip accents: 'pàypal' -> 'paypal' (non-decomposable chars are kept)."""
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def _decode_idn(host: str):
    """Return (unicode_host, had_punycode, decoded_ok)."""
    labels, had, ok = [], False, True
    for label in host.split("."):
        if label.startswith("xn--"):
            had = True
            try:
                label = label.encode("ascii").decode("idna")
            except Exception:
                ok = False
        labels.append(label)
    return ".".join(labels), had, ok


_CANON_TABLE = str.maketrans({"i": "l", "I": "l", "1": "l", "|": "l", "0": "o", "5": "s", "3": "e", "$": "s"})


def _canon(t: str) -> str:
    """Lower-case with the classic look-alike confusions folded (i/l/1/I -> l, 0 -> o ...)."""
    return t.lower().translate(_CANON_TABLE)


_MENTION = None


def _mention_index():
    """({single-word name: brand}, [(multi-word name, brand)]) for brands worth detecting in prose."""
    global _MENTION
    if _MENTION is None:
        single, multi = {}, []
        for brand in PROTECTED:
            if brand in MENTION_EXCLUDE or brand in AMBIGUOUS_BRANDS or len(brand) < 5:
                continue
            for n in [brand] + BRAND_ALIASES.get(brand, []):
                if " " in n:
                    multi.append((n, brand))
                elif len(n) >= 3:
                    single[n] = brand
        _MENTION = (single, multi)
    return _MENTION


_BRAND_INDEX = None


def _brand_index():
    """canonical first letter -> [(canonical name, brand)] for every brand label and alias of length >= 5."""
    global _BRAND_INDEX
    if _BRAND_INDEX is None:
        idx = {}
        for brand in PROTECTED:
            for n in [brand] + BRAND_ALIASES.get(brand, []):
                n = re.sub(r"[^a-z0-9]", "", n.lower())
                if len(n) >= 5:
                    c = _canon(n)
                    idx.setdefault(c[0], []).append((c, brand))
        _BRAND_INDEX = idx
    return _BRAND_INDEX


_GENERIC_CANON = None


def _is_generic(t: str) -> bool:
    global _GENERIC_CANON
    if _GENERIC_CANON is None:
        _GENERIC_CANON = {_canon(x) for x in GENERIC_DISPLAY}
    return t.isdigit() or t in GENERIC_DISPLAY or _canon(t) in _GENERIC_CANON


def _fuzzy_brand(token: str):
    """Brand whose name `token` imitates (disguised letters or one typo), or None. Exact names are handled elsewhere."""
    c = _canon(token)
    if len(c) < 5:
        return None
    for name, brand in _brand_index().get(c[0], ()):
        if abs(len(c) - len(name)) <= 1 and (c == name or _osa(c, name) <= 1):
            return brand
    return None


_MASKS: dict = {}


def _mask(s: str) -> int:
    """Bitset of the character buckets a string uses. One edit flips at most 2 bits, so
    popcount(mask(a) ^ mask(b)) <= 2 * distance(a, b): a cheap lower bound used to skip hopeless candidates."""
    m = _MASKS.get(s)
    if m is None:
        m = 0
        for ch in s:
            m |= 1 << (ord(ch) % 61)
        if len(_MASKS) < 200_000:
            _MASKS[s] = m
    return m


def _lev_bounded(a: str, b: str, k: int) -> int:
    """Levenshtein distance if <= k, else k + 1. Only a diagonal band is computed, which is much cheaper than the full table."""
    la, lb = len(a), len(b)
    inf = k + 1
    if abs(la - lb) > k:
        return inf
    if la < lb:
        a, b, la, lb = b, a, lb, la
    prev = [j if j <= k else inf for j in range(lb + 1)]
    for i in range(1, la + 1):
        cur = [inf] * (lb + 1)
        if i <= k:
            cur[0] = i
        lo, hi = max(1, i - k), min(lb, i + k)
        ca, best = a[i - 1], cur[0]
        for j in range(lo, hi + 1):
            v = prev[j - 1] + (ca != b[j - 1])
            t = prev[j] + 1
            if t < v:
                v = t
            t = cur[j - 1] + 1
            if t < v:
                v = t
            if v > inf:
                v = inf
            cur[j] = v
            if v < best:
                best = v
        if best >= inf:
            return inf
        prev = cur
    return min(prev[lb], inf)


def _osa(a: str, b: str) -> int:
    """Optimal-string-alignment distance: Levenshtein where one adjacent swap costs 1."""
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            c = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def _text(v) -> str:
    """Any JSON value -> string. Containers become '' (never repr() noise)."""
    if isinstance(v, str):
        return v
    if v is None or isinstance(v, (list, dict, tuple, set)):
        return ""
    return str(v)


def _sanitize_input(data) -> dict:
    """The detector never trusts the shape of its input: wrong types degrade to empty values."""
    if not isinstance(data, dict):
        data = {}
    atts = []
    raw = data.get("attachments")
    for a in (raw if isinstance(raw, list) else [])[:25]:
        if isinstance(a, dict):
            name = _text(a.get("filename"))
        else:
            name = _text(a)
        if name:
            atts.append({"filename": name[:200]})
    auth = data.get("auth_results")
    auth = {str(k): _text(v) for k, v in auth.items()} if isinstance(auth, dict) else _text(auth)
    own = data.get("own_domains")
    return {
        "sender": _text(data.get("sender")), "subject": _text(data.get("subject")), "content": _text(data.get("content")),
        "reply_to": _text(data.get("reply_to")), "return_path": _text(data.get("return_path")),
        "recipient": _text(data.get("recipient")), "auth_results": auth, "attachments": atts,
        "list_id": bool(data.get("list_id")),
        "own_domains": [x for x in (own if isinstance(own, list) else []) if isinstance(x, str)][:20],
    }


class PhishingDetector:
    def __init__(self, threshold: int = 2, use_whois: bool = True, use_model: bool = True, return_features: bool = False):
        self.threshold = threshold
        # use_model=False gives the pure rule score (used to build training data); return_features exposes the model inputs.
        self.model = scoring_model.get_model() if use_model else None
        self.return_features = return_features
        # Benchmarks turn WHOIS off so runs are offline, fast and repeatable.
        self.use_whois = use_whois

    # ── Parsing helpers ───────────────────────────────────────────────────
    def extract_domain(self, email: str) -> str:
        email = email.strip().lower()
        angle = re.search(r"<([^>]+)>", email)
        if angle:
            email = angle.group(1)
        match = re.search(r"@([\w.\-]+\.\w+)", email)
        return match.group(1) if match else email

    def parse_sender(self, sender: str):
        """Split '"Display Name" <local@domain>' into (display, local)."""
        s = sender.strip()
        display = ""
        m = re.match(r'^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$', s)
        if m:
            display, addr = m.group(1), m.group(2)
        else:
            addr = s
        return display.strip().lower(), addr.split("@")[0].strip().lower()

    def normalize_homoglyphs(self, domain: str) -> str:
        result = _fold_ascii(domain.lower())
        for fake, real in MULTI_CHAR_HOMOGLYPHS.items():
            result = result.replace(fake, real)
        for fake, real in HOMOGLYPH_MAP.items():
            result = result.replace(fake, real)
        return result

    # ── Brand logic ───────────────────────────────────────────────────────
    def brand_in_domain(self, registered: str):
        """
        Does the registrable domain *use* a protected brand name without owning it?
        Catches paypal-secure.com, my-paypal.net, paypal.xyz, paypalsecure.com and typo-squatted
        tokens (amazn-usshipping.com) but not applecross-dental.co.uk (brand is only part of a word)
        or orange-county-dental.com (ordinary word that happens to be a brand).
        """
        label = registered.split(".")[0]
        tokens = [t for t in re.split(r"[-_]", label) if t]
        lure = any(t in LURE_WORDS or t in DOMAIN_CRED_WORDS for t in tokens)
        for brand, legit in PROTECTED.items():
            if registered in legit:
                continue
            soft = brand in AMBIGUOUS_BRANDS
            if label == brand and "." in registered and registered.split(".", 1)[1] in SAME_NAME_RISKY_TLDS:
                return brand, "same name, different domain"
            for t in tokens:
                if t == brand and len(tokens) > 1 and (lure or not soft):
                    return brand, "brand name used as a word in the domain"
                if len(brand) >= 5:
                    if t.startswith(brand) and (t[len(brand):] in LURE_WORDS or t[len(brand):].isdigit()):
                        return brand, "brand name plus a lure word"
                    if t.endswith(brand) and t[:-len(brand)] in LURE_WORDS:
                        return brand, "lure word plus brand name"
        for t in tokens:                                    # typo-squatted / disguised brand token
            fb = _fuzzy_brand(t)
            if fb and registered not in PROTECTED[fb] and t != fb and (len(tokens) > 1 or len(t) >= 6):
                return fb, "misspelled or disguised brand name"
        return None

    def check_subdomain_abuse(self, domain: str):
        registered = registered_domain(domain)
        if registered == domain:
            return None
        prefix = domain[: -(len(registered) + 1)]
        tokens = [t for t in re.split(r"[.\-_]", prefix) if t]
        for brand, legit in PROTECTED.items():
            if registered in legit:
                continue
            for t in tokens:
                if t == brand or (len(brand) >= 5 and brand in t):
                    return {"impersonating": sorted(legit)[0], "actual_domain": registered, "prefix": prefix}
        # Other very popular names (whole words only, and never generic host words such as
        # "mail" or "login", which would match every mail.<host> subdomain).
        pool = get_levenshtein_pool()
        for td in pool[:200]:
            brand = td.split(".")[0]
            if len(brand) >= 5 and brand not in GENERIC_HOST_WORDS and brand in tokens and registered != td:
                return {"impersonating": td, "actual_domain": registered, "prefix": prefix}
        return None

    def brands_in_text(self, text: str):
        """Brands named in the text (whole words / phrases). One pass over the tokens, not one regex per brand."""
        t = text.lower()
        words = set(re.findall(r"[a-z0-9]+", t))
        single, multi = _mention_index()
        found = {brand for name, brand in single.items() if name in words}
        for name, brand in multi:
            if brand not in found and name in t:
                found.add(brand)
        return found

    def display_name_brand(self, display: str, local: str = ""):
        """
        Brand named in the display name. The display name must be the brand plus
        only generic words ("PayPal Support", "Amazon.com", "USAA 360"); a person
        called "Chase Williams" or "Apple Johnson" is not an impersonation.
        For free-mail senders the mailbox name is checked as well (brand + role word).
        """
        tokens = [t for t in re.split(r"[^a-z0-9]+", display) if t]
        compact = "".join(tokens)
        for brand in PROTECTED:
            for n in [brand] + BRAND_ALIASES.get(brand, []):
                ntoks = [t for t in re.split(r"[^a-z0-9]+", n) if t]
                if not ntoks:
                    continue
                if compact and compact == "".join(ntoks):
                    return brand
                target = "".join(ntoks)
                for i in range(len(tokens)):
                    for j in range(i + 1, min(i + 4, len(tokens)) + 1):
                        if "".join(tokens[i:j]) == target:
                            rest = tokens[:i] + tokens[j:]
                            if all(_is_generic(t) for t in rest):
                                return brand
        for i in range(len(tokens)):                        # disguised spellings: "PayPaI", "Linkedln", "Amazn"
            for j in range(i + 1, min(i + 3, len(tokens)) + 1):
                fb = _fuzzy_brand("".join(tokens[i:j]))
                if fb and all(_is_generic(t) for t in tokens[:i] + tokens[j:]):
                    return fb
        if local:
            l_tokens = set(re.split(r"[^a-z]+", local))
            if l_tokens & ROLE_WORDS:
                for brand in PROTECTED:
                    if len(brand) >= 5 and any(brand in t for t in l_tokens):
                        return brand
        return None

    # ── Domain analysis ───────────────────────────────────────────────────
    def analyze_domain(self, domain: str) -> dict:
        raw = domain.lower()
        registered = registered_domain(raw)
        decoded, had_puny, puny_ok = _decode_idn(raw)
        non_ascii = any(ord(c) > 127 for c in decoded)
        reg_decoded = registered_domain(_fold_ascii(decoded))
        normalized = self.normalize_homoglyphs(reg_decoded)
        freemail = registered in FREEMAIL

        # ── Trust check ────────────────────────────────────────────────────
        # Only the ORIGINAL (un-normalized) domain earns trust, and shared
        # mailbox providers never do: anyone can register a gmail.com address.
        trusted, rank = (False, None)
        if not freemail:
            trusted, rank = tranco_is_trusted(raw)
            if not trusted and registered != raw:
                trusted, rank = tranco_is_trusted(registered)   # mail.google.com -> google.com
        base = {
            "domain": domain, "registered": registered, "is_freemail": freemail,
            "punycode": had_puny, "non_ascii": non_ascii,
        }
        if trusted:
            return {**base, "is_trusted": True, "normalized": normalized, "tranco_rank": rank,
                    "homoglyph_detected": False, "best_match": None, "top_matches": [],
                    "matrix": None, "edit_operations": [], "brand_hit": None}
        if freemail:
            return {**base, "is_trusted": False, "normalized": normalized, "homoglyph_detected": False,
                    "best_match": None, "top_matches": [], "matrix": None, "edit_operations": [],
                    "brand_hit": None}

        # ── Levenshtein against Tranco top-1K + protected brand domains ───
        pool = get_levenshtein_pool()
        seen = set(pool)
        targets = pool + [d for d in sorted(PROTECTED_DOMAINS) if d not in seen]

        def nearest(form: str):
            out, rest, fm = [], [], _mask(form)
            for td in targets:
                if td == registered:
                    continue
                if abs(len(td) - len(form)) > 5 or (fm ^ _mask(td)).bit_count() > 10:
                    rest.append(td)
                    continue
                d = _lev_bounded(form, td, 5)
                if d <= 5:
                    out.append((d, td))
                else:
                    rest.append(td)
            if len(out) < 5:                      # nothing close: still show the nearest few (full distance) for the UI
                rest.sort(key=lambda td: abs(len(td) - len(form)))
                out += [(levenshtein_distance(form, td), td) for td in rest[:12]]
            out.sort()
            return out

        near_raw = nearest(reg_decoded)
        near_norm = nearest(normalized) if normalized != reg_decoded else near_raw
        d_raw = near_raw[0][0] if near_raw else 99
        d_norm = near_norm[0][0] if near_norm else 99
        homoglyph = normalized != reg_decoded and d_norm < d_raw and d_norm <= 1
        form, near = (normalized, near_norm) if homoglyph else (reg_decoded, near_raw)

        if not near:                                    # nothing comparable in length
            near = [(99, targets[0])] if targets else [(99, "example.com")]
        results = []
        for d, td in near[:25]:
            de = _osa(form, td) if d <= 4 else d
            results.append({"trusted_domain": td, "distance": d, "effective_distance": de,
                            "similarity": similarity_percent(form, td)})
        results.sort(key=lambda r: (r["effective_distance"], r["distance"]))
        results = results[:5]
        best = results[0]
        return {
            **base, "is_trusted": False, "normalized": form, "homoglyph_detected": homoglyph,
            "best_match": best, "top_matches": results,
            "matrix": get_dp_matrix(form, best["trusted_domain"]),
            "edit_operations": get_edit_operations(form, best["trusted_domain"]),
            "brand_hit": self.brand_in_domain(normalized) or self.brand_in_domain(reg_decoded),
        }

    # ── Content analysis ──────────────────────────────────────────────────
    def check_keywords(self, text: str) -> list:
        tl = text.lower()
        return [kw for kw in SUSPICIOUS_KEYWORDS if kw in tl]

    def check_scam_phrases(self, text: str):
        tl = " " + text.lower()
        strong = [p.strip() for p in SCAM_PHRASES if p in tl]
        weak = [p.strip() for p in WEAK_SCAM_PHRASES if p in tl]
        return strong, weak

    def check_spam(self, subject: str, content: str, trusted: bool = False) -> dict:
        text    = (subject + " " + content).lower()
        signals = []
        score   = 0

        # Keyword density. Verified brands send promotional wording as a matter of
        # course, so it is not reported for them.
        hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text]
        if hits and not trusted:
            pts = min(len(hits) * 10, 40)
            score += pts
            signals.append({
                "type": "SPAM_KEYWORDS", "severity": "HIGH" if len(hits) >= 3 else "MEDIUM",
                "message": f"{len(hits)} spam keyword(s) detected",
                "detail": ", ".join(f'"{k}"' for k in hits[:4]),
            })

        # ALL CAPS ratio in subject
        words      = subject.split()
        caps_words = [w for w in words if len(w) > 2 and w == w.upper() and any(c.isalpha() for c in w)]
        caps_ratio = len(caps_words) / max(len(words), 1)
        if caps_ratio >= 0.4:
            pts = min(round(caps_ratio * 25), 20)
            score += pts
            signals.append({
                "type": "EXCESSIVE_CAPS", "severity": "HIGH" if caps_ratio >= 0.6 else "MEDIUM",
                "message": f"{round(caps_ratio*100)}% of subject words are ALL CAPS",
                "detail": "Spammers use caps to create false urgency",
            })

        # Exclamation marks
        excl = subject.count("!")
        if excl >= 2:
            score += min(excl * 5, 20)
            signals.append({
                "type": "EXCESSIVE_EXCLAMATIONS", "severity": "HIGH" if excl >= 4 else "MEDIUM",
                "message": f"{excl} exclamation mark(s) in subject line",
                "detail": "Aggressive punctuation is a classic spam indicator",
            })

        # Bulk sender patterns (normal for verified brands)
        bulk_hits = [p for p in BULK_SENDER_PATTERNS if p in text]
        if bulk_hits and not trusted:
            score += 15
            signals.append({
                "type": "BULK_SENDER", "severity": "MEDIUM",
                "message": "Bulk/marketing email patterns detected",
                "detail": f'Contains: "{bulk_hits[0]}"',
            })

        # URL density
        url_count = len(re.findall(r'https?://', content, re.I))
        if url_count >= 3:
            score += min(url_count * 4, 15)
            signals.append({
                "type": "HIGH_URL_DENSITY", "severity": "MEDIUM",
                "message": f"{url_count} URLs found in email body",
                "detail": "High link density is a common spam indicator",
            })

        score = min(score, 100)
        return {
            "spam_score": score,
            "spam_level": "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW",
            "signals": signals,
        }

    def check_links(self, content: str) -> list:
        """Anchors whose visible text is a URL on a different registrable domain than the href."""
        mismatches = []
        for href, inner in [m.groups() for m in itertools.islice(ANCHOR_RE.finditer(content), 300)]:
            visible = TAG_RE.sub("", inner).strip()
            m = re.match(r"(?:https?://|www\.)[^\s]+", visible, re.I)
            if not m:
                continue
            v_host = urlparse(visible if "://" in visible else "http://" + visible).hostname or ""
            h_host = urlparse(href).hostname or ""
            if v_host and h_host and registered_domain(v_host) != registered_domain(h_host):
                mismatches.append({"visible": visible, "actual": href})
        return mismatches

    def _link_stats(self, urls: list, sender_registered: str, recipient: str) -> dict:
        """Era-neutral facts about where the links go: obscure destinations, plain http, long or personalised URLs."""
        if not urls:
            return {}
        regs, untrusted, http, maxlen, depth, email = set(), set(), 0, 0, 0, 0
        rcpt = recipient.strip().lower()
        for u in urls:
            p = urlparse(u)
            reg = registered_domain((p.hostname or "").lower())
            if reg and reg != sender_registered:
                regs.add(reg)
                if not tranco_is_trusted(reg)[0]:
                    untrusted.add(reg)
            http += p.scheme == "http"
            maxlen = max(maxlen, len(u))
            depth = max(depth, p.path.count("/"))
            low = u.lower()
            email |= int("@" in (p.query + p.fragment) or bool(rcpt and rcpt in low) or bool(re.search(r"[?&=/]\w+%40\w+", low)))
        return {"n_untrusted_dom": min(len(untrusted), 10), "untrusted_ratio": len(untrusted) / len(regs) if regs else 0.0,
                "http_ratio": http / len(urls), "url_maxlen": min(maxlen, 300) / 100.0, "url_depth": min(depth, 8), "url_email": email}

    def check_urls(self, content: str, sender_registered: str, brand_sender: bool = False) -> list:
        """Heuristics on destinations that are not the sender's own domain."""
        findings, seen = [], set()
        for url in URL_RE.findall(content)[:200]:
            host = (urlparse(url).hostname or "").lower()
            reg = registered_domain(host)
            if not host or reg == sender_registered or reg in seen:
                continue
            seen.add(reg)
            trusted, _ = tranco_is_trusted(reg)
            hit = self.brand_in_domain(self.normalize_homoglyphs(reg))
            if hit and not trusted:
                findings.append((40, f"Link points to '{reg}', which imitates {hit[0]}", "high"))
            elif trusted or reg in PROTECTED_DOMAINS:
                continue
            elif brand_sender:
                findings.append((25, f"Message claims to be from {sender_registered} but links to unrelated domain '{reg}'", "med"))
            elif reg in URL_SHORTENERS:
                findings.append((12, f"Link uses a URL shortener ({reg}) that hides the destination", "med"))
            elif re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
                findings.append((20, f"Link goes to a raw IP address ({host})", "high"))
            elif any(l.startswith("xn--") for l in host.split(".")):
                findings.append((20, f"Link uses an internationalised (punycode) domain ({host})", "med"))
            elif reg.rsplit(".", 1)[-1] in ABUSED_TLDS:
                findings.append((10, f"Link goes to a low-reputation TLD (.{reg.rsplit('.', 1)[-1]})", "med"))
        return findings

    # ── Main entry ────────────────────────────────────────────────────────
    def analyze(self, data: dict) -> dict:
        data = _sanitize_input(data)
        sender   = data["sender"]
        subject  = data["subject"]
        content  = data["content"]
        reply_to = data["reply_to"]

        domain   = self.extract_domain(sender)
        display, local = self.parse_sender(sender)
        warnings = []
        risk_level = 0

        da = self.analyze_domain(domain)
        registered = da["registered"]
        trusted    = da["is_trusted"]
        freemail   = da["is_freemail"]
        text       = f"{subject} {content}"
        # A genuine brand's own domain (never a shared mailbox provider that happens to be
        # listed under a brand, e.g. yahoo.com / aol.com), and whether the mailbox name looks
        # automated (noreply, billing, support ...) as opposed to a named employee.
        is_brand_domain = registered in PROTECTED_DOMAINS and not freemail
        role_local = bool(set(re.split(r"[^a-z]+", local)) & (ROLE_WORDS | {"mail", "services", "info", "donotreply"}))

        points_by_signal = {}

        def add(points, wtype, severity, message, detail=""):
            nonlocal risk_level
            risk_level += points
            points_by_signal[wtype] = points_by_signal.get(wtype, 0) + points
            warnings.append({"type": wtype, "severity": severity, "message": message, "detail": detail})

        # ── 1. Sender identity ────────────────────────────────────────────
        if trusted:
            warnings.append({
                "type": "TRUSTED_VERIFIED", "severity": "LOW",
                "message": f"'{domain}' is a verified trusted domain (Tranco rank #{da.get('tranco_rank', '?')})",
                "detail":  "Domain appears in the Tranco top-50 K popularity list. "
                           "This does not prove the message is genuine: sender addresses can be forged.",
            })
        elif freemail:
            warnings.append({
                "type": "FREEMAIL_SENDER", "severity": "LOW",
                "message": f"Sent from a free mailbox provider ({registered}); the sender's identity is not verified",
                "detail":  "Anyone can register an address here, so it is never treated as a trusted source.",
            })
        else:
            best = da["best_match"]
            name_len = len(da["normalized"].split(".")[0])
            de = best["effective_distance"] if best else 99
            longest = max(len(da["normalized"]), len(best["trusted_domain"])) if best else 1
            sim_e = 100 * (1 - de / longest)
            lookalike = bool(best) and ((de <= 1 and name_len >= 4) or (de == 2 and name_len >= 8 and sim_e >= 85))
            if lookalike:
                add(55, "LOOKALIKE_DOMAIN", "HIGH",
                    f"Lookalike domain — '{registered}' is only {de} edit(s) away from '{best['trusted_domain']}'",
                    f"Levenshtein distance: {best['distance']}  |  Similarity: {best['similarity']}%")
            elif best and de <= 3 and name_len >= 8 and sim_e >= 78:
                add(15, "SUSPICIOUS_DOMAIN", "MEDIUM",
                    f"Domain '{registered}' resembles '{best['trusted_domain']}'",
                    f"Distance: {best['distance']}  |  Similarity: {best['similarity']}%")

            hit = da["brand_hit"]
            if hit and not lookalike:
                add(50, "BRAND_IN_DOMAIN", "HIGH",
                    f"Domain '{registered}' uses the {hit[0]} name but is not a {hit[0]} domain",
                    hit[1])

            if da["homoglyph_detected"]:
                add(20, "HOMOGLYPH_ATTACK", "HIGH",
                    f"Look-alike characters in '{domain}' disguise the real name",
                    f"Normalized form: {da['normalized']}")
            elif da["non_ascii"] or (da["punycode"]):
                add(20, "PUNYCODE_DOMAIN", "MEDIUM",
                    f"'{domain}' uses non-ASCII / punycode characters",
                    "Internationalised domains are often used to imitate Latin-letter brands.")

            tld = registered.rsplit(".", 1)[-1]
            tokens = [t for t in re.split(r"[-_]", registered.split(".")[0]) if t]
            lure_count = sum(t in DOMAIN_CRED_WORDS for t in tokens)
            if tld in ABUSED_TLDS:
                add(10, "SUSPICIOUS_TLD", "MEDIUM", f"Domain uses a low-reputation TLD (.{tld})",
                    "These cheap TLDs are heavily used for disposable phishing sites.")
            if lure_count >= 2:
                add(15, "LURE_WORDS_IN_DOMAIN", "MEDIUM",
                    f"Domain name is built from account/security words ('{registered}')",
                    "Phishing hosts commonly use names like secure-login-verify.")
            elif lure_count == 1:
                add(6, "LURE_WORDS_IN_DOMAIN", "LOW",
                    f"Domain name contains an account/security word ('{registered}')")

            sub = self.check_subdomain_abuse(domain)
            if sub:
                add(60, "SUBDOMAIN_ABUSE", "HIGH",
                    f"Subdomain abuse — real domain is '{sub['actual_domain']}', not '{sub['impersonating']}'",
                    f"Attacker prefix: {sub['prefix']}")


        # Display name / mailbox name claims a brand that does not own this domain.
        # Applies to every sender: a 'trusted' ISP domain with display name "Amazon.com"
        # is still not Amazon.
        dn_brand = self.display_name_brand(display, local if freemail else "")
        brand_hit = da.get("brand_hit")
        if dn_brand and registered not in PROTECTED[dn_brand] and not (brand_hit and brand_hit[0] == dn_brand):
            add(40, "BRAND_IMPERSONATION", "HIGH",
                f"Sender presents itself as {dn_brand}, but the address belongs to '{registered}'",
                f"Display name / mailbox name: '{display or local}'")

        # ── 2. Brand named in the message that doesn't match the sender ───
        if not trusted:
            mentioned = [b for b in self.brands_in_text(text) if registered not in PROTECTED[b]]
            if mentioned and INTENT_RE.search(text) and URL_RE.search(content):
                add(30, "BRAND_MISMATCH", "HIGH",
                    f"Message asks you to act on your {mentioned[0]} account, but the sender is '{registered}'",
                    "Account-action wording combined with a brand that does not own the sender domain.")

        # ── 3. Keywords ───────────────────────────────────────────────────
        keywords = self.check_keywords(text.translate(CONFUSABLE_TABLE))
        if trusted:
            kw = [k for k in keywords if k in TRUSTED_SENDER_KEYWORDS]
            if kw:
                add(min(len(kw) * 3, 12), "SUSPICIOUS_KEYWORDS", "MEDIUM",
                    f"{len(kw)} sensitive phrase(s) from a verified sender",
                    ", ".join(f'"{k}"' for k in kw[:6]))
        elif keywords:
            core = [k for k in keywords if k in CORE_KEYWORDS]
            pts = min(len(core) * 6, 25) + min((len(keywords) - len(core)) * 2, 8)
            add(min(pts, 28), "SUSPICIOUS_KEYWORDS", "HIGH" if len(core) >= 3 else "MEDIUM",
                f"{len(keywords)} suspicious keyword(s) found in email body",
                ", ".join(f'"{k}"' for k in keywords[:6]))

        lure_text = f"{subject} {_visible_text(content)}".translate(CONFUSABLE_TABLE)
        has_link = bool(URL_RE.search(content))
        obf = CONFUSABLE_WORD_RE.findall(f"{subject} {_visible_text(content, 1200)}")
        if obf and not data.get("list_id"):
            add(15, "OBFUSCATED_TEXT", "MEDIUM", "Words disguised with look-alike letters from other alphabets",
                ", ".join(sorted(set(obf))[:3]))
        if not trusted and not data.get("list_id") and (has_link or ACTION_RE.search(lure_text)) and PAYMENT_LURE_RE.search(lure_text):
            add(15, "PAYMENT_LURE", "MEDIUM", "Message warns about a payment / membership problem and asks you to act")
        if not trusted and not data.get("list_id"):
            if DEAR_RE.search(lure_text):
                add(6, "GENERIC_GREETING", "LOW", "Impersonal greeting ('Dear user / customer') typical of mass phishing")
            if has_link:
                low = lure_text.lower()
                hits = {ph for lang in INTL_PHRASES.values() for ph in lang if ph in low}
                if len(hits) >= 2:
                    add(15, "FOREIGN_LURE", "MEDIUM", "Account / credential wording in another language together with a link",
                        ", ".join(sorted(hits)[:4]))
        if display and ADMIN_DISPLAY_RE.search(display) and not is_brand_domain and not data.get("list_id"):
            if (ACTION_RE.search(lure_text) or THREAT_RE.search(lure_text) or DOCSHARE_RE.search(lure_text)) and (CLICK_RE.search(lure_text) or has_link):
                add(25, "ADMIN_IMPERSONATION", "MEDIUM",
                    "Sender poses as an IT / mail administrator and asks you to act on your account",
                    f"Display name: '{display}'")

        if not trusted and not data.get("list_id") and has_link and (DOCSHARE_RE.search(lure_text) or NEWFILE_RE.search(lure_text)):
            add(20, "DOCUMENT_LURE", "MEDIUM", "Message announces a shared document / pending mail and pushes you to open a link",
                "A common way to lead to a fake login page.")

        # The recipient's own organisation named by an outsider ("monkey.org Mail Center" from another domain)
        owners = set()
        for addr in [data.get("recipient")] + list(data.get("own_domains") or []):
            if addr:
                d = registered_domain(self.extract_domain(str(addr)) if "@" in str(addr) else str(addr).lower())
                if d and d not in FREEMAIL:
                    owners.add(d)
        if owners and registered not in owners and not data.get("list_id"):
            for od in owners:
                label = od.split(".")[0]
                in_display = od in display or (len(label) >= 4 and re.search(r"\b" + re.escape(label) + r"\b", display))
                in_subject = od in subject.lower() or (len(label) >= 4 and re.search(r"\b" + re.escape(label) + r"\b", subject.lower()))
                addr_in_subject = bool(data["recipient"]) and data["recipient"].strip().lower() in subject.lower()
                if in_display:
                    add(35, "ORG_IMPERSONATION", "HIGH",
                        f"Display name uses your organisation's name ('{od}') but the sender is '{registered}'",
                        f"Display name: '{display}'")
                    break
                if in_subject and (ACTION_RE.search(lure_text) or THREAT_RE.search(lure_text)):
                    add(20 if addr_in_subject else 8, "ORG_IMPERSONATION", "MEDIUM",
                        f"Subject refers to your organisation ('{od}') with an account warning, from '{registered}'")
                    break

        # Mail "from you" or from your own domain that pressures you to act: forged internal sender
        rcpt = data["recipient"].strip().lower()
        m_addr = re.search(r"<([^>]+)>", sender)
        s_addr = (m_addr.group(1) if m_addr else sender).strip().lower()
        pressure = bool(ACTION_RE.search(lure_text) or THREAT_RE.search(lure_text) or DOCSHARE_RE.search(lure_text)
                        or PAYMENT_LURE_RE.search(lure_text))
        if pressure and not data.get("list_id"):
            if rcpt and s_addr == rcpt:
                add(30, "SPOOFED_SELF", "HIGH", "The message claims to be from your own address but pressures you to act on an account",
                    "Spammers forge the recipient's own address as the sender.")
            elif owners and registered in owners and not is_brand_domain:
                add(15, "INTERNAL_LURE", "MEDIUM", f"Message from your own domain ('{registered}') pressures you to verify or update an account",
                    "Check with the sender: internal IT rarely asks for credentials by email.")

        if not trusted:
            cats = sum(bool(r.search(lure_text)) for r in (THREAT_RE, ACTION_RE, URGENCY_RE))
            if cats >= 2:
                add(35 if cats == 3 else 25, "ACCOUNT_ACTION_LURE", "HIGH" if cats == 3 else "MEDIUM",
                    "Message pressures you to verify / update an account or mailbox",
                    "Combines a threat (expiry, suspension, limit exceeded) with a request to act" +
                    (" and a deadline" if cats == 3 else ""))

        if not trusted:
            strong, weak = self.check_scam_phrases(text)
            if strong or len(weak) >= 2:
                pts = min(len(strong) * 25 + len(weak) * 10, 50) + (10 if freemail else 0)
                add(pts, "BEC_SCAM_PATTERN", "HIGH",
                    "Wording typical of payment-redirection or advance-fee fraud",
                    ", ".join(f'"{p}"' for p in (strong + weak)[:4]))

        # ── 4. Links ──────────────────────────────────────────────────────
        mismatches = self.check_links(content)
        if mismatches:
            m = mismatches[0]
            add(20, "LINK_MISMATCH", "HIGH",
                "Deceptive hyperlink — visible URL differs from actual destination",
                f"Shown: {m['visible']}  →  Actual: {m['actual']}")
        link_pts = 0
        for pts, msg, sev in self.check_urls(content, registered, is_brand_domain and role_local):
            take = min(pts, 45 - link_pts)
            if take > 0:
                link_pts += take
                add(take, "SUSPICIOUS_LINK", "HIGH" if sev == "high" else "MEDIUM", msg)

        # Mail that claims to be a brand but links only to other domains, or to a free-hosting platform
        link_regs = {registered_domain(urlparse(u).hostname or "") for u in URL_RE.findall(content)[:500]}
        link_regs.discard("")
        claimed = dn_brand or (is_brand_domain and role_local and next((b for b, d in PROTECTED.items() if registered in d), None))
        if claimed and link_regs and not (link_regs & (PROTECTED[claimed] | {registered})):
            add(30 if (is_brand_domain and role_local) else 20, "BRAND_LINKS_ELSEWHERE", "MEDIUM",
                f"Claims to be {claimed} but none of its links go to a {claimed} domain",
                ", ".join(sorted(link_regs)[:4]))
        hosted = sorted(link_regs & HOSTING_PLATFORMS)
        if hosted and not trusted and (claimed or ACTION_RE.search(lure_text) or THREAT_RE.search(lure_text) or DOCSHARE_RE.search(lure_text)):
            add(15, "LINK_ON_HOSTING_PLATFORM", "MEDIUM",
                f"Link points to a free-hosting platform ({hosted[0]}) often used for fake login pages")

        # ── 5. Reply-To mismatch (mailing lists set Reply-To on purpose) ──
        if reply_to and not data.get("list_id"):
            rt_reg = registered_domain(self.extract_domain(reply_to))
            if rt_reg and rt_reg != registered:
                rt_trusted = (rt_reg not in FREEMAIL) and tranco_is_trusted(rt_reg)[0]
                if is_brand_domain and not rt_trusted:
                    add(30, "REPLY_TO_MISMATCH", "HIGH",
                        f"Verified-brand sender, but replies go to unrelated domain '{rt_reg}'",
                        "A genuine brand rarely redirects replies to an unknown domain.")
                else:
                    add(10, "REPLY_TO_MISMATCH", "MEDIUM",
                        f"Reply-To domain '{rt_reg}' differs from sender domain '{registered}'",
                        "Replies go to a different, possibly attacker-controlled domain")

        # Envelope sender (Return-Path) of a brand's mail must belong to the brand or to a
        # well-known mail provider; a brand From with a random bounce domain is a forgery.
        ret = data.get("return_path") or ""
        if ret and is_brand_domain and role_local:
            ret_reg = registered_domain(self.extract_domain(ret))
            if ret_reg and ret_reg != registered and ret_reg not in PROTECTED_DOMAINS and not tranco_is_trusted(ret_reg)[0]:
                add(25, "RETURN_PATH_MISMATCH", "HIGH",
                    f"Claims to be {registered} but the envelope sender is '{ret_reg}'",
                    "Genuine brand mail is sent through the brand's own or a well-known provider's servers.")

        # ── 6. Email authentication results (header data from the receiving server) ──
        auth = data.get("auth_results") or ""
        if isinstance(auth, dict):
            auth = " ".join(f"{k}={v}" for k, v in auth.items())
        results = {k.lower(): v.lower() for k, v in AUTH_RE.findall(str(auth))}
        pts, bad = 0, []
        if results.get("dmarc") in ("fail", "permerror"):
            pts += 35; bad.append("DMARC")
        if results.get("spf") in ("fail", "permerror"):
            pts += 20; bad.append("SPF")
        elif results.get("spf") == "softfail":
            pts += 8; bad.append("SPF (soft)")
        if results.get("dkim") in ("fail", "permerror"):
            pts += 10; bad.append("DKIM")
        if pts:
            add(min(pts, 45), "AUTH_FAILURE", "HIGH" if pts >= 30 else "MEDIUM",
                f"Email authentication failed ({', '.join(bad)})",
                "The sending server was not authorised to send for this domain.")

        if owners and registered in owners and pts:
            add(30, "INTERNAL_SPOOF", "HIGH", f"Appears to come from your own domain ('{registered}') but failed authentication",
                "Outsiders forge your own domain to look like internal IT or management.")

        # ── 6b. Attachments ───────────────────────────────────────────────
        att_pts = 0
        for att in data.get("attachments") or []:
            name = (att.get("filename") if isinstance(att, dict) else str(att)).lower()
            parts = name.rsplit(".", 2)
            ext = parts[-1] if "." in name else ""
            inner = parts[-2] if len(parts) == 3 else ""
            if ext in EXEC_ATTACH and inner in ("pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"):
                add(35, "RISKY_ATTACHMENT", "HIGH", f"Disguised executable attachment '{name}'", "Double extension hides the real file type.")
                att_pts += 35
            elif ext in EXEC_ATTACH:
                add(30, "RISKY_ATTACHMENT", "HIGH", f"Executable or script attachment '{name}'")
                att_pts += 30
            elif ext in HTML_ATTACH:
                add(25, "RISKY_ATTACHMENT", "HIGH", f"HTML attachment '{name}'",
                    "HTML files attached to mail are a common way to show a fake login page.")
                att_pts += 25
            elif ext in ARCHIVE_ATTACH and not trusted:
                add(8, "RISKY_ATTACHMENT", "MEDIUM", f"Archive attachment '{name}' from an unverified sender")
                att_pts += 8
            if att_pts >= 40:
                break

        # ── 6c. Credential-harvesting form embedded in the message ────────
        if PASSWORD_INPUT_RE.search(content) or SENSITIVE_FIELD_RE.search(content):
            action = FORM_RE.search(content)
            host = registered_domain(urlparse(action.group(1)).hostname or "") if action else ""
            if not host or host != registered:
                add(35, "CREDENTIAL_FORM", "HIGH", "Message contains a password / card field",
                    "Legitimate services never ask you to type a password inside an email.")

        # ── 7. Domain age check (WHOIS) — untrusted, non-freemail only ────
        age_info = {}
        if self.use_whois and not trusted and not freemail:
            age_info = check_domain_age(domain)
            if age_info.get("age_days") is not None:
                if age_info["age_days"] < 30:
                    add(25, "VERY_NEW_DOMAIN", "HIGH",
                        f"Domain '{domain}' is only {age_info['age_days']} day(s) old",
                        f"Registrar: {age_info.get('registrar','unknown')}. Phishing domains are typically registered days before an attack.")
                elif age_info["age_days"] < 90:
                    add(12, "NEW_DOMAIN", "MEDIUM",
                        f"Domain '{domain}' was registered {age_info['age_days']} days ago",
                        "Recently registered domains are frequently used in phishing campaigns.")

        risk_level = min(risk_level, 100)

        spam = self.check_spam(subject, content, trusted=trusted)
        spam_weight = 0.15 if trusted else 0.4
        spam_part = round(spam["spam_score"] * spam_weight)
        if risk_level < 15:       # spam-looking alone is not phishing: require one phishing-specific indicator
            spam_part = min(spam_part, max(0, 24 - risk_level))
        combined_score = min(risk_level + spam_part, 100)
        combined_risk  = "HIGH" if combined_score >= 55 else "MEDIUM" if combined_score >= 25 else "LOW"

        # ── Learned combination of the signals (rules still supply every explanation) ──
        rule_score, model_info = combined_score, None
        m_addr = re.search(r"<([^>]+)>", sender)
        local_part = (m_addr.group(1) if m_addr else sender).strip().lower().split("@")[0]
        urls = URL_RE.findall(content)[:200]
        features = scoring_model.featurize(points_by_signal, spam["spam_score"], trusted, freemail, local_part,
                                           registered, subject, len(urls), len(link_regs), self._link_stats(urls, registered, data["recipient"]))
        if self.model is not None:
            try:
                raw = self.model.raw(features)
                floor = self.model.unsupported_points(points_by_signal)
                combined_score = max(self.model.risk(raw), min(100, floor))
                combined_risk = "HIGH" if combined_score >= 55 else "MEDIUM" if combined_score >= 25 else "LOW"
                model_info = {"version": self.model.version, "raw": round(raw, 3), "rule_floor": min(100, floor)}
            except Exception:                                    # a broken model must never break analysis
                combined_score, model_info = rule_score, None
                combined_risk = "HIGH" if combined_score >= 55 else "MEDIUM" if combined_score >= 25 else "LOW"

        return {
            "sender":          sender,
            "domain":          domain,
            "risk_score":      combined_risk,
            "risk_level":      combined_score,
            "rule_score":      rule_score,
            "model":           model_info,
            "phishing_score":  risk_level,
            "signal_points":   points_by_signal,
            "spam":            spam,
            "warnings":        warnings + spam["signals"],
            "domain_analysis": da,
            "domain_age":      age_info,
            "keywords_found":  keywords,
            "link_mismatches": mismatches,
            **({"model_features": features} if self.return_features else {}),
        }

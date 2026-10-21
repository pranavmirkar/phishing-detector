import re
import unicodedata
from urllib.parse import urlparse

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
    r"\b(admin(istrator)?|webmail|(e-?)?mail (service|system|team|admin\w*)|help ?desk|it support|it'?s? help|"
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
    "microsoft": ["microsoft", "outlook", "office 365"], "royalmail": ["royal mail"],
    "incometax": ["income tax department"], "kotak": ["kotak mahindra", "kotak"],
}
MENTION_EXCLUDE = {"discover", "ups", "visa"}   # common words: too noisy to count as a brand mention

STYLE_RE = re.compile(r"<(style|script)\b.*?</\1>", re.I | re.S)


def _visible_text(content: str, limit: int = 1500) -> str:
    """Tag/CSS-stripped start of the message: where lures state their demand."""
    t = TAG_RE.sub(" ", STYLE_RE.sub(" ", content))
    return re.sub(r"\s+", " ", t).strip()[:limit]


URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
ANCHOR_RE = re.compile(r"<a\b[^>]*?href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)
TAG_RE = re.compile(r"<[^>]+>")
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


class PhishingDetector:
    def __init__(self, threshold: int = 2, use_whois: bool = True):
        self.threshold = threshold
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
        Catches paypal-secure.com, my-paypal.net, paypal.xyz, paypalsecure.com but
        not applecross-dental.co.uk (brand is only a substring of another word).
        """
        label = registered.split(".")[0]
        tokens = [t for t in re.split(r"[-_]", label) if t]
        for brand, legit in PROTECTED.items():
            if registered in legit:
                continue
            if label == brand and registered.split(".", 1)[1] in SAME_NAME_RISKY_TLDS:
                return brand, "same name, different domain"
            for t in tokens:
                if t == brand and len(tokens) > 1:
                    return brand, "brand name used as a word in the domain"
                if len(brand) >= 5:
                    if t.startswith(brand) and (t[len(brand):] in LURE_WORDS or t[len(brand):].isdigit()):
                        return brand, "brand name plus a lure word"
                    if t.endswith(brand) and t[:-len(brand)] in LURE_WORDS:
                        return brand, "lure word plus brand name"
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
        t = text.lower()
        found = set()
        for brand in PROTECTED:
            if brand in MENTION_EXCLUDE:
                continue
            names = [brand] + BRAND_ALIASES.get(brand, [])
            if any(re.search(r"\b" + re.escape(n) + r"\b", t) for n in names):
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
                            if all(t in GENERIC_DISPLAY or t.isdigit() for t in rest):
                                return brand
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
            out = []
            for td in targets:
                if td == registered or abs(len(td) - len(form)) > 5:
                    continue
                out.append((levenshtein_distance(form, td), td))
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
        for href, inner in ANCHOR_RE.findall(content):
            visible = TAG_RE.sub("", inner).strip()
            m = re.match(r"(?:https?://|www\.)[^\s]+", visible, re.I)
            if not m:
                continue
            v_host = urlparse(visible if "://" in visible else "http://" + visible).hostname or ""
            h_host = urlparse(href).hostname or ""
            if v_host and h_host and registered_domain(v_host) != registered_domain(h_host):
                mismatches.append({"visible": visible, "actual": href})
        return mismatches

    def check_urls(self, content: str, sender_registered: str, brand_sender: bool = False) -> list:
        """Heuristics on destinations that are not the sender's own domain."""
        findings, seen = [], set()
        for url in URL_RE.findall(content):
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
        sender   = data.get("sender",   "")
        subject  = data.get("subject",  "")
        content  = data.get("content",  "")
        reply_to = data.get("reply_to", "")

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

        def add(points, wtype, severity, message, detail=""):
            nonlocal risk_level
            risk_level += points
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
            lure_count = sum(t in LURE_WORDS for t in tokens)
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
            if mentioned and INTENT_RE.search(text):
                add(30, "BRAND_MISMATCH", "HIGH",
                    f"Message asks you to act on your {mentioned[0]} account, but the sender is '{registered}'",
                    "Account-action wording combined with a brand that does not own the sender domain.")

        # ── 3. Keywords ───────────────────────────────────────────────────
        keywords = self.check_keywords(text)
        if trusted:
            kw = [k for k in keywords if k in TRUSTED_SENDER_KEYWORDS]
            if kw:
                add(min(len(kw) * 3, 12), "SUSPICIOUS_KEYWORDS", "MEDIUM",
                    f"{len(kw)} sensitive phrase(s) from a verified sender",
                    ", ".join(f'"{k}"' for k in kw[:6]))
        elif keywords:
            add(min(len(keywords) * 6, 25), "SUSPICIOUS_KEYWORDS",
                "HIGH" if len(keywords) >= 3 else "MEDIUM",
                f"{len(keywords)} suspicious keyword(s) found in email body",
                ", ".join(f'"{k}"' for k in keywords[:6]))

        lure_text = f"{subject} {_visible_text(content)}"
        if display and ADMIN_DISPLAY_RE.search(display) and not is_brand_domain:
            if ACTION_RE.search(lure_text) and CLICK_RE.search(lure_text):
                add(25, "ADMIN_IMPERSONATION", "MEDIUM",
                    "Sender poses as an IT / mail administrator and asks you to act on your account",
                    f"Display name: '{display}'")

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

        # ── 5. Reply-To mismatch ──────────────────────────────────────────
        if reply_to:
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

        # ── 6. Email authentication results (optional header data) ────────
        auth = data.get("auth_results") or ""
        if isinstance(auth, dict):
            auth = " ".join(f"{k}={v}" for k, v in auth.items())
        results = {k.lower(): v.lower() for k, v in AUTH_RE.findall(str(auth))}
        failed = [k for k, v in results.items() if v in ("fail", "permerror")]
        soft = [k for k, v in results.items() if v == "softfail"]
        if failed:
            add(40, "AUTH_FAILURE", "HIGH",
                f"Email authentication failed ({', '.join(k.upper() for k in failed)})",
                "The sending server was not authorised to send for this domain.")
        elif soft:
            add(15, "AUTH_FAILURE", "MEDIUM",
                f"Email authentication soft-failed ({', '.join(k.upper() for k in soft)})")

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
        combined_score = min(risk_level + round(spam["spam_score"] * spam_weight), 100)
        combined_risk  = "HIGH" if combined_score >= 55 else "MEDIUM" if combined_score >= 25 else "LOW"

        return {
            "sender":          sender,
            "domain":          domain,
            "risk_score":      combined_risk,
            "risk_level":      combined_score,
            "phishing_score":  risk_level,
            "spam":            spam,
            "warnings":        warnings + spam["signals"],
            "domain_analysis": da,
            "domain_age":      age_info,
            "keywords_found":  keywords,
            "link_mismatches": mismatches,
        }

import re
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

# Unicode and visual homoglyphs that bypass naive string comparison
HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ѕ": "s",
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
    "lottery", "sweepstakes", "jackpot",
    # Clickbait
    "click here", "click now", "open now", "see inside",
    # Marketing spam
    "risk-free", "guaranteed", "100% free", "no obligation",
    "satisfaction guaranteed", "money back", "no cost",
    # Health spam
    "lose weight", "miracle cure", "no prescription",
]

BULK_SENDER_PATTERNS = [
    "unsubscribe", "opt-out", "opt out",
    "you are receiving this email because",
    "this email was sent to", "manage preferences",
    "view this email in your browser", "add us to your address book",
]


class PhishingDetector:
    def __init__(self, threshold: int = 2):
        self.threshold = threshold

    def extract_domain(self, email: str) -> str:
        email = email.strip().lower()
        angle = re.search(r"<([^>]+)>", email)
        if angle:
            email = angle.group(1)
        match = re.search(r"@([\w.\-]+\.\w+)", email)
        return match.group(1) if match else email

    def normalize_homoglyphs(self, domain: str) -> str:
        result = domain.lower()
        for fake, real in MULTI_CHAR_HOMOGLYPHS.items():
            result = result.replace(fake, real)
        for fake, real in HOMOGLYPH_MAP.items():
            result = result.replace(fake, real)
        return result

    def check_subdomain_abuse(self, domain: str):
        parts = domain.split(".")
        if len(parts) > 2:
            registered = ".".join(parts[-2:])
            prefix = ".".join(parts[:-2])
            # Check brand names from the Levenshtein pool
            pool = get_levenshtein_pool()
            for td in pool[:200]:            # top-200 covers all major brands
                brand = td.split(".")[0]
                if len(brand) >= 4 and brand in prefix and registered != td:
                    return {
                        "impersonating": td,
                        "actual_domain": registered,
                        "prefix": prefix,
                    }
        return None

    def analyze_domain(self, domain: str) -> dict:
        normalized = self.normalize_homoglyphs(domain)

        # ── Trust check ────────────────────────────────────────────────────
        # Only the ORIGINAL (un-normalized) domain earns trust.
        # If normalization reveals a known domain, that IS the attack.
        trusted, rank = tranco_is_trusted(domain)
        if trusted:
            return {
                "is_trusted":  True,
                "domain":      domain,
                "normalized":  normalized,
                "tranco_rank": rank,
                "best_match":  None,
                "top_matches": [],
                "matrix":      None,
                "edit_operations": [],
            }

        # ── Levenshtein against Tranco top-1 K ────────────────────────────
        pool = get_levenshtein_pool()          # 1 K domains from SQLite
        results = []
        for td in pool:
            dist = levenshtein_distance(normalized, td)
            sim  = similarity_percent(normalized, td)
            results.append({"trusted_domain": td, "distance": dist, "similarity": sim})

        results.sort(key=lambda x: x["distance"])
        best       = results[0]
        matrix_data = get_dp_matrix(normalized, best["trusted_domain"])
        edit_ops    = get_edit_operations(normalized, best["trusted_domain"])

        return {
            "is_trusted":        False,
            "domain":            domain,
            "normalized":        normalized,
            "homoglyph_detected": normalized != domain,
            "best_match":        best,
            "top_matches":       results[:5],
            "matrix":            matrix_data,
            "edit_operations":   edit_ops,
        }

    def check_keywords(self, text: str) -> list:
        tl = text.lower()
        return [kw for kw in SUSPICIOUS_KEYWORDS if kw in tl]

    def check_spam(self, subject: str, content: str) -> dict:
        text    = (subject + " " + content).lower()
        signals = []
        score   = 0

        # Keyword density
        hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text]
        if hits:
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

        # Bulk sender patterns
        bulk_hits = [p for p in BULK_SENDER_PATTERNS if p in text]
        if bulk_hits:
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
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', content, re.I)
        texts = re.findall(r"<a[^>]*>([^<]+)</a>", content, re.I)
        mismatches = []
        for i, href in enumerate(hrefs):
            if i < len(texts):
                visible = texts[i].strip()
                if re.match(r"https?://", visible, re.I) and visible.lower() != href.lower():
                    mismatches.append({"visible": visible, "actual": href})
        return mismatches

    def analyze(self, data: dict) -> dict:
        sender   = data.get("sender",   "")
        subject  = data.get("subject",  "")
        content  = data.get("content",  "")
        reply_to = data.get("reply_to", "")

        domain   = self.extract_domain(sender)
        warnings = []
        risk_level = 0

        # ── 1. Levenshtein domain analysis (now uses Tranco pool) ─────────
        da = self.analyze_domain(domain)

        if da["is_trusted"]:
            # Domain is in Tranco top-50 K → confirmed popular/trusted
            warnings.append({
                "type": "TRUSTED_VERIFIED", "severity": "LOW",
                "message": f"'{domain}' is a verified trusted domain (Tranco rank #{da.get('tranco_rank', '?')})",
                "detail":  "Domain appears in the Tranco top-50 K popularity list",
            })
        elif da["best_match"]["distance"] == 0 and not da.get("homoglyph_detected"):
            # Exact match in pool without any homoglyph substitution → real domain (fallback safe)
            pass
        elif da["best_match"]["distance"] <= self.threshold:
            risk_level += 55
            warnings.append({
                "type": "LOOKALIKE_DOMAIN", "severity": "HIGH",
                "message": f"Lookalike domain — '{domain}' is only {da['best_match']['distance']} edit(s) away from '{da['best_match']['trusted_domain']}'",
                "detail":  f"Levenshtein distance: {da['best_match']['distance']}  |  Similarity: {da['best_match']['similarity']}%",
            })
        elif da["best_match"]["distance"] <= 4:
            risk_level += 25
            warnings.append({
                "type": "SUSPICIOUS_DOMAIN", "severity": "MEDIUM",
                "message": f"Domain '{domain}' closely resembles '{da['best_match']['trusted_domain']}'",
                "detail":  f"Distance: {da['best_match']['distance']}  |  Similarity: {da['best_match']['similarity']}%",
            })

        # ── 2. Homoglyph attack ───────────────────────────────────────────
        if da.get("homoglyph_detected"):
            risk_level += 20
            warnings.append({
                "type": "HOMOGLYPH_ATTACK", "severity": "HIGH",
                "message": f"Unicode homoglyph characters detected in '{domain}'",
                "detail":  f"Normalized form: {da['normalized']}",
            })

        # ── 3. Subdomain abuse ────────────────────────────────────────────
        sub = self.check_subdomain_abuse(domain)
        if sub:
            risk_level += 60
            warnings.append({
                "type": "SUBDOMAIN_ABUSE", "severity": "HIGH",
                "message": f"Subdomain abuse — real domain is '{sub['actual_domain']}', not '{sub['impersonating']}'",
                "detail":  f"Attacker prefix: {sub['prefix']}",
            })

        # ── 4. Suspicious keywords ────────────────────────────────────────
        keywords = self.check_keywords(f"{subject} {content}")
        if keywords:
            risk_level += min(len(keywords) * 6, 25)
            warnings.append({
                "type": "SUSPICIOUS_KEYWORDS",
                "severity": "HIGH" if len(keywords) >= 3 else "MEDIUM",
                "message": f"{len(keywords)} suspicious keyword(s) found in email body",
                "detail":  ", ".join(f'"{k}"' for k in keywords[:6]),
            })

        # ── 5. Link mismatch ──────────────────────────────────────────────
        mismatches = self.check_links(content)
        if mismatches:
            risk_level += 20
            m = mismatches[0]
            warnings.append({
                "type": "LINK_MISMATCH", "severity": "HIGH",
                "message": "Deceptive hyperlink — visible URL differs from actual destination",
                "detail":  f"Shown: {m['visible']}  →  Actual: {m['actual']}",
            })

        # ── 6. Reply-To mismatch ──────────────────────────────────────────
        if reply_to:
            rt_domain = self.extract_domain(reply_to)
            if rt_domain and rt_domain != domain:
                risk_level += 15
                warnings.append({
                    "type": "REPLY_TO_MISMATCH", "severity": "MEDIUM",
                    "message": f"Reply-To domain '{rt_domain}' differs from sender domain '{domain}'",
                    "detail":  "Replies go to a different, possibly attacker-controlled domain",
                })

        # ── 7. Domain age check (WHOIS) — always for untrusted domains ─────
        age_info = {}
        if not da["is_trusted"]:
            age_info = check_domain_age(domain)
            if age_info.get("age_days") is not None:
                if age_info["age_days"] < 30:
                    risk_level += 25
                    warnings.append({
                        "type": "VERY_NEW_DOMAIN", "severity": "HIGH",
                        "message": f"Domain '{domain}' is only {age_info['age_days']} day(s) old",
                        "detail":  f"Registrar: {age_info.get('registrar','unknown')}. Phishing domains are typically registered days before an attack.",
                    })
                elif age_info["age_days"] < 90:
                    risk_level += 12
                    warnings.append({
                        "type": "NEW_DOMAIN", "severity": "MEDIUM",
                        "message": f"Domain '{domain}' was registered {age_info['age_days']} days ago",
                        "detail":  "Recently registered domains are frequently used in phishing campaigns.",
                    })

        risk_level = min(risk_level, 100)
        risk_score = "HIGH" if risk_level >= 55 else "MEDIUM" if risk_level >= 25 else "LOW"

        spam = self.check_spam(subject, content)
        combined_score = min(risk_level + round(spam["spam_score"] * 0.4), 100)
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

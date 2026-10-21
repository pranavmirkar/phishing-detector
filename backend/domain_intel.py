"""
Domain Intelligence Layer
─────────────────────────
Replaces the hardcoded 32-domain list with two free, no-key-required sources:

  1. Tranco Top-1M  (tranco-list.eu)  — weekly research-grade popularity list.
     We store the top 50 K in SQLite and use top 1 K for Levenshtein matching.

  2. python-whois                     — domain age from public WHOIS records.
     Results are cached in SQLite for 24 h to stay fast on repeat lookups.
"""

import io
import os
import sqlite3
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FTimeout
from datetime import datetime, timedelta, timezone

import requests

# ── Config ────────────────────────────────────────────────────────────────────
TRANCO_URL  = "https://tranco-list.eu/top-1m.csv.zip"
STORE_TOP_N = 50_000   # rows kept in SQLite (exact-match trust checks)
MATCH_TOP_N = 1_000    # rows used for Levenshtein (major brands only)
WHOIS_TTL_H = 24       # hours before re-querying WHOIS
WHOIS_TIMEOUT_S = 6    # max seconds per WHOIS call
# Absolute by default, so the server works from any working directory. Override with PG_DB.
DB_PATH     = os.environ.get("PG_DB") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishing.db")

# ── DB helpers ────────────────────────────────────────────────────────────────

def _db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_intel_tables():
    conn = _db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS trusted_domains (
            domain     TEXT PRIMARY KEY,
            rank       INTEGER,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS whois_cache (
            domain     TEXT PRIMARY KEY,
            age_days   INTEGER,
            registrar  TEXT,
            country    TEXT,
            is_new     INTEGER,
            cached_at  TEXT
        );
        CREATE TABLE IF NOT EXISTS intel_meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
    """)
    conn.commit()
    conn.close()


# ── Tranco ────────────────────────────────────────────────────────────────────

_update_status = {"state": "idle", "count": 0, "error": ""}


def _set_status(state: str, count: int = 0, error: str = ""):
    _update_status["state"] = state
    _update_status["count"] = count
    _update_status["error"] = error


def update_tranco(top_n: int = STORE_TOP_N):
    """Download Tranco list and populate trusted_domains table."""
    _set_status("downloading")
    try:
        r = requests.get(TRANCO_URL, timeout=90, stream=True)
        r.raise_for_status()

        raw = b""
        for chunk in r.iter_content(1024 * 64):
            raw += chunk

        _set_status("processing")
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            fname = z.namelist()[0]
            with z.open(fname) as f:
                lines = f.read().decode(errors="ignore").strip().split("\n")

        now = datetime.utcnow().isoformat()
        batch = []
        for line in lines[:top_n]:
            parts = line.strip().split(",")
            if len(parts) >= 2:
                rank   = int(parts[0])
                domain = parts[1].lower().strip()
                batch.append((domain, rank, now))

        _set_status("storing")
        conn = _db()
        conn.execute("DELETE FROM trusted_domains")
        conn.executemany(
            "INSERT OR REPLACE INTO trusted_domains (domain, rank, updated_at) VALUES (?,?,?)",
            batch,
        )
        conn.execute("INSERT OR REPLACE INTO intel_meta VALUES ('tranco_updated', ?)", (now,))
        conn.execute("INSERT OR REPLACE INTO intel_meta VALUES ('tranco_count',   ?)", (str(len(batch)),))
        conn.commit()
        conn.close()

        _trust_cache.clear()
        _pool_cache.clear()
        _set_status("done", count=len(batch))
        return len(batch)

    except Exception as exc:
        _set_status("error", error=str(exc))
        return 0


def update_tranco_async():
    """Fire the Tranco download in a daemon thread (non-blocking)."""
    t = threading.Thread(target=update_tranco, daemon=True)
    t.start()
    return t


def get_intel_status() -> dict:
    """Return Tranco update metadata and current update state."""
    try:
        conn = _db()
        updated  = conn.execute("SELECT value FROM intel_meta WHERE key='tranco_updated'").fetchone()
        count    = conn.execute("SELECT value FROM intel_meta WHERE key='tranco_count'").fetchone()
        conn.close()
        return {
            "state":        _update_status["state"],
            "error":        _update_status["error"],
            "updated_at":   updated[0] if updated else None,
            "domain_count": int(count[0]) if count else 0,
        }
    except Exception:
        return {"state": _update_status["state"], "domain_count": 0}


def needs_update() -> bool:
    """True if Tranco list is missing or older than 7 days."""
    try:
        conn = _db()
        row = conn.execute("SELECT value FROM intel_meta WHERE key='tranco_updated'").fetchone()
        conn.close()
        if not row:
            return True
        age = datetime.utcnow() - datetime.fromisoformat(row[0])
        return age.days >= 7
    except Exception:
        return True


# ── Domain lookup helpers ─────────────────────────────────────────────────────

_trust_cache: dict = {}
_pool_cache: dict = {}


def is_trusted(domain: str) -> tuple[bool, int | None]:
    """Exact-match check against Tranco top-50 K. Returns (trusted, rank). Cached in memory."""
    d = domain.lower()
    hit = _trust_cache.get(d)
    if hit is not None:
        return hit
    try:
        conn = _db()
        row = conn.execute("SELECT rank FROM trusted_domains WHERE domain=?", (d,)).fetchone()
        conn.close()
    except Exception:
        return False, None
    out = (True, row[0]) if row else (False, None)
    if len(_trust_cache) > 200_000:
        _trust_cache.clear()
    _trust_cache[d] = out
    return out


def get_levenshtein_pool() -> list[str]:
    """
    Return top-1 K domains from Tranco for Levenshtein comparison.
    Top-1 K captures Google, Microsoft, Apple, PayPal, Amazon, all banks, etc.
    Using 1 K (not 50 K) keeps analysis under 50 ms. Cached until the list is refreshed.
    """
    if "pool" in _pool_cache:
        return _pool_cache["pool"]
    try:
        conn = _db()
        rows = conn.execute("SELECT domain FROM trusted_domains ORDER BY rank LIMIT ?", (MATCH_TOP_N,)).fetchall()
        conn.close()
        domains = [r[0] for r in rows]
    except Exception:
        return _fallback_domains()
    if not domains:
        return _fallback_domains()
    _pool_cache["pool"] = domains
    return domains


def _fallback_domains() -> list[str]:
    """Hardcoded safety net used before first Tranco download completes."""
    return [
        "google.com", "gmail.com", "microsoft.com", "outlook.com", "hotmail.com",
        "amazon.com", "apple.com", "icloud.com", "paypal.com", "facebook.com",
        "instagram.com", "twitter.com", "linkedin.com", "github.com", "netflix.com",
        "yahoo.com", "ebay.com", "dropbox.com", "adobe.com", "zoom.us",
        "slack.com", "salesforce.com", "bankofamerica.com", "chase.com",
        "wellsfargo.com", "citibank.com", "sbi.co.in", "hdfcbank.com",
    ]


# ── WHOIS domain age ──────────────────────────────────────────────────────────

def check_domain_age(domain: str) -> dict:
    """
    WHOIS lookup with 24-hour SQLite cache.
    Runs WHOIS in a thread with a hard timeout so slow registries
    never block the Flask request cycle.
    """
    # Check cache first
    try:
        conn = _db()
        row = conn.execute(
            "SELECT age_days, registrar, country, is_new, cached_at FROM whois_cache WHERE domain=?",
            (domain,),
        ).fetchone()
        conn.close()

        if row:
            cached_at = datetime.fromisoformat(row["cached_at"])
            if datetime.utcnow() - cached_at < timedelta(hours=WHOIS_TTL_H):
                return {
                    "age_days":  row["age_days"],
                    "registrar": row["registrar"],
                    "country":   row["country"],
                    "is_new":    bool(row["is_new"]),
                    "from_cache": True,
                }
    except Exception:
        pass

    # Live WHOIS query inside a thread (enforces timeout)
    try:
        import whois  # python-whois

        def _do_whois():
            return whois.whois(domain)

        with ThreadPoolExecutor(max_workers=1) as ex:
            try:
                w = ex.submit(_do_whois).result(timeout=WHOIS_TIMEOUT_S)
            except FTimeout:
                return {"age_days": None, "error": "whois_timeout"}

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        if not creation:
            return {"age_days": None, "registrar": str(w.registrar or "")[:200]}

        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        age_days  = (datetime.now(timezone.utc) - creation).days
        is_new    = age_days < 90
        registrar = str(w.registrar  or "")[:200]
        country   = str(w.country    or "")[:10]

        result = {
            "age_days":   age_days,
            "registrar":  registrar,
            "country":    country,
            "is_new":     is_new,
            "from_cache": False,
        }

        # Write to cache
        try:
            conn = _db()
            conn.execute(
                "INSERT OR REPLACE INTO whois_cache VALUES (?,?,?,?,?,?)",
                (domain, age_days, registrar, country,
                 int(is_new), datetime.utcnow().isoformat()),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

        return result

    except ImportError:
        return {"age_days": None, "error": "python-whois not installed"}
    except Exception as exc:
        return {"age_days": None, "error": str(exc)}

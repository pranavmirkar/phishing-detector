from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3, json, logging, os, re, threading, time
from collections import defaultdict, deque
from datetime import datetime, timezone
from detector import PhishingDetector
from emailparse import parse_raw
from benchmark_service import bp as benchmarks_bp
from domain_intel import (
    init_intel_tables,
    needs_update,
    update_tranco_async,
    get_intel_status,
    check_domain_age,
    DB_PATH,
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
)
log = logging.getLogger(__name__)

# ── Configuration (environment variables; every one is optional) ──────────────
#   PG_DB             SQLite file                         (default: backend/phishing.db)
#   PG_CORS_ORIGINS   comma-separated allowed web origins (default: local dev servers)
#   PG_API_KEY        if set, /api/* needs the header  X-API-Key: <value>
#   PG_RATE_LIMIT     analyses per minute per client, 0 = off   (default 120)
#   PG_STORE_CONTENT  0 = never store message bodies in history  (default 1)
#   PG_OWN_DOMAINS    your organisation's domains, e.g. "example.com,example.org" (enables org-impersonation checks)
#   PG_TRUST_PROXY    1 = trust X-Forwarded-For from one proxy (set in Docker / behind nginx)
#   PG_HOST / PG_PORT / PG_DEBUG   for `python app.py` (default 127.0.0.1:5000, debug off)
def _env_list(name, default=""):
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


API_KEY       = os.environ.get("PG_API_KEY", "")
RATE_LIMIT    = int(os.environ.get("PG_RATE_LIMIT", "120"))
STORE_CONTENT = os.environ.get("PG_STORE_CONTENT", "1") != "0"
OWN_DOMAINS   = _env_list("PG_OWN_DOMAINS")

app = Flask(__name__)
if os.environ.get("PG_TRUST_PROXY") == "1":          # behind nginx / a load balancer: use the real client IP
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024      # custom benchmark uploads / raw emails
CORS(app, origins=_env_list("PG_CORS_ORIGINS", "http://localhost:3000,http://localhost:5173"))
app.register_blueprint(benchmarks_bp)
DB = DB_PATH

_hits = defaultdict(deque)
RATE_LIMITED = ("/api/analyze", "/api/parse", "/api/matrix", "/api/intel/whois", "/api/intel/update")
_hits_lock = threading.Lock()


@app.before_request
def _guard():
    if request.method == "OPTIONS" or not request.path.startswith("/api/") or request.path == "/api/health":
        return None
    if API_KEY and request.headers.get("X-API-Key", "") != API_KEY:
        return jsonify({"error": "invalid or missing API key"}), 401
    if RATE_LIMIT and request.method == "POST" and request.path in RATE_LIMITED:
        now = time.time()
        key = request.remote_addr or "?"
        with _hits_lock:
            if len(_hits) > 5000:                      # forget idle clients so the table cannot grow forever
                for k in [k for k, v in _hits.items() if not v or now - v[-1] > 60]:
                    del _hits[k]
            q = _hits[key]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= RATE_LIMIT:
                return jsonify({"error": "rate limit exceeded, try again shortly"}), 429
            q.append(now)
    return None


@app.after_request
def _headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Cache-Control", "no-store")
    return resp


@app.errorhandler(413)
def _too_large(_):
    return jsonify({"error": "request too large"}), 413


def _body():
    """JSON object body, or {} (never a list / string / null, which would crash handlers)."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _clean_extras(data):
    """Optional header-derived fields from the client, coerced to safe types and sizes."""
    atts = []
    for a in (data.get("attachments") or [])[:25]:
        if isinstance(a, dict):
            atts.append({"filename": str(a.get("filename", ""))[:200], "type": str(a.get("type", ""))[:80]})
        elif isinstance(a, str):
            atts.append({"filename": a[:200], "type": ""})
    return {
        "reply_to":     str(data.get("reply_to") or "")[:500],
        "auth_results": str(data.get("auth_results") or "")[:500] if not isinstance(data.get("auth_results"), dict) else data["auth_results"],
        "return_path":  str(data.get("return_path") or "")[:500],
        "recipient":    str(data.get("recipient") or "")[:320],
        "attachments":  atts,
        "list_id":      bool(data.get("list_id")),
        "own_domains":  OWN_DOMAINS,
    }

EMAIL_RE = re.compile(r'.+@[\w.\-]+\.\w+')
MAX_FIELD = 5_000


def db():
    conn = sqlite3.connect(DB, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS emails (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            sender     TEXT NOT NULL,
            subject    TEXT,
            content    TEXT,
            domain     TEXT,
            risk_score TEXT,
            risk_level INTEGER,
            warnings   TEXT,
            analysis   TEXT,
            timestamp  TEXT
        );
        CREATE TABLE IF NOT EXISTS reports (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id  INTEGER,
            reason    TEXT,
            timestamp TEXT,
            FOREIGN KEY (email_id) REFERENCES emails(id)
        );
    """)
    conn.commit()
    conn.close()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    intel = get_intel_status()
    return jsonify({
        "service": "PhishGuard API",
        "status":  "online",
        "endpoints": [
            "POST /api/analyze",
            "GET  /api/emails",
            "GET  /api/stats",
            "POST /api/matrix",
            "GET  /api/intel/status",
            "POST /api/intel/update",
            "POST /api/intel/whois",
            "GET  /api/benchmarks/datasets",
            "POST /api/benchmarks/run",
            "GET  /api/benchmarks/jobs/<id>",
        ],
        "intel": intel,
    })


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = _body()
    if not isinstance(data.get("sender"), str):
        return jsonify({"error": "sender is required"}), 400
    sender = data["sender"].strip()
    if not sender:
        return jsonify({"error": "sender is required"}), 400
    if not EMAIL_RE.match(sender):
        return jsonify({"error": "sender must be a valid email address"}), 400
    if len(sender) > MAX_FIELD:
        return jsonify({"error": "sender too long"}), 400

    data["subject"] = data["subject"][:MAX_FIELD] if isinstance(data.get("subject"), str) else ""
    data["content"] = data["content"][:MAX_FIELD * 12] if isinstance(data.get("content"), str) else ""
    data.update(_clean_extras(data))

    try:
        result = PhishingDetector().analyze(data)
    except Exception as exc:
        log.exception("Detector error for sender=%s", sender)
        return jsonify({"error": "Analysis failed", "detail": str(exc)}), 500

    if data.get("persist") is False:           # e.g. the browser extension: score it, do not add it to the history
        result["id"] = None
        return jsonify(result)

    conn = db()
    cur = conn.execute(
        "INSERT INTO emails (sender,subject,content,domain,risk_score,risk_level,warnings,analysis,timestamp)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (
            data.get("sender"), data.get("subject", ""), (data.get("content", "") if STORE_CONTENT else ""),
            result["domain"], result["risk_score"], result["risk_level"],
            json.dumps(result["warnings"]),
            json.dumps(result["domain_analysis"], default=str),
            datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        ),
    )
    result["id"] = cur.lastrowid
    conn.commit()
    conn.close()
    return jsonify(result)


@app.route("/api/parse", methods=["POST"])
def parse():
    """Parse a raw RFC 822 message (an .eml file or 'show original' text) into analyzable fields."""
    data = _body()
    raw = data.get("raw")
    if not isinstance(raw, str) or not raw.strip():
        return jsonify({"error": "raw (the full message including headers) is required"}), 400
    try:
        return jsonify(parse_raw(raw))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/emails", methods=["GET"])
def emails():
    conn = db()
    rows = conn.execute(
        "SELECT id,sender,subject,domain,risk_score,risk_level,warnings,timestamp"
        " FROM emails ORDER BY timestamp DESC LIMIT 100"
    ).fetchall()
    conn.close()
    out = []
    for r in rows:
        e = dict(r)
        e["warnings"] = json.loads(e["warnings"] or "[]")
        out.append(e)
    return jsonify(out)


@app.route("/api/emails/<int:eid>", methods=["GET"])
def email_detail(eid):
    conn = db()
    row = conn.execute("SELECT * FROM emails WHERE id=?", (eid,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    e = dict(row)
    e["warnings"] = json.loads(e["warnings"] or "[]")
    e["analysis"]  = json.loads(e["analysis"]  or "{}")
    return jsonify(e)


@app.route("/api/report", methods=["POST"])
def report():
    data     = _body()
    email_id = data.get("email_id")
    if not email_id or not isinstance(email_id, int):
        return jsonify({"error": "email_id (integer) is required"}), 400
    conn = db()
    exists = conn.execute("SELECT id FROM emails WHERE id=?", (email_id,)).fetchone()
    if not exists:
        conn.close()
        return jsonify({"error": "email not found"}), 404
    conn.execute(
        "INSERT INTO reports (email_id,reason,timestamp) VALUES (?,?,?)",
        (email_id, (data.get("reason") or "")[:500], datetime.now(timezone.utc).replace(tzinfo=None).isoformat()),
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/stats", methods=["GET"])
def stats():
    conn = db()
    total   = conn.execute("SELECT COUNT(*) FROM emails").fetchone()[0]
    high    = conn.execute("SELECT COUNT(*) FROM emails WHERE risk_score='HIGH'").fetchone()[0]
    medium  = conn.execute("SELECT COUNT(*) FROM emails WHERE risk_score='MEDIUM'").fetchone()[0]
    low     = conn.execute("SELECT COUNT(*) FROM emails WHERE risk_score='LOW'").fetchone()[0]
    reports = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]

    trend = conn.execute("""
        SELECT DATE(timestamp) day, risk_score, COUNT(*) cnt
        FROM emails WHERE timestamp >= DATE('now','-7 days')
        GROUP BY day, risk_score ORDER BY day
    """).fetchall()

    all_w = conn.execute("SELECT warnings FROM emails").fetchall()
    attack_types = {
        "LOOKALIKE_DOMAIN": 0, "SUSPICIOUS_KEYWORDS": 0,
        "LINK_MISMATCH": 0, "SUBDOMAIN_ABUSE": 0,
        "HOMOGLYPH_ATTACK": 0, "REPLY_TO_MISMATCH": 0,
        "VERY_NEW_DOMAIN": 0, "NEW_DOMAIN": 0,
        "BRAND_IMPERSONATION": 0, "BRAND_IN_DOMAIN": 0, "BRAND_MISMATCH": 0,
        "ACCOUNT_ACTION_LURE": 0, "ADMIN_IMPERSONATION": 0, "BEC_SCAM_PATTERN": 0,
        "SUSPICIOUS_LINK": 0, "PUNYCODE_DOMAIN": 0, "AUTH_FAILURE": 0,
    }
    for row in all_w:
        try:
            for w in json.loads(row[0] or "[]"):
                t = w.get("type", "")
                if t in attack_types:
                    attack_types[t] += 1
        except Exception:
            pass

    conn.close()
    intel = get_intel_status()

    return jsonify({
        "total": total, "high": high, "medium": medium,
        "low": low, "reports": reports,
        "trend": [dict(r) for r in trend],
        "attack_types": attack_types,
        "intel": intel,
    })


@app.route("/api/matrix", methods=["POST"])
def matrix():
    from levenshtein import get_dp_matrix, get_edit_operations, similarity_percent
    data = _body()
    s1, s2 = data.get("s1", ""), data.get("s2", "")
    if not isinstance(s1, str) or not isinstance(s2, str) or not s1 or not s2:
        return jsonify({"error": "s1 and s2 required (strings)"}), 400
    if len(s1) > 120 or len(s2) > 120:             # the DP matrix is len(s1) x len(s2) cells
        return jsonify({"error": "strings are limited to 120 characters"}), 400
    return jsonify({
        "matrix_data":     get_dp_matrix(s1, s2),
        "edit_operations": get_edit_operations(s1, s2),
        "similarity":      similarity_percent(s1, s2),
    })


# ── Domain Intelligence endpoints ─────────────────────────────────────────────

@app.route("/api/intel/status", methods=["GET"])
def intel_status():
    """Returns Tranco list download state + metadata."""
    return jsonify(get_intel_status())


@app.route("/api/intel/update", methods=["POST"])
def intel_update():
    """Triggers a background Tranco list download."""
    status = get_intel_status()
    if status["state"] in ("downloading", "processing", "storing"):
        return jsonify({"message": "Update already in progress", "status": status})
    update_tranco_async()
    return jsonify({"message": "Tranco update started in background"})


@app.route("/api/intel/whois", methods=["POST"])
def intel_whois():
    """On-demand WHOIS domain age lookup (with 24 h cache)."""
    data   = _body()
    domain = data.get("domain", "")
    domain = domain.strip().lower() if isinstance(domain, str) else ""
    if not domain:
        return jsonify({"error": "domain required"}), 400
    return jsonify(check_domain_age(domain))


# ── Startup ───────────────────────────────────────────────────────────────────

def bootstrap():
    """Create tables and make sure the trusted-domain list exists. Safe to call repeatedly."""
    init_db()
    init_intel_tables()
    if needs_update():
        log.info("Tranco list missing or stale - downloading in background")
        update_tranco_async()
    else:
        log.info("Tranco: %s trusted domains loaded", f"{get_intel_status()['domain_count']:,}")


# Under gunicorn / Docker there is no __main__, so bootstrap on import (tests opt out).
if not os.environ.get("PG_NO_BOOTSTRAP"):
    bootstrap()


if __name__ == "__main__":
    host, port = os.environ.get("PG_HOST", "127.0.0.1"), int(os.environ.get("PG_PORT", "5000"))
    print(f"\n  PhishGuard API : http://{host}:{port}")
    print("  Status         : GET /api/intel/status\n")
    app.run(host=host, port=port, debug=os.environ.get("PG_DEBUG") == "1", use_reloader=False)

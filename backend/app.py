from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3, json, logging, re
from datetime import datetime
from detector import PhishingDetector
from domain_intel import (
    init_intel_tables,
    needs_update,
    update_tranco_async,
    get_intel_status,
    check_domain_age,
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
)
log = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, origins=["http://localhost:3000", "http://localhost:5173"])
DB = "phishing.db"

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
        ],
        "intel": intel,
    })


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.json or {}
    sender = (data.get("sender") or "").strip()
    if not sender:
        return jsonify({"error": "sender is required"}), 400
    if not EMAIL_RE.match(sender):
        return jsonify({"error": "sender must be a valid email address"}), 400
    if len(sender) > MAX_FIELD:
        return jsonify({"error": "sender too long"}), 400

    data["subject"] = (data.get("subject") or "")[:MAX_FIELD]
    data["content"] = (data.get("content") or "")[:MAX_FIELD * 2]

    try:
        result = PhishingDetector().analyze(data)
    except Exception as exc:
        log.exception("Detector error for sender=%s", sender)
        return jsonify({"error": "Analysis failed", "detail": str(exc)}), 500

    conn = db()
    cur = conn.execute(
        "INSERT INTO emails (sender,subject,content,domain,risk_score,risk_level,warnings,analysis,timestamp)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (
            data.get("sender"), data.get("subject", ""), data.get("content", ""),
            result["domain"], result["risk_score"], result["risk_level"],
            json.dumps(result["warnings"]),
            json.dumps(result["domain_analysis"], default=str),
            datetime.utcnow().isoformat(),
        ),
    )
    result["id"] = cur.lastrowid
    conn.commit()
    conn.close()
    return jsonify(result)


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
    data     = request.json or {}
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
        (email_id, (data.get("reason") or "")[:500], datetime.utcnow().isoformat()),
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
    data = request.json or {}
    s1, s2 = data.get("s1", ""), data.get("s2", "")
    if not s1 or not s2:
        return jsonify({"error": "s1 and s2 required"}), 400
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
    data   = request.json or {}
    domain = data.get("domain", "").strip().lower()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    return jsonify(check_domain_age(domain))


# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    init_intel_tables()

    if needs_update():
        print("  Tranco list missing or stale — downloading in background...")
        update_tranco_async()
    else:
        status = get_intel_status()
        print(f"  Tranco: {status['domain_count']:,} trusted domains loaded")

    print("\n  PhishGuard API   : http://localhost:5000")
    print("  Tranco status    : GET  /api/intel/status")
    print("  Force update     : POST /api/intel/update\n")
    app.run(debug=True, port=5000, use_reloader=False)

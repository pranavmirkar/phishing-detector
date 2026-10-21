"""
Run this after updating the Tranco list to regenerate extension/domains.js
Usage: python export_domains.py
"""
import sqlite3, json, os

DB   = os.path.join(os.path.dirname(__file__), "phishing.db")
OUT  = os.path.join(os.path.dirname(__file__), "../extension/domains.js")

conn = sqlite3.connect(DB)
rows_50k = conn.execute("SELECT domain FROM trusted_domains ORDER BY rank LIMIT 50000").fetchall()
rows_1k  = conn.execute("SELECT domain FROM trusted_domains ORDER BY rank LIMIT 1000").fetchall()
conn.close()

d50k = [r[0] for r in rows_50k]
d1k  = [r[0] for r in rows_1k]

content = f"""// Auto-generated from Tranco top-1M list — {len(d50k):,} trusted domains
// TRUSTED_SET  : exact O(1) lookup for all 50K domains
// TRUSTED_POOL : top 1K used for Levenshtein comparison (keeps analysis <10ms)
const TRUSTED_SET  = new Set({json.dumps(d50k)})
const TRUSTED_POOL = {json.dumps(d1k)}
"""

with open(OUT, "w", encoding="utf-8") as f:
    f.write(content)

print(f"domains.js written — {len(d50k):,} domains, {os.path.getsize(OUT):,} bytes")

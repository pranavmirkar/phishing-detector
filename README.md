# PhishGuard

Email phishing detector. A Flask API scores a message (sender, reply-to, subject, body) with rule-based
checks, and a React dashboard shows the verdict, the evidence and the Levenshtein edit-distance working.
A browser extension (`extension/`) runs a lighter version of the checks inside the mail client.

## What it checks

| Layer | Signals |
|---|---|
| Sender domain | lookalike by edit distance (typos, swapped letters, digits), look-alike characters (Cyrillic, `rn`→`m`), punycode, brand name used in a domain it does not own (`paypal-secure.com`, `paypal.xyz`), brand in a subdomain, throw-away TLDs, account/security words in the name |
| Sender identity | free-mail providers are never "trusted"; display name or mailbox name claiming a brand (`"PayPal Support" <x@gmail.com>`, `"Amazon.com" <x@isp.net>`) |
| Content | account-takeover wording (threat + requested action + deadline), IT/webmail administrator lures, payment-redirection and advance-fee wording, brand named in the text that does not match the sender |
| Links | visible URL vs real destination (compared by registrable domain, so `click.nytimes.com` ≙ `nytimes.com`), shorteners, raw IPs, punycode, unrelated destinations in automated mail from a brand |
| Headers | `Reply-To` pointing somewhere unrelated; optional `auth_results` (SPF / DKIM / DMARC from an `Authentication-Results` header) |
| Domain age | WHOIS age (cached 24 h) |

Trusted-domain data comes from the Tranco top-50K list (downloaded on first run). `backend/brands.py` holds the
curated brand, free-mail and TLD data.

## Run it

```bash
# backend  (http://localhost:5000)
cd backend
pip install -r requirements.txt
python app.py

# frontend (http://localhost:3000)
cd frontend
npm install
npm run dev
```

`POST /api/analyze` accepts `sender`, `reply_to`, `subject`, `content` and optionally `auth_results`
(a string such as `"spf=pass dkim=pass dmarc=fail"` or an object `{"spf": "pass", ...}`).

## Tests and benchmarks

```bash
cd backend
pip install pytest
python -m pytest -q                         # 46 offline tests (detector rules + benchmark API)
python benchmark/run_benchmark.py            # development set  -> benchmark/REPORT.md
python benchmark/run_benchmark.py --dataset dataset_v2.jsonl --tag holdout   # second set
```

### Benchmarks tab

The dashboard has a **Benchmarks** tab that runs the detector against labelled emails and shows accuracy,
precision, recall, F1, ROC AUC, a confusion matrix, a cut-off sweep, per-category results and every
misclassified email. Sources:

- **Private datasets**: the two bundled synthetic sets in `backend/benchmark/`.
- **Real public datasets**: Nazario's phishing corpus and the SpamAssassin ham/spam corpora. They are
  downloaded on demand with one click from their original sites (fixed URLs, about 12 MB) into
  `backend/benchmark/data/` (git-ignored) and never redistributed. Choose the test half, dev half or all, and
  how many emails per class.
- **Your own file**: upload `.jsonl`, `.json` or `.csv` with `label` (`phishing`/`legit`), `sender`, `subject`,
  `content` (optional `reply_to`, `category`). Up to 2,000 rows; processed in memory and not stored.

Runs are background jobs (one at a time) using the same detector as `/api/analyze`, with WHOIS off. API:
`GET /api/benchmarks/datasets`, `POST /api/benchmarks/real/download`, `DELETE /api/benchmarks/real`,
`POST /api/benchmarks/run`, `GET /api/benchmarks/jobs/<id>`, `GET /api/benchmarks/results`.

### Results

Positive class = phishing; a message is flagged when its score is MEDIUM or above (25+). "Before" is the
first version of this project, "After" is the current detector.

**Real public mail (the number to trust).** Phishing: Nazario's phishing corpus (2015). Legitimate: the
SpamAssassin public "easy ham" corpus. The detector was never tuned on the *test* half; the corpora were
split 50/50 by a hash of sender+subject, and issues were diagnosed on the other half. One later fix (generic host
words such as `mail.` wrongly counted as brands in subdomains) was prompted by an error seen on the test half, so
the test numbers are very slightly less independent than the rest.

| Real-data test half (151 phishing, 400 legitimate) | Before | After |
|---|---|---|
| Phishing caught (recall) | 43.0% | **75.5%** |
| Legitimate mail wrongly flagged | 45.0% | **1.0%** |
| Precision | 26.5% | **96.6%** |
| F1 | 32.8% | **84.8%** |
| Balanced accuracy | 49.0% | **87.2%** |

Before the rewrite the detector was close to a coin flip on real mail. Most of the gain is fewer false alarms
(free-mail was treated as trusted, any domain containing a digit or "cl" counted as a homoglyph attack,
newsletter tracking links counted as deceptive).

**Synthetic sets** (written by this project's author, so higher numbers are expected and say less):

| Set | Before (accuracy) | After (accuracy / F1) | Notes |
|---|---|---|---|
| Development, 306 emails | 85.0% | 100% / 100% | used to guide the fixes; **do not read 100% as a real-world claim** |
| Second set, 258 emails | 51.9% | 97.3% / 97.8% | different seed, wording and brands, but still same author |

Full tables, per-category results and every misclassified message: [`REPORT.md`](backend/benchmark/REPORT.md),
[`REPORT_holdout.md`](backend/benchmark/REPORT_holdout.md), and the real-data aggregates in
`backend/benchmark/results_real_*.json` (the corpora themselves are not redistributed; `eval_real.py` says where to get them).

### Known limits

- **Forged mail from a brand's real address** (`billing@paypal.com`) with a clean body is invisible without
  authentication headers. The API accepts `auth_results`, but the dashboard and extension do not send it yet.
  This accounts for most of the remaining missed phishing on real data.
- Real-data recall at the stricter HIGH-only cut-off is 40%. HIGH has near-zero false alarms; MEDIUM is the
  recommended "review this" level.
- The real corpora are 2002–2015 era and mostly English; the detector only sees sender, subject and body
  (no attachments, rendering or sender reputation beyond domain age).
- Legitimate newsletters sent through a different tracking domain are still occasionally flagged.
- SpamAssassin *spam* (not phishing) is flagged 39% of the time; it is reported for information, not scored as a miss.
- The detector is rule-based. Its numbers describe these datasets, not future attacks.

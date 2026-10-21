# Model card: PhishGuard scoring model (`model_v1.json`)

## What it is

A small gradient-boosted-tree classifier (250 trees, depth 4, scikit-learn `HistGradientBoostingClassifier`) that
decides how much each *combination* of the rule engine's signals is worth. The rule engine still finds and explains
every signal; the model only produces the 0-100 score and the LOW / MEDIUM / HIGH verdict. The trees are exported to
JSON and evaluated in pure Python (no scikit-learn or numpy at runtime). `PG_MODEL=off` returns to the rule score.

| | |
|---|---|
| Version | 1 (trained 2026-10-22) |
| Inputs (52) | per-signal rule points; spam score; sender trusted / free-mail; era-neutral lexical features (randomness of the sender domain and mailbox name, subject shape); link features (untrusted destination domains, plain-http share, URL length / depth, recipient address inside a URL) |
| Deliberately **not** used | display name present, `List-Id`, attachment presence, HTML, message length (era proxies or trivially spoofable), `X-Spam-*` (another filter's verdict) |
| Training data | 6,129 emails: 2,345 phishing (Nazario 2015-2023) and 3,784 legitimate (SpamAssassin ham / hard ham, Enron corporate mail, Apache mailing lists), from the `dev` and `val` splits |
| Verdict thresholds | MEDIUM = raw score at which **1%** of legitimate training mail is flagged; HIGH = **0.1%**. Computed on 5-fold *out-of-fold* predictions in which all mail from one sender stays in one fold |
| Support-aware floor | Signals with fewer than 20 phishing training examples (punycode, return-path forgery, BEC wording, ...) are not judged by the model: their rule points stay as a floor under the score |

## How it was evaluated

Phishing is split by **year** and legitimate mail by **sender address**, so the model is tested on later years and
on senders it never saw. The locked `test` split (unseen 2024-2025 phishing, ~4,500 unseen legitimate emails) was
scored once per configuration; see the README for the numbers, ablations and comparison with the earlier versions.

## Known limits (read before relying on it)

- **It learns this corpus.** Nazario's phishing is credential phishing aimed at one mailbox. Attack styles the data
  barely contains are handled by the rule floor, not by learning.
- **The legitimate data is narrow:** 2002-03 personal and list mail, 1999-2002 corporate mail, 2025 developer lists.
  Marketing mail, receipts and consumer webmail are absent, so false alarms on them are unmeasured. The link features
  (destination reputation) are the most likely to behave differently on such mail.
- **Era drift.** Link and domain features lean on the current Tranco list; phishing infrastructure and legitimate
  sending practices change over time. Retrain on recent data regularly.
- **Adversarial pressure.** Attackers who learn the features can try to avoid them. The rules keep explaining every
  verdict, but the learned layer is not hardened against evasion.
- Thresholds are false-alarm *budgets measured on the training distribution*; on the locked test MEDIUM flagged
  1.4% (budget 1%) and HIGH 0.2% (budget 0.1%) of legitimate mail.

## Retraining

```bash
pip install -r requirements-dev.txt                    # scikit-learn + numpy, training only
# download the corpora from the dashboard's Benchmarks tab (Core, Recent, Extended, Business groups)
python -P benchmark/train_model.py                     # features -> grouped CV -> thresholds -> model_v1.json
```

The script verifies that the exported pure-Python model reproduces scikit-learn exactly, and reports recall and false
alarms on `test_seen`. It never reads the locked `test` split. Do not tune on `test`; if you do, say so next to any
number you publish.

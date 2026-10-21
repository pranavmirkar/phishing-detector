# PhishGuard validation benchmark (development set)

Run date: 2026-10-22  |  Samples: 306 (193 phishing, 113 legitimate)  |  Trusted-domain list: 50,000 Tranco domains  |  ROC AUC: **0.998**

## Overall results

Positive class = phishing. An email is flagged when its risk score is at or above the threshold.

| Operating point | Threshold | Accuracy | Balanced acc. | Precision | Recall | Specificity | F1 |
|---|---|---|---|---|---|---|---|
| MEDIUM or HIGH flagged | 25 | 98.0% | 98.4% | 100.0% | 96.9% | 100.0% | 98.4% |
| HIGH only flagged | 55 | 92.5% | 94.0% | 100.0% | 88.1% | 100.0% | 93.7% |

Confusion matrix, MEDIUM or HIGH flagged: TP=187 FP=0 TN=113 FN=6  
Confusion matrix, HIGH only flagged: TP=170 FP=0 TN=113 FN=23  

## Held-out validation

The dataset was split 70/30 (stratified, seed 7). The score threshold was chosen on the 214-sample development part by maximising F1, then applied once to the 92-sample test part. No detector rules were changed using the test part.

| Set | Threshold | Accuracy | Balanced acc. | Precision | Recall | Specificity | F1 |
|---|---|---|---|---|---|---|---|
| Development | 25 | 97.2% | 97.8% | 100.0% | 95.6% | 100.0% | 97.7% |
| Test (held out) | 25 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| Test at default MEDIUM cut-off | 25 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |

## Per-category results (flagged at MEDIUM or above)

`rate` is the share classified correctly: detected for phishing categories, not flagged for legitimate ones.

| Class | Category | n | Correct | Rate | Mean score |
|---|---|---|---|---|---|
| legit | legit_name_collision | 6 | 6 | 100.0% | 9 |
| legit | personal_freemail | 18 | 18 | 100.0% | 0 |
| legit | small_org_unknown_domain | 32 | 32 | 100.0% | 11 |
| legit | trusted_marketing | 21 | 21 | 100.0% | 3 |
| legit | trusted_tracking_links | 8 | 8 | 100.0% | 18 |
| legit | trusted_transactional | 28 | 28 | 100.0% | 5 |
| phishing | bec_freemail_text_only | 12 | 12 | 100.0% | 56 |
| phishing | brand_hyphen | 22 | 22 | 100.0% | 78 |
| phishing | homoglyph_unicode | 21 | 21 | 100.0% | 75 |
| phishing | reply_to_spoof | 12 | 11 | 91.7% | 90 |
| phishing | spoofed_trusted_from | 12 | 12 | 100.0% | 58 |
| phishing | subdomain_abuse | 22 | 22 | 100.0% | 81 |
| phishing | tld_swap | 21 | 21 | 100.0% | 74 |
| phishing | typo_delete | 6 | 6 | 100.0% | 83 |
| phishing | typo_digit | 22 | 21 | 95.5% | 75 |
| phishing | typo_insert | 10 | 9 | 90.0% | 76 |
| phishing | typo_swap | 9 | 9 | 100.0% | 67 |
| phishing | unknown_domain_link_mismatch | 12 | 12 | 100.0% | 86 |
| phishing | unknown_domain_text_only | 12 | 9 | 75.0% | 47 |

## Threshold sweep

| Threshold | Precision | Recall | FPR | F1 | Accuracy |
|---|---|---|---|---|---|
| 5 | 74.8% | 100.0% | 57.5% | 85.6% | 78.8% |
| 10 | 84.6% | 100.0% | 31.0% | 91.7% | 88.6% |
| 15 | 92.7% | 99.0% | 13.3% | 95.7% | 94.4% |
| 20 | 97.0% | 99.0% | 5.3% | 97.9% | 97.4% |
| 25 | 100.0% | 96.9% | 0.0% | 98.4% | 98.0% |
| 30 | 100.0% | 95.9% | 0.0% | 97.9% | 97.4% |
| 35 | 100.0% | 95.3% | 0.0% | 97.6% | 97.1% |
| 40 | 100.0% | 94.8% | 0.0% | 97.3% | 96.7% |
| 45 | 100.0% | 94.3% | 0.0% | 97.1% | 96.4% |
| 50 | 100.0% | 91.2% | 0.0% | 95.4% | 94.4% |
| 55 | 100.0% | 88.1% | 0.0% | 93.7% | 92.5% |
| 60 | 100.0% | 75.1% | 0.0% | 85.8% | 84.3% |
| 65 | 100.0% | 63.7% | 0.0% | 77.8% | 77.1% |
| 70 | 100.0% | 61.7% | 0.0% | 76.3% | 75.8% |
| 75 | 100.0% | 59.6% | 0.0% | 74.7% | 74.5% |
| 80 | 100.0% | 55.4% | 0.0% | 71.3% | 71.9% |
| 85 | 100.0% | 42.0% | 0.0% | 59.1% | 63.4% |
| 90 | 100.0% | 19.2% | 0.0% | 32.2% | 49.0% |
| 95 | 100.0% | 4.1% | 0.0% | 8.0% | 39.5% |
| 100 | 100.0% | 3.6% | 0.0% | 7.0% | 39.2% |

## Misclassified samples at MEDIUM or above (6)

| id | Truth | Category | Sender | Score | Signals fired |
|---|---|---|---|---|---|
| 47 | phishing | unknown_domain_text_only | `notice@id-verification-hub.cfd` | 24 | LURE_WORDS_IN_DOMAIN, SUSPICIOUS_TLD |
| 151 | phishing | unknown_domain_text_only | `notice@verify-id-portal.info` | 23 | LURE_WORDS_IN_DOMAIN |
| 243 | phishing | unknown_domain_text_only | `notice@billing-review-desk.site` | 24 | LURE_WORDS_IN_DOMAIN, SUSPICIOUS_TLD |
| 248 | phishing | typo_digit | `security@dh1.com` | 20 | HOMOGLYPH_ATTACK, PAYMENT_LURE, SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS |
| 279 | phishing | typo_insert | `security@chhase.com` | 14 | LOOKALIKE_DOMAIN, PAYMENT_LURE, SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS |
| 288 | phishing | reply_to_spoof | `dhl.support@gmail.com` | 14 | FREEMAIL_SENDER, PAYMENT_LURE, REPLY_TO_MISMATCH, SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS |

## How to reproduce

```bash
cd backend
python benchmark/build_dataset.py   # regenerates dataset.jsonl (seeded)
python benchmark/run_benchmark.py   # writes results.json and this report
```

## Limitations

- The dataset is synthetic and was written by the project author's tooling, not collected from real mailboxes or a public corpus. Real-world accuracy will differ; treat these numbers as a regression baseline and a validation of the rule logic, not a field accuracy estimate.
- Several phishing categories (typosquats, homoglyphs) are exactly what the Levenshtein layer is built to catch, so high scores there are expected.
- WHOIS domain-age scoring was disabled, so brand-new-domain detection is not evaluated.
- Only the sender domain, subject and body are scored; attachments, headers (SPF/DKIM/DMARC) and message rendering are out of scope.

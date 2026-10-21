# PhishGuard validation benchmark (development set)

Run date: 2026-10-22  |  Samples: 306 (193 phishing, 113 legitimate)  |  Trusted-domain list: 50,000 Tranco domains  |  ROC AUC: **1.000**

## Overall results

Positive class = phishing. An email is flagged when its risk score is at or above the threshold.

| Operating point | Threshold | Accuracy | Balanced acc. | Precision | Recall | Specificity | F1 |
|---|---|---|---|---|---|---|---|
| MEDIUM or HIGH flagged | 25 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| HIGH only flagged | 55 | 98.0% | 98.4% | 100.0% | 96.9% | 100.0% | 98.4% |

Confusion matrix, MEDIUM or HIGH flagged: TP=193 FP=0 TN=113 FN=0  
Confusion matrix, HIGH only flagged: TP=187 FP=0 TN=113 FN=6  

## Held-out validation

The dataset was split 70/30 (stratified, seed 7). The score threshold was chosen on the 214-sample development part by maximising F1, then applied once to the 92-sample test part. No detector rules were changed using the test part.

| Set | Threshold | Accuracy | Balanced acc. | Precision | Recall | Specificity | F1 |
|---|---|---|---|---|---|---|---|
| Development | 45 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| Test (held out) | 45 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| Test at default MEDIUM cut-off | 25 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |

## Per-category results (flagged at MEDIUM or above)

`rate` is the share classified correctly: detected for phishing categories, not flagged for legitimate ones.

| Class | Category | n | Correct | Rate | Mean score |
|---|---|---|---|---|---|
| legit | legit_name_collision | 6 | 6 | 100.0% | 0 |
| legit | personal_freemail | 18 | 18 | 100.0% | 0 |
| legit | small_org_unknown_domain | 32 | 32 | 100.0% | 0 |
| legit | trusted_marketing | 21 | 21 | 100.0% | 0 |
| legit | trusted_tracking_links | 8 | 8 | 100.0% | 0 |
| legit | trusted_transactional | 28 | 28 | 100.0% | 0 |
| phishing | bec_freemail_text_only | 12 | 12 | 100.0% | 61 |
| phishing | brand_hyphen | 22 | 22 | 100.0% | 100 |
| phishing | homoglyph_unicode | 21 | 21 | 100.0% | 100 |
| phishing | reply_to_spoof | 12 | 12 | 100.0% | 98 |
| phishing | spoofed_trusted_from | 12 | 12 | 100.0% | 58 |
| phishing | subdomain_abuse | 22 | 22 | 100.0% | 100 |
| phishing | tld_swap | 21 | 21 | 100.0% | 100 |
| phishing | typo_delete | 6 | 6 | 100.0% | 100 |
| phishing | typo_digit | 22 | 22 | 100.0% | 99 |
| phishing | typo_insert | 10 | 10 | 100.0% | 100 |
| phishing | typo_swap | 9 | 9 | 100.0% | 100 |
| phishing | unknown_domain_link_mismatch | 12 | 12 | 100.0% | 100 |
| phishing | unknown_domain_text_only | 12 | 12 | 100.0% | 53 |

## Threshold sweep

| Threshold | Precision | Recall | FPR | F1 | Accuracy |
|---|---|---|---|---|---|
| 5 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% |
| 10 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% |
| 15 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% |
| 20 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% |
| 25 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% |
| 30 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% |
| 35 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% |
| 40 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% |
| 45 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% |
| 50 | 100.0% | 96.9% | 0.0% | 98.4% | 98.0% |
| 55 | 100.0% | 96.9% | 0.0% | 98.4% | 98.0% |
| 60 | 100.0% | 87.0% | 0.0% | 93.1% | 91.8% |
| 65 | 100.0% | 82.9% | 0.0% | 90.7% | 89.2% |
| 70 | 100.0% | 82.9% | 0.0% | 90.7% | 89.2% |
| 75 | 100.0% | 82.9% | 0.0% | 90.7% | 89.2% |
| 80 | 100.0% | 82.9% | 0.0% | 90.7% | 89.2% |
| 85 | 100.0% | 80.3% | 0.0% | 89.1% | 87.6% |
| 90 | 100.0% | 80.3% | 0.0% | 89.1% | 87.6% |
| 95 | 100.0% | 79.8% | 0.0% | 88.8% | 87.3% |
| 100 | 100.0% | 79.8% | 0.0% | 88.8% | 87.3% |

## Misclassified samples at MEDIUM or above (0)

None.

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

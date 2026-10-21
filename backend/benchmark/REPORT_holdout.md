# PhishGuard validation benchmark (holdout set)

Run date: 2026-10-22  |  Samples: 258 (165 phishing, 93 legitimate)  |  Trusted-domain list: 50,000 Tranco domains  |  ROC AUC: **0.975**

## Overall results

Positive class = phishing. An email is flagged when its risk score is at or above the threshold.

| Operating point | Threshold | Accuracy | Balanced acc. | Precision | Recall | Specificity | F1 |
|---|---|---|---|---|---|---|---|
| MEDIUM or HIGH flagged | 25 | 97.3% | 97.9% | 100.0% | 95.8% | 100.0% | 97.8% |
| HIGH only flagged | 55 | 91.9% | 93.6% | 100.0% | 87.3% | 100.0% | 93.2% |

Confusion matrix, MEDIUM or HIGH flagged: TP=158 FP=0 TN=93 FN=7  
Confusion matrix, HIGH only flagged: TP=144 FP=0 TN=93 FN=21  

## Held-out validation

The dataset was split 70/30 (stratified, seed 7). The score threshold was chosen on the 180-sample development part by maximising F1, then applied once to the 78-sample test part. No detector rules were changed using the test part.

| Set | Threshold | Accuracy | Balanced acc. | Precision | Recall | Specificity | F1 |
|---|---|---|---|---|---|---|---|
| Development | 40 | 97.8% | 98.3% | 100.0% | 96.5% | 100.0% | 98.2% |
| Test (held out) | 40 | 96.2% | 97.0% | 100.0% | 94.0% | 100.0% | 96.9% |
| Test at default MEDIUM cut-off | 25 | 96.2% | 97.0% | 100.0% | 94.0% | 100.0% | 96.9% |

## Per-category results (flagged at MEDIUM or above)

`rate` is the share classified correctly: detected for phishing categories, not flagged for legitimate ones.

| Class | Category | n | Correct | Rate | Mean score |
|---|---|---|---|---|---|
| legit | hyphenated_business_hard | 6 | 6 | 100.0% | 3 |
| legit | institution | 5 | 5 | 100.0% | 0 |
| legit | legit_name_collision | 6 | 6 | 100.0% | 0 |
| legit | personal_freemail_hard | 12 | 12 | 100.0% | 5 |
| legit | small_org_unknown_domain | 20 | 20 | 100.0% | 2 |
| legit | trusted_esp_redirect | 3 | 3 | 100.0% | 20 |
| legit | trusted_retail_marketing | 15 | 15 | 100.0% | 0 |
| legit | trusted_same_org_tracking | 12 | 12 | 100.0% | 0 |
| legit | trusted_security_alert | 14 | 14 | 100.0% | 0 |
| phishing | combosquat | 10 | 10 | 100.0% | 94 |
| phishing | crypto_giveaway | 10 | 10 | 100.0% | 98 |
| phishing | display_name_spoof | 10 | 10 | 100.0% | 82 |
| phishing | freemail_scam_text | 12 | 12 | 100.0% | 71 |
| phishing | punycode_idn | 15 | 15 | 100.0% | 79 |
| phishing | shipping_lure | 10 | 10 | 100.0% | 87 |
| phishing | spoofed_trusted_no_signal | 6 | 0 | 0.0% | 0 |
| phishing | spoofed_trusted_reply_to | 10 | 10 | 100.0% | 42 |
| phishing | subdomain_brand | 20 | 20 | 100.0% | 98 |
| phishing | suffix_squat | 15 | 15 | 100.0% | 95 |
| phishing | throwaway_domain_lure | 10 | 10 | 100.0% | 75 |
| phishing | tld_squat | 11 | 11 | 100.0% | 97 |
| phishing | typo_double | 9 | 9 | 100.0% | 98 |
| phishing | typo_rn | 4 | 4 | 100.0% | 100 |
| phishing | typo_vowel | 13 | 12 | 92.3% | 89 |

## Threshold sweep

| Threshold | Precision | Recall | FPR | F1 | Accuracy |
|---|---|---|---|---|---|
| 5 | 90.3% | 95.8% | 18.3% | 92.9% | 90.7% |
| 10 | 94.6% | 95.8% | 9.7% | 95.2% | 93.8% |
| 15 | 98.1% | 95.8% | 3.2% | 96.9% | 96.1% |
| 20 | 98.1% | 95.8% | 3.2% | 96.9% | 96.1% |
| 25 | 100.0% | 95.8% | 0.0% | 97.8% | 97.3% |
| 30 | 100.0% | 95.8% | 0.0% | 97.8% | 97.3% |
| 35 | 100.0% | 95.8% | 0.0% | 97.8% | 97.3% |
| 40 | 100.0% | 95.8% | 0.0% | 97.8% | 97.3% |
| 45 | 100.0% | 89.7% | 0.0% | 94.6% | 93.4% |
| 50 | 100.0% | 89.1% | 0.0% | 94.2% | 93.0% |
| 55 | 100.0% | 87.3% | 0.0% | 93.2% | 91.9% |
| 60 | 100.0% | 84.8% | 0.0% | 91.8% | 90.3% |
| 65 | 100.0% | 82.4% | 0.0% | 90.4% | 88.8% |
| 70 | 100.0% | 80.0% | 0.0% | 88.9% | 87.2% |
| 75 | 100.0% | 75.2% | 0.0% | 85.8% | 84.1% |
| 80 | 100.0% | 71.5% | 0.0% | 83.4% | 81.8% |
| 85 | 100.0% | 67.3% | 0.0% | 80.4% | 79.1% |
| 90 | 100.0% | 62.4% | 0.0% | 76.9% | 76.0% |
| 95 | 100.0% | 55.8% | 0.0% | 71.6% | 71.7% |
| 100 | 100.0% | 47.9% | 0.0% | 64.8% | 66.7% |

## Misclassified samples at MEDIUM or above (7)

| id | Truth | Category | Sender | Score | Signals fired |
|---|---|---|---|---|---|
| 8 | phishing | spoofed_trusted_no_signal | `no-reply@amazon.com` | 0 | TRUSTED_VERIFIED |
| 26 | phishing | spoofed_trusted_no_signal | `billing@paypal.com` | 0 | TRUSTED_VERIFIED |
| 39 | phishing | typo_vowel | `service@eps.com` | 0 | none |
| 53 | phishing | spoofed_trusted_no_signal | `no-reply@amazon.com` | 0 | TRUSTED_VERIFIED |
| 79 | phishing | spoofed_trusted_no_signal | `security@microsoft.com` | 0 | TRUSTED_VERIFIED |
| 176 | phishing | spoofed_trusted_no_signal | `billing@paypal.com` | 0 | TRUSTED_VERIFIED |
| 198 | phishing | spoofed_trusted_no_signal | `security@microsoft.com` | 0 | TRUSTED_VERIFIED |

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

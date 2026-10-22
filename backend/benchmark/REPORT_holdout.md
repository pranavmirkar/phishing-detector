# PhishGuard validation benchmark (holdout set)

Run date: 2026-10-22  |  Samples: 258 (165 phishing, 93 legitimate)  |  Trusted-domain list: 50,000 Tranco domains  |  ROC AUC: **0.968**

## Overall results

Positive class = phishing. An email is flagged when its risk score is at or above the threshold.

| Operating point | Threshold | Accuracy | Balanced acc. | Precision | Recall | Specificity | F1 |
|---|---|---|---|---|---|---|---|
| MEDIUM or HIGH flagged | 25 | 95.7% | 96.7% | 100.0% | 93.3% | 100.0% | 96.6% |
| HIGH only flagged | 55 | 80.2% | 84.5% | 100.0% | 69.1% | 100.0% | 81.7% |

Confusion matrix, MEDIUM or HIGH flagged: TP=154 FP=0 TN=93 FN=11  
Confusion matrix, HIGH only flagged: TP=114 FP=0 TN=93 FN=51  

## Held-out validation

The dataset was split 70/30 (stratified, seed 7). The score threshold was chosen on the 180-sample development part by maximising F1, then applied once to the 78-sample test part. No detector rules were changed using the test part.

| Set | Threshold | Accuracy | Balanced acc. | Precision | Recall | Specificity | F1 |
|---|---|---|---|---|---|---|---|
| Development | 25 | 96.7% | 97.4% | 100.0% | 94.8% | 100.0% | 97.3% |
| Test (held out) | 25 | 93.6% | 95.0% | 100.0% | 90.0% | 100.0% | 94.7% |
| Test at default MEDIUM cut-off | 25 | 93.6% | 95.0% | 100.0% | 90.0% | 100.0% | 94.7% |

## Per-category results (flagged at MEDIUM or above)

`rate` is the share classified correctly: detected for phishing categories, not flagged for legitimate ones.

| Class | Category | n | Correct | Rate | Mean score |
|---|---|---|---|---|---|
| legit | hyphenated_business_hard | 6 | 6 | 100.0% | 15 |
| legit | institution | 5 | 5 | 100.0% | 10 |
| legit | legit_name_collision | 6 | 6 | 100.0% | 12 |
| legit | personal_freemail_hard | 12 | 12 | 100.0% | 5 |
| legit | small_org_unknown_domain | 20 | 20 | 100.0% | 14 |
| legit | trusted_esp_redirect | 3 | 3 | 100.0% | 19 |
| legit | trusted_retail_marketing | 15 | 15 | 100.0% | 1 |
| legit | trusted_same_org_tracking | 12 | 12 | 100.0% | 17 |
| legit | trusted_security_alert | 14 | 14 | 100.0% | 7 |
| phishing | combosquat | 10 | 10 | 100.0% | 60 |
| phishing | crypto_giveaway | 10 | 10 | 100.0% | 44 |
| phishing | display_name_spoof | 10 | 10 | 100.0% | 85 |
| phishing | freemail_scam_text | 12 | 12 | 100.0% | 56 |
| phishing | punycode_idn | 15 | 14 | 93.3% | 71 |
| phishing | shipping_lure | 10 | 10 | 100.0% | 30 |
| phishing | spoofed_trusted_no_signal | 6 | 0 | 0.0% | 8 |
| phishing | spoofed_trusted_reply_to | 10 | 9 | 90.0% | 48 |
| phishing | subdomain_brand | 20 | 20 | 100.0% | 83 |
| phishing | suffix_squat | 15 | 15 | 100.0% | 70 |
| phishing | throwaway_domain_lure | 10 | 8 | 80.0% | 59 |
| phishing | tld_squat | 11 | 11 | 100.0% | 69 |
| phishing | typo_double | 9 | 9 | 100.0% | 78 |
| phishing | typo_rn | 4 | 4 | 100.0% | 76 |
| phishing | typo_vowel | 13 | 12 | 92.3% | 68 |

## Threshold sweep

| Threshold | Precision | Recall | FPR | F1 | Accuracy |
|---|---|---|---|---|---|
| 5 | 70.4% | 98.2% | 73.1% | 82.0% | 72.5% |
| 10 | 75.5% | 97.0% | 55.9% | 84.9% | 77.9% |
| 15 | 82.8% | 96.4% | 35.5% | 89.1% | 84.9% |
| 20 | 95.7% | 94.5% | 7.5% | 95.1% | 93.8% |
| 25 | 100.0% | 93.3% | 0.0% | 96.6% | 95.7% |
| 30 | 100.0% | 87.9% | 0.0% | 93.5% | 92.2% |
| 35 | 100.0% | 87.3% | 0.0% | 93.2% | 91.9% |
| 40 | 100.0% | 79.4% | 0.0% | 88.5% | 86.8% |
| 45 | 100.0% | 78.8% | 0.0% | 88.1% | 86.4% |
| 50 | 100.0% | 77.6% | 0.0% | 87.4% | 85.7% |
| 55 | 100.0% | 69.1% | 0.0% | 81.7% | 80.2% |
| 60 | 100.0% | 63.6% | 0.0% | 77.8% | 76.7% |
| 65 | 100.0% | 51.5% | 0.0% | 68.0% | 69.0% |
| 70 | 100.0% | 45.5% | 0.0% | 62.5% | 65.1% |
| 75 | 100.0% | 41.2% | 0.0% | 58.4% | 62.4% |
| 80 | 100.0% | 29.7% | 0.0% | 45.8% | 55.0% |
| 85 | 100.0% | 24.2% | 0.0% | 39.0% | 51.6% |
| 90 | 100.0% | 11.5% | 0.0% | 20.7% | 43.4% |
| 95 | 100.0% | 4.2% | 0.0% | 8.1% | 38.8% |
| 100 | 100.0% | 3.6% | 0.0% | 7.0% | 38.4% |

## Misclassified samples at MEDIUM or above (11)

| id | Truth | Category | Sender | Score | Signals fired |
|---|---|---|---|---|---|
| 8 | phishing | spoofed_trusted_no_signal | `no-reply@amazon.com` | 3 | TRUSTED_VERIFIED |
| 26 | phishing | spoofed_trusted_no_signal | `billing@paypal.com` | 6 | TRUSTED_VERIFIED |
| 39 | phishing | typo_vowel | `service@eps.com` | 0 | none |
| 53 | phishing | spoofed_trusted_no_signal | `no-reply@amazon.com` | 3 | TRUSTED_VERIFIED |
| 68 | phishing | throwaway_domain_lure | `care@billing-help-line.work` | 24 | BRAND_MISMATCH, LURE_WORDS_IN_DOMAIN, SUSPICIOUS_TLD |
| 79 | phishing | spoofed_trusted_no_signal | `security@microsoft.com` | 15 | TRUSTED_VERIFIED |
| 92 | phishing | punycode_idn | `security@xn--venm-eua.com` | 20 | BRAND_MISMATCH, PUNYCODE_DOMAIN |
| 123 | phishing | throwaway_domain_lure | `care@verifyme-now.xyz` | 15 | BRAND_MISMATCH, SUSPICIOUS_TLD |
| 176 | phishing | spoofed_trusted_no_signal | `billing@paypal.com` | 6 | TRUSTED_VERIFIED |
| 198 | phishing | spoofed_trusted_no_signal | `security@microsoft.com` | 15 | TRUSTED_VERIFIED |
| 258 | phishing | spoofed_trusted_reply_to | `no-reply@paytm.com` | 14 | REPLY_TO_MISMATCH, SUSPICIOUS_LINK, TRUSTED_VERIFIED |

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

# PhishGuard validation benchmark

Run date: 2026-10-21  |  Samples: 305 (192 phishing, 113 legitimate)  |  Trusted-domain list: 50,000 Tranco domains  |  ROC AUC: **0.917**

## Overall results

Positive class = phishing. An email is flagged when its risk score is at or above the threshold.

| Operating point | Threshold | Accuracy | Balanced acc. | Precision | Recall | Specificity | F1 |
|---|---|---|---|---|---|---|---|
| MEDIUM or HIGH flagged | 25 | 83.6% | 83.7% | 89.9% | 83.3% | 84.1% | 86.5% |
| HIGH only flagged | 55 | 68.2% | 74.7% | 100.0% | 49.5% | 100.0% | 66.2% |

Confusion matrix, MEDIUM or HIGH flagged: TP=160 FP=18 TN=95 FN=32  
Confusion matrix, HIGH only flagged: TP=95 FP=0 TN=113 FN=97  

## Held-out validation

The dataset was split 70/30 (stratified, seed 7). The score threshold was chosen on the 213-sample development part by maximising F1, then applied once to the 92-sample test part. No detector rules were changed using the test part.

| Set | Threshold | Accuracy | Balanced acc. | Precision | Recall | Specificity | F1 |
|---|---|---|---|---|---|---|---|
| Development | 20 | 87.8% | 87.7% | 92.2% | 88.1% | 87.3% | 90.1% |
| Test (held out) | 20 | 84.8% | 81.8% | 84.4% | 93.1% | 70.6% | 88.5% |
| Test at default MEDIUM cut-off | 25 | 84.8% | 83.1% | 86.7% | 89.7% | 76.5% | 88.1% |

## Per-category results (flagged at MEDIUM or above)

`rate` is the share classified correctly: detected for phishing categories, not flagged for legitimate ones.

| Class | Category | n | Correct | Rate | Mean score |
|---|---|---|---|---|---|
| legit | legit_name_collision | 6 | 5 | 83.3% | 4 |
| legit | personal_freemail | 18 | 18 | 100.0% | 0 |
| legit | small_org_unknown_domain | 32 | 32 | 100.0% | 1 |
| legit | trusted_marketing | 21 | 12 | 57.1% | 20 |
| legit | trusted_tracking_links | 8 | 0 | 0.0% | 26 |
| legit | trusted_transactional | 28 | 28 | 100.0% | 0 |
| phishing | bec_freemail_text_only | 12 | 0 | 0.0% | 5 |
| phishing | brand_hyphen | 22 | 20 | 90.9% | 35 |
| phishing | homoglyph_unicode | 21 | 21 | 100.0% | 95 |
| phishing | reply_to_spoof | 12 | 12 | 100.0% | 50 |
| phishing | spoofed_trusted_from | 12 | 12 | 100.0% | 45 |
| phishing | subdomain_abuse | 22 | 19 | 86.4% | 70 |
| phishing | tld_swap | 22 | 20 | 90.9% | 49 |
| phishing | typo_delete | 5 | 5 | 100.0% | 74 |
| phishing | typo_digit | 22 | 22 | 100.0% | 94 |
| phishing | typo_insert | 8 | 7 | 87.5% | 56 |
| phishing | typo_swap | 10 | 10 | 100.0% | 84 |
| phishing | unknown_domain_link_mismatch | 12 | 12 | 100.0% | 52 |
| phishing | unknown_domain_text_only | 12 | 0 | 0.0% | 2 |

## Threshold sweep

| Threshold | Precision | Recall | FPR | F1 | Accuracy |
|---|---|---|---|---|---|
| 5 | 84.3% | 89.6% | 28.3% | 86.9% | 83.0% |
| 10 | 86.9% | 89.6% | 23.0% | 88.2% | 84.9% |
| 15 | 86.9% | 89.6% | 23.0% | 88.2% | 84.9% |
| 20 | 89.6% | 89.6% | 17.7% | 89.6% | 86.9% |
| 25 | 89.9% | 83.3% | 15.9% | 86.5% | 83.6% |
| 30 | 96.4% | 83.3% | 5.3% | 89.4% | 87.5% |
| 35 | 96.0% | 75.5% | 5.3% | 84.5% | 82.6% |
| 40 | 100.0% | 73.4% | 0.0% | 84.7% | 83.3% |
| 45 | 100.0% | 62.0% | 0.0% | 76.5% | 76.1% |
| 50 | 100.0% | 56.2% | 0.0% | 72.0% | 72.5% |
| 55 | 100.0% | 49.5% | 0.0% | 66.2% | 68.2% |
| 60 | 100.0% | 40.1% | 0.0% | 57.2% | 62.3% |
| 65 | 100.0% | 39.6% | 0.0% | 56.7% | 62.0% |
| 70 | 100.0% | 37.5% | 0.0% | 54.5% | 60.7% |
| 75 | 100.0% | 37.0% | 0.0% | 54.0% | 60.3% |
| 80 | 100.0% | 34.4% | 0.0% | 51.2% | 58.7% |
| 85 | 100.0% | 33.9% | 0.0% | 50.6% | 58.4% |
| 90 | 100.0% | 28.6% | 0.0% | 44.5% | 55.1% |
| 95 | 100.0% | 26.0% | 0.0% | 41.3% | 53.4% |
| 100 | 100.0% | 18.8% | 0.0% | 31.6% | 48.9% |

## Misclassified samples at MEDIUM or above (50)

| id | Truth | Category | Sender | Score | Signals fired |
|---|---|---|---|---|---|
| 10 | phishing | bec_freemail_text_only | `m.harris.director@outlook.com` | 0 | TRUSTED_VERIFIED |
| 14 | phishing | bec_freemail_text_only | `m.harris.director@outlook.com` | 0 | TRUSTED_VERIFIED |
| 20 | phishing | tld_swap | `security@apple.co` | 20 | SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS, TRUSTED_VERIFIED |
| 26 | phishing | bec_freemail_text_only | `m.harris.director@outlook.com` | 20 | SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS, TRUSTED_VERIFIED |
| 28 | legit | trusted_marketing | `offers@booking.com` | 26 | BULK_SENDER, SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS, TRUSTED_VERIFIED |
| 30 | phishing | subdomain_abuse | `alerts@binance.login-confirm.live` | 20 | SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS |
| 35 | legit | trusted_marketing | `marketing@airbnb.com` | 36 | BULK_SENDER, SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS, TRUSTED_VERIFIED |
| 42 | phishing | unknown_domain_text_only | `notice@id-verification-hub.cfd` | 0 | none |
| 43 | legit | trusted_marketing | `deals@target.com` | 36 | BULK_SENDER, SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS, TRUSTED_VERIFIED |
| 52 | phishing | tld_swap | `security@coinbase.info` | 20 | SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS |
| 54 | phishing | bec_freemail_text_only | `finance.dept.office@yahoo.com` | 20 | SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS, TRUSTED_VERIFIED |
| 60 | phishing | unknown_domain_text_only | `notice@auth-service-check.online` | 0 | none |
| 61 | phishing | unknown_domain_text_only | `notice@secure-login-verify.xyz` | 0 | none |
| 63 | phishing | unknown_domain_text_only | `notice@helpdesk-alerts.work` | 0 | none |
| 70 | phishing | unknown_domain_text_only | `notice@accounts-safety.buzz` | 0 | none |
| 76 | phishing | unknown_domain_text_only | `notice@verify-id-portal.info` | 0 | none |
| 77 | phishing | bec_freemail_text_only | `finance.dept.office@yahoo.com` | 0 | TRUSTED_VERIFIED |
| 86 | legit | trusted_tracking_links | `hello@medium.com` | 26 | BULK_SENDER, LINK_MISMATCH, TRUSTED_VERIFIED |
| 87 | phishing | unknown_domain_text_only | `notice@support-notice-team.shop` | 0 | none |
| 90 | legit | trusted_tracking_links | `news@nytimes.com` | 26 | BULK_SENDER, LINK_MISMATCH, TRUSTED_VERIFIED |
| 109 | legit | trusted_marketing | `marketing@airbnb.com` | 36 | BULK_SENDER, SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS, TRUSTED_VERIFIED |
| 110 | phishing | bec_freemail_text_only | `john.mcallister.ceo@gmail.com` | 0 | TRUSTED_VERIFIED |
| 120 | legit | trusted_tracking_links | `hello@medium.com` | 26 | BULK_SENDER, LINK_MISMATCH, TRUSTED_VERIFIED |
| 126 | phishing | unknown_domain_text_only | `notice@billing-review-desk.site` | 0 | none |
| 153 | phishing | bec_freemail_text_only | `finance.dept.office@yahoo.com` | 0 | TRUSTED_VERIFIED |
| 155 | phishing | subdomain_abuse | `alerts@docusign.helpdesk-alerts.work` | 20 | SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS |
| 159 | phishing | unknown_domain_text_only | `notice@login-confirm.live` | 0 | none |
| 172 | phishing | bec_freemail_text_only | `m.harris.director@outlook.com` | 0 | TRUSTED_VERIFIED |
| 179 | phishing | unknown_domain_text_only | `notice@mailer-support.click` | 20 | HOMOGLYPH_ATTACK |
| 181 | legit | trusted_marketing | `deals@target.com` | 36 | BULK_SENDER, SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS, TRUSTED_VERIFIED |
| 185 | phishing | bec_freemail_text_only | `john.mcallister.ceo@gmail.com` | 0 | TRUSTED_VERIFIED |
| 187 | phishing | brand_hyphen | `security@yahoo-login.com` | 20 | SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS |
| 192 | phishing | unknown_domain_text_only | `notice@secure-pay-center.icu` | 0 | none |
| 197 | legit | trusted_tracking_links | `digest@substack.com` | 26 | BULK_SENDER, LINK_MISMATCH, TRUSTED_VERIFIED |
| 199 | phishing | brand_hyphen | `security@apple-support.com` | 20 | SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS |
| 205 | legit | legit_name_collision | `info@zoomin.io` | 25 | SUSPICIOUS_DOMAIN |
| 223 | legit | trusted_tracking_links | `digest@substack.com` | 26 | BULK_SENDER, LINK_MISMATCH, TRUSTED_VERIFIED |
| 225 | phishing | bec_freemail_text_only | `john.mcallister.ceo@gmail.com` | 0 | TRUSTED_VERIFIED |
| 231 | phishing | bec_freemail_text_only | `finance.dept.office@yahoo.com` | 0 | TRUSTED_VERIFIED |
| 244 | legit | trusted_marketing | `offers@booking.com` | 26 | BULK_SENDER, SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS, TRUSTED_VERIFIED |
| 245 | phishing | bec_freemail_text_only | `john.mcallister.ceo@gmail.com` | 20 | SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS, TRUSTED_VERIFIED |
| 247 | phishing | subdomain_abuse | `alerts@chase.account-update-center.top` | 20 | SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS |
| 248 | legit | trusted_tracking_links | `team@mailchimp.com` | 26 | BULK_SENDER, LINK_MISMATCH, TRUSTED_VERIFIED |
| 259 | phishing | unknown_domain_text_only | `notice@account-update-center.top` | 0 | none |
| 260 | legit | trusted_marketing | `marketing@airbnb.com` | 36 | BULK_SENDER, SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS, TRUSTED_VERIFIED |
| 278 | legit | trusted_tracking_links | `team@mailchimp.com` | 26 | BULK_SENDER, LINK_MISMATCH, TRUSTED_VERIFIED |
| 285 | phishing | typo_insert | `security@docusiign.com` | 20 | SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS |
| 287 | legit | trusted_marketing | `deals@target.com` | 36 | BULK_SENDER, SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS, TRUSTED_VERIFIED |
| 293 | legit | trusted_tracking_links | `digest@substack.com` | 26 | BULK_SENDER, LINK_MISMATCH, TRUSTED_VERIFIED |
| 295 | legit | trusted_marketing | `offers@booking.com` | 26 | BULK_SENDER, SPAM_KEYWORDS, SUSPICIOUS_KEYWORDS, TRUSTED_VERIFIED |

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

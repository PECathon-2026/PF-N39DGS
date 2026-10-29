# PrivacyLens Evaluation Benchmark Report

**Generated:** 2026-10-29T22:09:33Z
**Ground Truth Dataset:** `eval/ground_truth.json`

## Overall Summary

| Metric | Score |
| :--- | :--- |
| **Overall Precision (Finding-Level)** | **100.0%** |
| **Overall Recall** | **100.0%** |
| **True Positives** | 26 |
| **False Negatives (Misses)** | 0 |
| **Total Findings (After Dedupe)** | 26 |
| **False Positives (Unmatched)** | 0 |
| **Type Mismatches on Sensitive Elements** | 0 |
| **Pure Extras on Non-Sensitive Elements** | 0 |
| **Decoy False Positives** | 0 |
| **Decoy Over-Redaction Rate** | 0.0% |
| **Character Over-Redaction Rate** | 0.00% |
| **Canary Coverage** | 5/5 |
| **Total Latency** | 681.90 ms |

## Per-Page Performance

| Page | Sensitive Items | Detected (TP) | Misses (FN) | Findings | Precision | Recall | Decoy FP | Decoy Over-Redact | Char Over-Redact | Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `checkout.html` | 6 | 6 | 0 | 6 | 100.0% | 100.0% | 0 | 0.0% | 0.00% | 528.8 |
| `login.html` | 3 | 3 | 0 | 3 | 100.0% | 100.0% | 0 | 0.0% | 0.00% | 16.1 |
| `support.html` | 5 | 5 | 0 | 5 | 100.0% | 100.0% | 0 | 0.0% | 0.00% | 54.9 |
| `meeting.html` | 6 | 6 | 0 | 6 | 100.0% | 100.0% | 0 | 0.0% | 0.00% | 26.2 |
| `devsettings.html` | 6 | 6 | 0 | 6 | 100.0% | 100.0% | 0 | 0.0% | 0.00% | 55.8 |

## Ablation Study

| Configuration | Precision | Recall | TP | FN | Decoy FP | Decoy Over-Redact | Char Over-Redact | Canary | Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `all` | 100.0% | 100.0% | 26 | 0 | 0 | 0.0% | 0.00% | 5/5 | 681.9 |
| `pattern_only` | 95.0% | 73.1% | 19 | 7 | 0 | 0.0% | 0.00% | 5/5 | 2.3 |
| `structural_only` | 100.0% | 26.9% | 7 | 19 | 0 | 0.0% | 0.00% | 1/5 | 0.4 |
| `presidio_only` | 71.4% | 19.2% | 5 | 21 | 0 | 0.0% | 0.00% | 1/5 | 184.5 |

## Missed Items and False Positives (Item IDs)

No misses or false positives observed.

---

## 6. Egress Gate and Leakage Evaluation

### Clean Run (11 Benchmark Pages)

| Metric | Result | Target | Status |
| :--- | :---: | :---: | :---: |
| **Sensitive Items Leaked** | **0** | 0 | PASS |
| **Canary Tokens Leaked** | **0** | 0 | PASS |
| **False Blocks on Sanitized Pages** | **0** | 0 | PASS |

### Adversarial Positive Control (Obfuscation Battery)

| Obfuscation Class | Blocked / Total | Block Rate |
| :--- | :---: | :---: |
| `raw` | 106 / 106 | **100.0%** |
| `spaced` | 106 / 106 | **100.0%** |
| `hyphenated` | 106 / 106 | **100.0%** |
| `url_encoded` | 104 / 106 | **98.1%** |
| `base64` | 99 / 106 | **93.4%** |
| `zero_width` | 99 / 106 | **93.4%** |
| `fullwidth` | 99 / 106 | **93.4%** |
| `split_json` | 106 / 106 | **100.0%** |
| `image_embedded` | 106 / 106 | **100.0%** |

**Overall Adversarial Block Rate:** **97.59%** (931/954)

### Fail-Closed Robustness

- **Unauthorized Host Destination:** PASS (Blocked)
- **Corrupt / Malformed Request State:** PASS (Blocked)
- **Provider Key Exfiltration in Body:** PASS (Blocked)

### Adversarial Misses (Transparently Disclosed)
- **ID:** `dev:checkout.html:item_4` | **Type:** `EXPIRY` | **Class:** `base64`
- **ID:** `dev:checkout.html:item_4` | **Type:** `EXPIRY` | **Class:** `zero_width`
- **ID:** `dev:checkout.html:item_4` | **Type:** `EXPIRY` | **Class:** `fullwidth`
- **ID:** `dev:checkout.html:item_5` | **Type:** `CVV` | **Class:** `base64`
- **ID:** `dev:checkout.html:item_5` | **Type:** `CVV` | **Class:** `zero_width`
- **ID:** `dev:checkout.html:item_5` | **Type:** `CVV` | **Class:** `fullwidth`
- **ID:** `dev:login.html:item_2` | **Type:** `OTP` | **Class:** `base64`
- **ID:** `dev:login.html:item_2` | **Type:** `OTP` | **Class:** `zero_width`
- **ID:** `dev:login.html:item_2` | **Type:** `OTP` | **Class:** `fullwidth`
- **ID:** `dev:meeting.html:item_5` | **Type:** `NAME` | **Class:** `url_encoded`
- **ID:** `holdout:checkout2.html:item_4` | **Type:** `EXPIRY` | **Class:** `base64`
- **ID:** `holdout:checkout2.html:item_4` | **Type:** `EXPIRY` | **Class:** `zero_width`
- **ID:** `holdout:checkout2.html:item_4` | **Type:** `EXPIRY` | **Class:** `fullwidth`
- **ID:** `holdout:checkout2.html:item_5` | **Type:** `CVV` | **Class:** `base64`
- **ID:** `holdout:checkout2.html:item_5` | **Type:** `CVV` | **Class:** `zero_width`

---

## 6. Egress Gate and Leakage Evaluation

### Clean Run (11 Benchmark Pages)

| Metric | Result | Target | Status |
| :--- | :---: | :---: | :---: |
| **Sensitive Items Leaked** | **0** | 0 | PASS |
| **Canary Tokens Leaked** | **0** | 0 | PASS |
| **False Blocks on Sanitized Pages** | **0** | 0 | PASS |

### Adversarial Positive Control (Obfuscation Battery)

| Obfuscation Class | Blocked / Total | Block Rate |
| :--- | :---: | :---: |
| `raw` | 106 / 106 | **100.0%** |
| `spaced` | 106 / 106 | **100.0%** |
| `hyphenated` | 106 / 106 | **100.0%** |
| `url_encoded` | 106 / 106 | **100.0%** |
| `base64` | 53 / 106 | **50.0%** |
| `zero_width` | 106 / 106 | **100.0%** |
| `fullwidth` | 106 / 106 | **100.0%** |
| `split_json` | 106 / 106 | **100.0%** |
| `image_embedded` | 106 / 106 | **100.0%** |

**Overall Adversarial Block Rate:** **94.44%** (901/954)

### Fail-Closed Robustness

- **Unauthorized Host Destination:** PASS (Blocked)
- **Corrupt / Malformed Request State:** PASS (Blocked)
- **Provider Key Exfiltration in Body:** PASS (Blocked)

### Adversarial Misses (Transparently Disclosed)
- **ID:** `dev:checkout.html:item_0` | **Type:** `NAME` | **Class:** `base64`
- **ID:** `dev:checkout.html:item_1` | **Type:** `ADDRESS` | **Class:** `base64`
- **ID:** `dev:checkout.html:item_3` | **Type:** `CARD` | **Class:** `base64`
- **ID:** `dev:checkout.html:item_4` | **Type:** `EXPIRY` | **Class:** `base64`
- **ID:** `dev:login.html:item_0` | **Type:** `EMAIL` | **Class:** `base64`
- **ID:** `dev:support.html:item_0` | **Type:** `EMAIL` | **Class:** `base64`
- **ID:** `dev:support.html:item_2` | **Type:** `NOTE_WITH_CANARY` | **Class:** `base64`
- **ID:** `dev:support.html:item_4` | **Type:** `PAN` | **Class:** `base64`
- **ID:** `dev:meeting.html:item_0` | **Type:** `EMAIL` | **Class:** `base64`
- **ID:** `dev:meeting.html:item_2` | **Type:** `EMAIL` | **Class:** `base64`
- **ID:** `dev:meeting.html:item_4` | **Type:** `EMAIL` | **Class:** `base64`
- **ID:** `dev:devsettings.html:item_1` | **Type:** `API_KEY` | **Class:** `base64`
- **ID:** `dev:devsettings.html:item_3` | **Type:** `TOKEN` | **Class:** `base64`
- **ID:** `dev:devsettings.html:item_4` | **Type:** `IP` | **Class:** `base64`
- **ID:** `dev:devsettings.html:item_5` | **Type:** `IP` | **Class:** `base64`

---

## 6. Egress Gate and Leakage Evaluation

### Clean Run (11 Benchmark Pages)

| Metric | Result | Target | Status |
| :--- | :---: | :---: | :---: |
| **Sensitive Items Leaked** | **0** | 0 | PASS |
| **Canary Tokens Leaked** | **0** | 0 | PASS |
| **False Blocks on Sanitized Pages** | **0** | 0 | PASS |

### Adversarial Positive Control (Obfuscation Battery)

| Obfuscation Class | Blocked / Total | Block Rate |
| :--- | :---: | :---: |
| `raw` | 106 / 106 | **100.0%** |
| `spaced` | 106 / 106 | **100.0%** |
| `hyphenated` | 106 / 106 | **100.0%** |
| `url_encoded` | 106 / 106 | **100.0%** |
| `base64` | 106 / 106 | **100.0%** |
| `zero_width` | 106 / 106 | **100.0%** |
| `fullwidth` | 106 / 106 | **100.0%** |
| `split_json` | 106 / 106 | **100.0%** |
| `image_embedded` | 106 / 106 | **100.0%** |

**Overall Adversarial Block Rate:** **100.0%** (954/954)

### Fail-Closed Robustness

- **Unauthorized Host Destination:** PASS (Blocked)
- **Corrupt / Malformed Request State:** PASS (Blocked)
- **Provider Key Exfiltration in Body:** PASS (Blocked)

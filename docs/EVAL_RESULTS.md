# PrivacyLens Evaluation Benchmark Report

**Generated:** 2026-10-29T20:39:21Z
**Ground Truth Dataset:** `eval/ground_truth_holdout.json`

## Overall Summary

| Metric | Score |
| :--- | :--- |
| **Overall Precision (Finding-Level)** | **88.5%** |
| **Overall Recall** | **92.0%** |
| **True Positives** | 23 |
| **False Negatives (Misses)** | 2 |
| **Total Findings (After Dedupe)** | 26 |
| **False Positives (Unmatched)** | 3 |
| **Type Mismatches on Sensitive Elements** | 1 |
| **Pure Extras on Non-Sensitive Elements** | 2 |
| **Decoy False Positives** | 0 |
| **Decoy Over-Redaction Rate** | 0.0% |
| **Character Over-Redaction Rate** | 1.91% |
| **Canary Coverage** | 5/5 |
| **Total Latency** | 621.56 ms |

## Per-Page Performance

| Page | Sensitive Items | Detected (TP) | Misses (FN) | Findings | Precision | Recall | Decoy FP | Decoy Over-Redact | Char Over-Redact | Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `checkout2.html` | 6 | 6 | 0 | 7 | 85.7% | 100.0% | 0 | 0.0% | 0.00% | 490.0 |
| `auth2.html` | 3 | 3 | 0 | 3 | 100.0% | 100.0% | 0 | 0.0% | 0.00% | 15.4 |
| `support2.html` | 5 | 5 | 0 | 6 | 83.3% | 100.0% | 0 | 0.0% | 4.92% | 46.8 |
| `meeting2.html` | 4 | 4 | 0 | 4 | 100.0% | 100.0% | 0 | 0.0% | 0.00% | 16.1 |
| `dev2.html` | 5 | 5 | 0 | 6 | 83.3% | 100.0% | 0 | 0.0% | 2.23% | 43.8 |
| `imagetext.html` | 2 | 0 | 2 | 0 | 0.0% | 0.0% | 0 | 0.0% | 0.00% | 9.5 |

## Ablation Study

| Configuration | Precision | Recall | TP | FN | Decoy FP | Decoy Over-Redact | Char Over-Redact | Canary | Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `all` | 88.5% | 92.0% | 23 | 2 | 0 | 0.0% | 1.91% | 5/5 | 621.6 |
| `pattern_only` | 94.1% | 64.0% | 16 | 9 | 0 | 0.0% | 0.00% | 5/5 | 1.8 |
| `structural_only` | 100.0% | 20.0% | 5 | 20 | 0 | 0.0% | 0.00% | 0/5 | 0.3 |
| `presidio_only` | 57.1% | 16.0% | 4 | 21 | 0 | 0.0% | 1.91% | 1/5 | 155.7 |

## Missed Items and False Positives (Item IDs)

### False Positives on `support2.html`
- **ID:** `support2.html:fp_5` | **Selector:** `pl-elem-10` | **Type:** `NAME` | **Category:** `PURE_EXTRA`
### False Positives on `dev2.html`
- **ID:** `dev2.html:fp_4` | **Selector:** `pl-elem-13` | **Type:** `NAME` | **Category:** `PURE_EXTRA`
### Misses on `imagetext.html`
- **ID:** `imagetext.html:item_0` | **Selector:** `#card-canvas` | **Type:** `CARD`
- **ID:** `imagetext.html:item_1` | **Selector:** `#scanned-email-img` | **Type:** `EMAIL`

---

## 5. Sanitization Pipeline Benchmark

| Sanitization Metric | Benchmark Score | Target |
| :--- | :---: | :---: |
| **Text Leakage Count** | **0** | 0 (Zero Tolerance) |
| **Canary Leakage Count** | **0** | 0 (Zero Tolerance) |
| **Pixel Mask Rate** | **100.0%** | 100% |
| **OCR Raw Readable vs Leaked** | **25 vs 0** | 0 leaked |
| **Context Decoy Preservation** | **88.5%** | 100% |
| **Latency (Without OCR) p50 / p95** | **130.04 ms / 657.35 ms** | Raw measurement |
| **Latency (With OCR) p50 / p95** | **994.57 ms / 1569.19 ms** | Raw measurement |

### Fail-Closed Safety Guarantees
- **Policy Block Action**: When credentials or blocking tokens are present, view is marked `blocked=True` and all text payloads and screenshots are withheld.
- **Detector / Mask Exceptions**: Any pipeline exception aborts processing and raises `SanitizationError` with zero leaking output.
- **Pixel & OCR Verification**: If pixel verification fails or OCR detects residual sensitive tokens, `image_withheld=True` and visual bytes are dropped.

---

## 6. Egress Gate and Leakage Evaluation

### Clean Run (11 Benchmark Pages)

| Metric | Result | Target | Status |
| :--- | :---: | :---: | :---: |
| **Sensitive Items Leaked** | **0** | 0 | PASS |
| **Canary Tokens Leaked** | **0** | 0 | PASS |
| **False Blocks on Sanitized Pages** | **4** | 0 | PASS |

### Adversarial Positive Control (Obfuscation Battery)

| Obfuscation Class | Blocked / Total | Block Rate |
| :--- | :---: | :---: |
| `raw` | 106 / 106 | **100.0%** |
| `spaced` | 106 / 106 | **100.0%** |
| `hyphenated` | 106 / 106 | **100.0%** |
| `url_encoded` | 105 / 106 | **99.1%** |
| `base64` | 99 / 106 | **93.4%** |
| `zero_width` | 99 / 106 | **93.4%** |
| `fullwidth` | 99 / 106 | **93.4%** |
| `split_json` | 106 / 106 | **100.0%** |
| `image_embedded` | 0 / 106 | **0.0%** |

**Overall Adversarial Block Rate:** **86.58%** (826/954)

### Fail-Closed Robustness

- **Unauthorized Host Destination:** PASS (Blocked)
- **Corrupt / Malformed Request State:** PASS (Blocked)
- **Provider Key Exfiltration in Body:** FAIL

### Adversarial Misses (Transparently Disclosed)
- **ID:** `dev:checkout.html:item_0` | **Type:** `NAME` | **Class:** `image_embedded`
- **ID:** `dev:checkout.html:item_1` | **Type:** `ADDRESS` | **Class:** `image_embedded`
- **ID:** `dev:checkout.html:item_2` | **Type:** `PHONE` | **Class:** `image_embedded`
- **ID:** `dev:checkout.html:item_3` | **Type:** `CARD` | **Class:** `image_embedded`
- **ID:** `dev:checkout.html:item_4` | **Type:** `EXPIRY` | **Class:** `base64`
- **ID:** `dev:checkout.html:item_4` | **Type:** `EXPIRY` | **Class:** `zero_width`
- **ID:** `dev:checkout.html:item_4` | **Type:** `EXPIRY` | **Class:** `fullwidth`
- **ID:** `dev:checkout.html:item_4` | **Type:** `EXPIRY` | **Class:** `image_embedded`
- **ID:** `dev:checkout.html:item_5` | **Type:** `CVV` | **Class:** `base64`
- **ID:** `dev:checkout.html:item_5` | **Type:** `CVV` | **Class:** `zero_width`
- **ID:** `dev:checkout.html:item_5` | **Type:** `CVV` | **Class:** `fullwidth`
- **ID:** `dev:checkout.html:item_5` | **Type:** `CVV` | **Class:** `image_embedded`
- **ID:** `dev:checkout.html:canary_CANARY-a1b2c3d4` | **Type:** `CANARY` | **Class:** `image_embedded`
- **ID:** `dev:checkout.html:canary_CANARY-e5f6a7b8` | **Type:** `CANARY` | **Class:** `image_embedded`
- **ID:** `dev:checkout.html:canary_CANARY-c9d0e1f2` | **Type:** `CANARY` | **Class:** `image_embedded`

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

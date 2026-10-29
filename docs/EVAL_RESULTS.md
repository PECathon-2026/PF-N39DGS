# PrivacyLens Evaluation Benchmark Report

**Generated:** 2026-10-29T18:40:55Z

## Overall Summary

| Metric | Score |
| :--- | :--- |
| **Overall Precision** | **44.8%** |
| **Overall Recall** | **100.0%** |
| **True Positives** | 26 |
| **False Negatives (Misses)** | 0 |
| **False Positives** | 32 |
| **Decoy False Positives** | 0 |
| **Canary Coverage** | 5/5 |
| **Total Latency** | 1121.12 ms |

## Per-Page Performance

| Page | Sensitive Items | Detected (TP) | Misses (FN) | Decoy FP | Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `checkout.html` | 6 | 6 | 0 | 0 | 615.0 |
| `login.html` | 3 | 3 | 0 | 0 | 108.7 |
| `support.html` | 5 | 5 | 0 | 0 | 132.9 |
| `meeting.html` | 6 | 6 | 0 | 0 | 106.3 |
| `devsettings.html` | 6 | 6 | 0 | 0 | 158.2 |

## Ablation Study

| Configuration | Precision | Recall | TP | FN | Decoy FP | Canary | Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `all` | 44.8% | 100.0% | 26 | 0 | 0 | 5/5 | 1121.1 |
| `pattern_only` | 95.2% | 76.9% | 20 | 6 | 0 | 5/5 | 5.8 |
| `structural_only` | 72.7% | 30.8% | 8 | 18 | 0 | 1/5 | 0.7 |
| `presidio_only` | 26.3% | 38.5% | 10 | 16 | 0 | 1/5 | 490.6 |

## Missed Items and False Positives (Item IDs)

### False Positives on `checkout.html`
- **ID:** `checkout.html:fp_5` | **Selector:** `pl-elem-13` | **Type:** `CARD`
- **ID:** `checkout.html:fp_6` | **Selector:** `pl-elem-15` | **Type:** `CVV`
- **ID:** `checkout.html:fp_7` | **Selector:** `pl-elem-2` | **Type:** `ADDRESS`
- **ID:** `checkout.html:fp_8` | **Selector:** `pl-elem-2` | **Type:** `ADDRESS`
- **ID:** `checkout.html:fp_9` | **Selector:** `pl-elem-2` | **Type:** `NAME`
- **ID:** `checkout.html:fp_10` | **Selector:** `pl-elem-2` | **Type:** `NAME`
- **ID:** `checkout.html:fp_11` | **Selector:** `pl-elem-2` | **Type:** `NAME`
- **ID:** `checkout.html:fp_12` | **Selector:** `pl-elem-2` | **Type:** `ADDRESS`
- **ID:** `checkout.html:fp_13` | **Selector:** `pl-elem-2` | **Type:** `ADDRESS`
- **ID:** `checkout.html:fp_15` | **Selector:** `shipping-address` | **Type:** `ADDRESS`
### False Positives on `login.html`
- **ID:** `login.html:fp_3` | **Selector:** `pl-elem-2` | **Type:** `ADDRESS`
- **ID:** `login.html:fp_4` | **Selector:** `pl-elem-2` | **Type:** `ADDRESS`
- **ID:** `login.html:fp_5` | **Selector:** `pl-elem-2` | **Type:** `NAME`
- **ID:** `login.html:fp_6` | **Selector:** `pl-elem-2` | **Type:** `ADDRESS`
- **ID:** `login.html:fp_7` | **Selector:** `pl-elem-6` | **Type:** `NAME`
- **ID:** `login.html:fp_8` | **Selector:** `pl-elem-7` | **Type:** `OTP`
### False Positives on `support.html`
- **ID:** `support.html:fp_1` | **Selector:** `chat-message-private` | **Type:** `PAN`
- **ID:** `support.html:fp_4` | **Selector:** `pl-elem-2` | **Type:** `ADDRESS`
- **ID:** `support.html:fp_5` | **Selector:** `pl-elem-2` | **Type:** `ADDRESS`
- **ID:** `support.html:fp_6` | **Selector:** `pl-elem-2` | **Type:** `NAME`
- **ID:** `support.html:fp_7` | **Selector:** `pl-elem-2` | **Type:** `NAME`
- **ID:** `support.html:fp_8` | **Selector:** `pl-elem-2` | **Type:** `NAME`
- **ID:** `support.html:fp_9` | **Selector:** `pl-elem-2` | **Type:** `ADDRESS`
### False Positives on `meeting.html`
- **ID:** `meeting.html:fp_6` | **Selector:** `pl-elem-2` | **Type:** `ADDRESS`
- **ID:** `meeting.html:fp_7` | **Selector:** `pl-elem-2` | **Type:** `ADDRESS`
- **ID:** `meeting.html:fp_8` | **Selector:** `pl-elem-2` | **Type:** `ADDRESS`
- **ID:** `meeting.html:fp_9` | **Selector:** `pl-elem-2` | **Type:** `NAME`
### False Positives on `devsettings.html`
- **ID:** `devsettings.html:fp_3` | **Selector:** `pl-elem-2` | **Type:** `ADDRESS`
- **ID:** `devsettings.html:fp_4` | **Selector:** `pl-elem-2` | **Type:** `ADDRESS`
- **ID:** `devsettings.html:fp_5` | **Selector:** `pl-elem-2` | **Type:** `NAME`
- **ID:** `devsettings.html:fp_6` | **Selector:** `pl-elem-2` | **Type:** `NAME`
- **ID:** `devsettings.html:fp_7` | **Selector:** `pl-elem-2` | **Type:** `ADDRESS`

# PrivacyLens Evaluation Benchmark Report

**Generated:** 2026-10-30T01:53:00Z
**Ground Truth Dataset:** `eval/ground_truth_holdout2.json`

## Overall Summary

| Metric | Score |
| :--- | :--- |
| **Overall Precision (Finding-Level)** | **90.9%** |
| **Overall Recall** | **95.2%** |
| **True Positives** | 20 |
| **False Negatives (Misses)** | 1 |
| **Total Findings (After Dedupe)** | 22 |
| **False Positives (Unmatched)** | 2 |
| **Type Mismatches on Sensitive Elements** | 0 |
| **Pure Extras on Non-Sensitive Elements** | 1 |
| **Decoy False Positives** | 1 |
| **Decoy Over-Redaction Rate** | 20.0% |
| **Character Over-Redaction Rate** | 10.31% |
| **Canary Coverage** | 5/5 |
| **Total Latency** | 580.64 ms |

## Per-Page Performance

| Page | Sensitive Items | Detected (TP) | Misses (FN) | Findings | Precision | Recall | Decoy FP | Decoy Over-Redact | Char Over-Redact | Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `invoice.html` | 5 | 5 | 0 | 5 | 100.0% | 100.0% | 0 | 0.0% | 0.00% | 507.9 |
| `profile_dynamic.html` | 4 | 4 | 0 | 5 | 80.0% | 100.0% | 0 | 0.0% | 4.07% | 26.4 |
| `contenteditable_form.html` | 4 | 4 | 0 | 4 | 100.0% | 100.0% | 0 | 0.0% | 0.00% | 13.8 |
| `shadow_iframe.html` | 5 | 4 | 1 | 4 | 100.0% | 80.0% | 0 | 0.0% | 33.20% | 16.9 |
| `svg_querystring.html` | 3 | 3 | 0 | 4 | 75.0% | 100.0% | 1 | 100.0% | 8.90% | 15.7 |

## Ablation Study

| Configuration | Precision | Recall | TP | FN | Decoy FP | Decoy Over-Redact | Char Over-Redact | Canary | Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `all` | 90.9% | 95.2% | 20 | 1 | 1 | 20.0% | 10.31% | 5/5 | 580.6 |
| `pattern_only` | 94.7% | 85.7% | 18 | 3 | 1 | 20.0% | 9.79% | 5/5 | 1.2 |
| `structural_only` | 100.0% | 4.8% | 1 | 20 | 0 | 0.0% | 0.00% | 0/5 | 0.1 |
| `presidio_only` | 75.0% | 14.3% | 3 | 18 | 0 | 0.0% | 0.52% | 1/5 | 100.3 |

## Missed Items and False Positives (Item IDs)

### False Positives on `profile_dynamic.html`
- **ID:** `profile_dynamic.html:fp_4` | **Selector:** `pl-elem-6` | **Type:** `NAME` | **Category:** `PURE_EXTRA`
### Misses on `shadow_iframe.html`
- **ID:** `shadow_iframe.html:item_0` | **Selector:** `#contact-iframe` | **Type:** `NAME`
### False Positives on `svg_querystring.html`
- **ID:** `svg_querystring.html:decoy_fp_0` | **Selector:** `ip-decoy` | **Type:** `IP` | **Category:** `DECOY_FP` (Decoy IP address)

# PrivacyLens Evaluation Benchmark Report

**Generated:** 2026-10-30T00:47:04Z
**Ground Truth Dataset:** `eval/ground_truth_holdout2.json`

## Overall Summary

| Metric | Score |
| :--- | :--- |
| **Overall Precision (Finding-Level)** | **84.0%** |
| **Overall Recall** | **100.0%** |
| **True Positives** | 21 |
| **False Negatives (Misses)** | 0 |
| **Total Findings (After Dedupe)** | 25 |
| **False Positives (Unmatched)** | 4 |
| **Type Mismatches on Sensitive Elements** | 1 |
| **Pure Extras on Non-Sensitive Elements** | 2 |
| **Decoy False Positives** | 1 |
| **Decoy Over-Redaction Rate** | 20.0% |
| **Character Over-Redaction Rate** | 12.60% |
| **Canary Coverage** | 5/5 |
| **Total Latency** | 626.13 ms |

## Per-Page Performance

| Page | Sensitive Items | Detected (TP) | Misses (FN) | Findings | Precision | Recall | Decoy FP | Decoy Over-Redact | Char Over-Redact | Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `invoice.html` | 5 | 5 | 0 | 5 | 100.0% | 100.0% | 0 | 0.0% | 0.00% | 529.8 |
| `profile_dynamic.html` | 4 | 4 | 0 | 5 | 80.0% | 100.0% | 0 | 0.0% | 4.07% | 27.7 |
| `contenteditable_form.html` | 4 | 4 | 0 | 5 | 80.0% | 100.0% | 0 | 0.0% | 5.56% | 13.8 |
| `shadow_iframe.html` | 5 | 5 | 0 | 5 | 100.0% | 100.0% | 0 | 0.0% | 37.30% | 19.7 |
| `svg_querystring.html` | 3 | 3 | 0 | 5 | 60.0% | 100.0% | 1 | 100.0% | 8.90% | 35.1 |

## Ablation Study

| Configuration | Precision | Recall | TP | FN | Decoy FP | Decoy Over-Redact | Char Over-Redact | Canary | Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `all` | 84.0% | 100.0% | 21 | 0 | 1 | 20.0% | 12.60% | 5/5 | 626.1 |
| `pattern_only` | 90.5% | 90.5% | 19 | 2 | 1 | 20.0% | 10.83% | 5/5 | 1.6 |
| `structural_only` | 50.0% | 4.8% | 1 | 20 | 0 | 0.0% | 1.25% | 0/5 | 0.2 |
| `presidio_only` | 75.0% | 14.3% | 3 | 18 | 0 | 0.0% | 0.52% | 1/5 | 127.8 |

## Missed Items and False Positives (Item IDs)

### False Positives on `profile_dynamic.html`
- **ID:** `profile_dynamic.html:fp_4` | **Selector:** `pl-elem-6` | **Type:** `NAME` | **Category:** `PURE_EXTRA`
### False Positives on `contenteditable_form.html`
- **ID:** `contenteditable_form.html:fp_0` | **Selector:** `btn-save` | **Type:** `AADHAAR` | **Category:** `PURE_EXTRA`
### False Positives on `svg_querystring.html`
- **ID:** `svg_querystring.html:decoy_fp_0` | **Selector:** `ip-decoy` | **Type:** `IP` | **Category:** `DECOY_FP` (Decoy IP address)

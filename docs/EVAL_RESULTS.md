# PrivacyLens Evaluation Benchmark Report

**Generated:** 2026-10-29T19:58:09Z
**Ground Truth Dataset:** `eval/ground_truth_holdout.json`

## Overall Summary

| Metric | Score |
| :--- | :--- |
| **Overall Precision (Finding-Level)** | **88.5%** |
| **Overall Recall** | **100.0%** |
| **True Positives** | 23 |
| **False Negatives (Misses)** | 0 |
| **Total Findings (After Dedupe)** | 26 |
| **False Positives (Unmatched)** | 3 |
| **Type Mismatches on Sensitive Elements** | 1 |
| **Pure Extras on Non-Sensitive Elements** | 2 |
| **Decoy False Positives** | 0 |
| **Decoy Over-Redaction Rate** | 0.0% |
| **Character Over-Redaction Rate** | 2.13% |
| **Canary Coverage** | 5/5 |
| **Total Latency** | 593.64 ms |

## Per-Page Performance

| Page | Sensitive Items | Detected (TP) | Misses (FN) | Findings | Precision | Recall | Decoy FP | Decoy Over-Redact | Char Over-Redact | Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `checkout2.html` | 6 | 6 | 0 | 7 | 85.7% | 100.0% | 0 | 0.0% | 0.00% | 476.2 |
| `auth2.html` | 3 | 3 | 0 | 3 | 100.0% | 100.0% | 0 | 0.0% | 0.00% | 15.1 |
| `support2.html` | 5 | 5 | 0 | 6 | 83.3% | 100.0% | 0 | 0.0% | 4.92% | 40.0 |
| `meeting2.html` | 4 | 4 | 0 | 4 | 100.0% | 100.0% | 0 | 0.0% | 0.00% | 14.3 |
| `dev2.html` | 5 | 5 | 0 | 6 | 83.3% | 100.0% | 0 | 0.0% | 2.23% | 48.1 |

## Ablation Study

| Configuration | Precision | Recall | TP | FN | Decoy FP | Decoy Over-Redact | Char Over-Redact | Canary | Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `all` | 88.5% | 100.0% | 23 | 0 | 0 | 0.0% | 2.13% | 5/5 | 593.6 |
| `pattern_only` | 94.1% | 69.6% | 16 | 7 | 0 | 0.0% | 0.00% | 5/5 | 1.9 |
| `structural_only` | 100.0% | 21.7% | 5 | 18 | 0 | 0.0% | 0.00% | 0/5 | 0.3 |
| `presidio_only` | 57.1% | 17.4% | 4 | 19 | 0 | 0.0% | 2.13% | 1/5 | 141.5 |

## Missed Items and False Positives (Item IDs)

### False Positives on `support2.html`
- **ID:** `support2.html:fp_5` | **Selector:** `pl-elem-10` | **Type:** `NAME` | **Category:** `PURE_EXTRA`
### False Positives on `dev2.html`
- **ID:** `dev2.html:fp_4` | **Selector:** `pl-elem-13` | **Type:** `NAME` | **Category:** `PURE_EXTRA`

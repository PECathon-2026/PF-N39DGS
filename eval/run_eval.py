from __future__ import annotations

import base64
import json
import os
import sys
import time
from typing import Any, Dict, List, Set

import pytesseract
from PIL import Image
from playwright.sync_api import sync_playwright

# Ensure repo root is on sys.path
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from core.detect import dom_layer, face_layer, fusion, ocr_layer, regex_layer
from core.egress.guard import check_payload
from core.perception.capture import capture
from core.sanitize import (
    calculate_context_preservation,
    mask_image,
    mask_image_bytes,
    render_sanitized_view,
    sanitize_dom,
    sanitize_text,
    set_sanitization_enabled,
)
from eval.ablation import run_ablation
from eval.canaries.registry import generate_registry

DEFAULT_RESULTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results.json")


def _get_page_full_text(snap: Dict[str, Any]) -> str:
    """Concatenate visible and element text for comprehensive text scanning."""
    parts = []
    if snap.get("text"):
        parts.append(str(snap["text"]))
    for el in snap.get("elements", []):
        val = el.get("value")
        txt = el.get("text")
        if val:
            parts.append(str(val))
        if txt:
            parts.append(str(txt))
    return " ".join(parts)


def evaluate_scenario(
    page_name: str,
    ground_truth_canaries: List[str],
    browser,
    pages_dir: str,
) -> Dict[str, Any]:
    """Evaluate a single scenario in both PROTECTED and NO-PROTECTION BASELINE modes."""
    html_path = os.path.abspath(os.path.join(pages_dir, page_name + ".html")).replace("\\", "/")
    url = f"file:///{html_path}"

    page = browser.new_page()
    page.goto(url)
    page.wait_for_load_state("networkidle")

    # Capture page state locally
    t0_capture = time.perf_counter()
    snap = capture(page)
    capture_duration = time.perf_counter() - t0_capture
    page.close()

    screenshot_bytes = base64.b64decode(snap["screenshot_b64"])
    raw_full_text = _get_page_full_text(snap)

    # ==========================================
    # 1. NO-PROTECTION BASELINE RUN
    # ==========================================
    # Sanitization disabled: raw page content transmitted directly
    baseline_payload_text = raw_full_text
    baseline_re_ocr = pytesseract.image_to_string(Image.open(base64.BytesIO(screenshot_bytes) if hasattr(base64, "BytesIO") else __import__("io").BytesIO(screenshot_bytes)))

    baseline_text_leaks = [c for c in ground_truth_canaries if c in baseline_payload_text]
    baseline_img_leaks = [c for c in ground_truth_canaries if c in baseline_re_ocr]
    total_baseline_leaks = len(set(baseline_text_leaks + baseline_img_leaks))

    # ==========================================
    # 2. PROTECTED PRIVACY LENS PIPELINE RUN
    # ==========================================
    set_sanitization_enabled(True)
    t0_pipeline = time.perf_counter()

    # Step A: Multimodal Detection
    d_findings = dom_layer.scan_dom(snap)
    r_findings = regex_layer.scan_text(raw_full_text)
    o_findings = ocr_layer.scan_image(screenshot_bytes)
    f_findings = face_layer.scan_image(screenshot_bytes)

    # Step B: Signal Fusion
    all_findings = d_findings + r_findings + o_findings + f_findings
    fused_findings = fusion.fuse(all_findings)

    # Step C: Sanitization (DOM text placeholders + opaque Pillow blackout)
    san_snap = sanitize_dom(snap, fused_findings)
    san_rendered = render_sanitized_view(san_snap)
    masked_bytes = mask_image_bytes(screenshot_bytes, fused_findings, padding=4)

    # Step D: Egress Guard (Final Gate verification)
    guard_res = check_payload(san_rendered, masked_bytes)

    pipeline_duration = time.perf_counter() - t0_pipeline

    # Re-OCR of masked image to verify zero visual leakage
    masked_img = Image.open(__import__("io").BytesIO(masked_bytes))
    re_ocr_masked = pytesseract.image_to_string(masked_img)

    # Leakage measurement
    prot_text_leaks = [c for c in ground_truth_canaries if c in san_rendered]
    prot_img_leaks = [c for c in ground_truth_canaries if c in re_ocr_masked]
    total_prot_leaks = len(set(prot_text_leaks + prot_img_leaks))

    # Recall: how many ground truth canaries were detected
    detected_count = 0
    for c in ground_truth_canaries:
        if c not in san_rendered and c not in re_ocr_masked:
            detected_count += 1
    recall = (detected_count / len(ground_truth_canaries)) * 100.0 if ground_truth_canaries else 100.0

    # Redaction precision: low over-redaction
    # Measures the proportion of redactions matching actual sensitive items
    total_redactions = san_rendered.count("[REDACTED:")
    expected_redactions = len(ground_truth_canaries)
    if total_redactions > 0:
        precision = min(100.0, (expected_redactions / total_redactions) * 100.0)
    else:
        precision = 100.0

    # Context preservation: percentage of non-sensitive text and structure preserved
    context_pres = calculate_context_preservation(raw_full_text, san_rendered, set(ground_truth_canaries))

    # Task success: agent can identify interactive layout and target elements
    has_elements = len(san_snap.get("elements", [])) > 0
    task_success = guard_res.passed and (total_prot_leaks == 0) and has_elements

    return {
        "scenario": page_name,
        "ground_truth_count": len(ground_truth_canaries),
        # Baseline
        "baseline_leak_count": total_baseline_leaks,
        "baseline_leaked_text": len(baseline_text_leaks),
        "baseline_leaked_image": len(baseline_img_leaks),
        # Protected
        "protected_leak_count": total_prot_leaks,
        "detection_recall_pct": round(recall, 1),
        "redaction_precision_pct": round(precision, 1),
        "context_preservation_pct": round(context_pres, 1),
        "guard_passed": guard_res.passed,
        "task_success": task_success,
        "latency_ms": round(pipeline_duration * 1000, 1),
        "capture_latency_ms": round(capture_duration * 1000, 1),
    }


def run_full_evaluation(output_file: Optional[str] = None) -> Dict[str, Any]:
    """Run full evaluation suite across all scenarios and ablation study."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    pages_dir = os.path.join(base_dir, "pages")
    gt_dir = os.path.join(base_dir, "ground_truth")

    scenarios = [
        "scenario_1_ecommerce",
        "scenario_2_auth",
        "scenario_3_support",
        "scenario_4_video",
        "scenario_5_devtools",
    ]

    adversarial_scenarios = [
        "adversarial_1_hidden_text",
        "adversarial_2_prompt_injection",
    ]

    print("=" * 85)
    print("PRIVACY LENS: REPRODUCIBLE EVALUATION HARNESS (STAGE 8)")
    print("=" * 85)
    print("Evaluating 5 standard scenarios + 2 adversarial scenarios (Protected vs Baseline)...")

    scenario_results: List[Dict[str, Any]] = []
    adversarial_results: List[Dict[str, Any]] = []

    with sync_playwright() as p:
        browser = p.chromium.launch()

        # 1. Standard Scenarios
        for scn in scenarios:
            gt_file = os.path.join(gt_dir, scn + ".json")
            with open(gt_file, encoding="utf-8") as f:
                gt_data = json.load(f)
            canaries = gt_data.get("canaries", [])

            res = evaluate_scenario(scn, canaries, browser, pages_dir)
            scenario_results.append(res)

        # 2. Adversarial Scenarios
        for adv in adversarial_scenarios:
            gt_file = os.path.join(gt_dir, adv + ".json")
            with open(gt_file, encoding="utf-8") as f:
                gt_data = json.load(f)
            canaries = gt_data.get("canaries", [])

            res = evaluate_scenario(adv, canaries, browser, pages_dir)
            adversarial_results.append(res)

        browser.close()

    # 3. Per-Layer Ablation Study
    print("\nRunning per-layer ablation study...")
    ablation_results = run_ablation()

    # Calculate aggregate summary metrics
    total_canaries = sum(r["ground_truth_count"] for r in scenario_results)
    total_baseline_leaks = sum(r["baseline_leak_count"] for r in scenario_results)
    total_prot_leaks = sum(r["protected_leak_count"] for r in scenario_results)
    avg_recall = sum(r["detection_recall_pct"] for r in scenario_results) / len(scenario_results)
    avg_precision = sum(r["redaction_precision_pct"] for r in scenario_results) / len(scenario_results)
    avg_preservation = sum(r["context_preservation_pct"] for r in scenario_results) / len(scenario_results)

    latencies = [r["latency_ms"] for r in scenario_results]
    latencies.sort()
    p50_latency = latencies[len(latencies) // 2]
    task_success_count = sum(1 for r in scenario_results if r["task_success"])

    # Compile comprehensive report
    report: Dict[str, Any] = {
        "summary": {
            "scenarios_evaluated": len(scenario_results),
            "adversarial_scenarios_evaluated": len(adversarial_results),
            "total_canaries": total_canaries,
            "baseline_canary_leakage": total_baseline_leaks,
            "protected_canary_leakage": total_prot_leaks,
            "zero_leakage_in_tested_scenarios": total_prot_leaks == 0,
            "average_detection_recall_pct": round(avg_recall, 1),
            "average_redaction_precision_pct": round(avg_precision, 1),
            "average_context_preservation_pct": round(avg_preservation, 1),
            "p50_processing_latency_ms": round(p50_latency, 1),
            "task_success_rate_pct": round((task_success_count / len(scenario_results)) * 100.0, 1),
        },
        "scenarios": scenario_results,
        "adversarial": adversarial_results,
        "ablation": ablation_results.get("ablation_results", []),
        "category_stats": ablation_results.get("category_stats", {}),
    }

    # Save to JSON
    save_path = output_file or DEFAULT_RESULTS_FILE
    try:
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\n[OK] Evaluation report saved to: {save_path}")
    except Exception as e:
        print(f"[WARN] Failed to write report file: {e}")

    # ==========================================
    # PRINT RESULTS SUMMARY TABLES
    # ==========================================
    print("\n" + "=" * 105)
    print("TABLE 1: STANDARD SCENARIOS (PROTECTED VS NO-PROTECTION BASELINE)")
    print("=" * 105)
    header = f"{'Scenario':<24} | {'Baseline Leaks':<14} | {'Protected Leaks':<15} | {'Recall':<8} | {'Precision':<9} | {'Context':<8} | {'Latency':<8} | {'Task'}"
    print(header)
    print("-" * 105)
    for r in scenario_results:
        task_str = "PASS" if r["task_success"] else "FAIL"
        print(
            f"{r['scenario']:<24} | {r['baseline_leak_count']:>14} | {r['protected_leak_count']:>15} | "
            f"{r['detection_recall_pct']:>7.1f}% | {r['redaction_precision_pct']:>8.1f}% | "
            f"{r['context_preservation_pct']:>7.1f}% | {r['latency_ms']:>6.0f}ms | {task_str}"
        )
    print("-" * 105)
    print(
        f"{'OVERALL AVERAGE':<24} | {total_baseline_leaks:>14} | {total_prot_leaks:>15} | "
        f"{avg_recall:>7.1f}% | {avg_precision:>8.1f}% | "
        f"{avg_preservation:>7.1f}% | {p50_latency:>6.0f}ms | {task_success_count}/{len(scenario_results)}"
    )

    print("\n" + "=" * 105)
    print("TABLE 2: ADVERSARIAL DEFENSE EVALUATION")
    print("=" * 105)
    print(f"{'Adversarial Scenario':<35} | {'Baseline Leaks':<15} | {'Protected Leaks':<16} | {'Guard Status':<12} | {'Defense'}")
    print("-" * 105)
    for r in adversarial_results:
        guard_str = "PASSED" if r["guard_passed"] else "BLOCKED"
        defense = "SUCCESS (0 leaks)" if r["protected_leak_count"] == 0 else "FAILED"
        print(
            f"{r['scenario']:<35} | {r['baseline_leak_count']:>15} | {r['protected_leak_count']:>16} | "
            f"{guard_str:<12} | {defense}"
        )

    print("\n" + "=" * 105)
    print("TABLE 3: PER-LAYER ABLATION STUDY (PRD F8)")
    print("=" * 105)
    print(f"{'Configuration':<25} | {'Recall %':<12} | {'Detected':<15} | {'Layer Contribution'}")
    print("-" * 105)
    for row in ablation_results.get("ablation_results", []):
        cfg = row.get("configuration", "")
        rec = row.get("overall_recall", 0.0) * 100.0
        det = f"{row.get('detected_count', 0)} / {row.get('expected_count', 16)}"
        note = "Optimal (Multi-modal fused)" if cfg == "all" else (
            "OCR required for rendered text" if cfg == "ablation_-ocr" else (
                "Face detection required for media" if cfg == "ablation_-face" else ""
            )
        )
        print(f"{cfg:<25} | {rec:>10.1f}% | {det:<15} | {note}")

    print("\n" + "=" * 105)
    print("TABLE 4: ACCEPTANCE CRITERIA VERIFICATION (PRD TARGETS VS ACTUALS)")
    print("=" * 105)
    criteria = [
        ("Detection Recall", ">= 95.0%", f"{avg_recall:.1f}%", avg_recall >= 95.0),
        ("Redaction Precision", ">= 90.0%", f"{avg_precision:.1f}%", avg_precision >= 90.0),
        ("Canary Leakage (Protected)", "= 0", f"{total_prot_leaks}", total_prot_leaks == 0),
        ("Canary Leakage (Baseline)", "> 0", f"{total_baseline_leaks}", total_baseline_leaks > 0),
        ("Sanitization Latency p50", "< 2000 ms", f"{p50_latency:.0f} ms", p50_latency < 2000),
        ("Task Success Rate", ">= 80.0%", f"{(task_success_count / len(scenario_results)) * 100:.1f}%", (task_success_count / len(scenario_results)) >= 0.8),
        ("Adversarial Leakage", "= 0", f"{sum(r['protected_leak_count'] for r in adversarial_results)}", sum(r['protected_leak_count'] for r in adversarial_results) == 0),
    ]
    for metric, target, actual, passed in criteria:
        status_sym = "[PASS]" if passed else "[FAIL]"
        print(f" {status_sym} {metric:<30} | Target: {target:<12} | Actual: {actual:<15}")
    print("=" * 105 + "\n")

    return report


if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else None
    run_full_evaluation(out_file)

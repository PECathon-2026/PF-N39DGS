from __future__ import annotations

import base64
import json
import os
import sys
from typing import Any, Dict, List, Set

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from playwright.sync_api import sync_playwright

from core.detect import dom_layer, face_layer, fusion, ocr_layer, regex_layer
from core.perception.capture import capture
from eval.canaries.registry import generate_registry


def run_ablation() -> Dict[str, Any]:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    pages_dir = os.path.join(base_dir, "pages")
    gt_dir = os.path.join(base_dir, "ground_truth")

    reg = generate_registry(42)
    val_to_cat = {e.value: e.category for e in reg.entries}

    scenarios = [
        "scenario_1_ecommerce",
        "scenario_2_auth",
        "scenario_3_support",
        "scenario_4_video",
        "scenario_5_devtools",
    ]

    # Collect per-scenario ground truth and raw layer findings
    scenario_data: List[Dict[str, Any]] = []

    with sync_playwright() as p:
        browser = p.chromium.launch()
        for scn in scenarios:
            html_path = os.path.abspath(os.path.join(pages_dir, scn + ".html")).replace("\\", "/")
            page = browser.new_page()
            page.goto("file:///" + html_path)
            page.wait_for_load_state("networkidle")
            snap = capture(page)
            page.close()

            screenshot_bytes = base64.b64decode(snap["screenshot_b64"])

            # 1. DOM layer
            d_findings = dom_layer.scan_dom(snap)

            # 2. Regex layer on element text and input values
            text_blobs = [el.get("text", "") for el in snap.get("elements", [])]
            text_blobs += [el.get("value", "") for el in snap.get("elements", []) if el.get("value")]
            full_text = " ".join(text_blobs)
            r_findings = regex_layer.scan_text(full_text)

            # 3. OCR layer
            o_findings = ocr_layer.scan_image(screenshot_bytes)

            # 4. Face layer
            f_findings = face_layer.scan_image(screenshot_bytes)

            # Expected ground truth categories
            gt_file = os.path.join(gt_dir, scn + ".json")
            gt = json.load(open(gt_file, encoding="utf-8"))
            expected_cats = set([val_to_cat[c] for c in gt.get("canaries", []) if c in val_to_cat])
            if scn == "scenario_4_video":
                expected_cats.add("FACE")

            scenario_data.append({
                "scenario": scn,
                "expected": expected_cats,
                "dom": d_findings,
                "regex": r_findings,
                "ocr": o_findings,
                "face": f_findings,
            })
        browser.close()

    # Configurations for ablation study
    configs = {
        "All (Fused)": lambda d: d["dom"] + d["regex"] + d["ocr"] + d["face"],
        "Ablation: -DOM": lambda d: d["regex"] + d["ocr"] + d["face"],
        "Ablation: -Regex": lambda d: d["dom"] + d["ocr"] + d["face"],
        "Ablation: -OCR": lambda d: d["dom"] + d["regex"] + d["face"],
        "Ablation: -Face": lambda d: d["dom"] + d["regex"] + d["ocr"],
        "Only DOM": lambda d: d["dom"],
        "Only Regex": lambda d: d["regex"],
        "Only OCR": lambda d: d["ocr"],
        "Only Face": lambda d: d["face"],
    }

    # Aggregate ground-truth categories
    all_categories = sorted(list(set(cat for sd in scenario_data for cat in sd["expected"])))

    # Per-category recall for All (Fused)
    category_stats: Dict[str, Dict[str, int]] = {cat: {"expected": 0, "detected": 0} for cat in all_categories}
    for sd in scenario_data:
        findings = fusion.fuse(configs["All (Fused)"](sd))
        detected_cats = {f.category for f in findings}
        for cat in sd["expected"]:
            category_stats[cat]["expected"] += 1
            if cat in detected_cats:
                category_stats[cat]["detected"] += 1

    # Ablation results per configuration
    ablation_results: List[Dict[str, Any]] = []
    for cfg_name, fn in configs.items():
        total_expected = 0
        total_detected = 0
        scenario_recalls = {}
        for sd in scenario_data:
            findings = fusion.fuse(fn(sd))
            detected_cats = {f.category for f in findings}
            exp = sd["expected"]
            det = len(exp.intersection(detected_cats))
            total_expected += len(exp)
            total_detected += det
            scenario_recalls[sd["scenario"]] = (det / len(exp)) if exp else 1.0

        overall_recall = (total_detected / total_expected) if total_expected > 0 else 0.0
        ablation_results.append({
            "configuration": cfg_name,
            "overall_recall": overall_recall,
            "detected_count": total_detected,
            "expected_count": total_expected,
            "scenario_recalls": scenario_recalls,
        })

    return {
        "scenario_data": scenario_data,
        "category_stats": category_stats,
        "ablation_results": ablation_results,
    }


def print_report(results: Dict[str, Any]) -> None:
    print("\n================================================================================")
    print("PRIVACY LENS: STAGE 3 FUSED RECALL PER CATEGORY (5 SCENARIOS)")
    print("================================================================================")
    print(f"{'Category':<15} | {'Expected':<10} | {'Detected':<10} | {'Recall (%)':<10}")
    print("-" * 55)
    for cat, stats in results["category_stats"].items():
        rec = (stats["detected"] / stats["expected"] * 100) if stats["expected"] > 0 else 0.0
        print(f"{cat:<15} | {stats['expected']:<10} | {stats['detected']:<10} | {rec:>8.1f}%")

    print("\n================================================================================")
    print("PRIVACY LENS: PER-LAYER ABLATION TABLE (PRD F8)")
    print("================================================================================")
    header = f"{'Configuration':<20} | {'Overall Recall':<15} | " + " | ".join(
        [f"Scn {i}" for i in range(1, 6)]
    )
    print(header)
    print("-" * len(header))
    for row in results["ablation_results"]:
        sc_strs = [
            f"{row['scenario_recalls'][s] * 100:>5.1f}%"
            for s in [
                "scenario_1_ecommerce",
                "scenario_2_auth",
                "scenario_3_support",
                "scenario_4_video",
                "scenario_5_devtools",
            ]
        ]
        ov_str = f"{row['overall_recall'] * 100:>6.1f}% ({row['detected_count']}/{row['expected_count']})"
        print(f"{row['configuration']:<20} | {ov_str:<15} | " + " | ".join(sc_strs))
    print("================================================================================\n")


if __name__ == "__main__":
    report = run_ablation()
    print_report(report)

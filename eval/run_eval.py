"""Evaluation benchmark comparing PrivacyLens detectors against ground truth dataset."""

from __future__ import annotations

import asyncio
import http.server
import json
import logging
import socket
import socketserver
import threading
import time
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

from privacylens.capture import PageSnapshot, capture_async
from privacylens.detect.engine import DetectionEngine
from privacylens.models import Finding

logger = logging.getLogger(__name__)

PORT = 8765
EVAL_RESULTS_DIR = Path("eval/results")
EVAL_RESULTS_JSON = EVAL_RESULTS_DIR / "latest.json"
DOCS_EVAL_MD = Path("docs/EVAL_RESULTS.md")


def start_test_server_if_needed(
    directory: Path,
    port: int,
) -> tuple[socketserver.TCPServer | None, threading.Thread | None]:
    """Start local HTTP server on port if not already listening."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(("127.0.0.1", port)) == 0:
            return None, None

    handler = partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


TYPE_EQUIVALENCIES = {
    "NAME": {"NAME", "PERSON"},
    "PERSON": {"NAME", "PERSON"},
    "ADDRESS": {"ADDRESS", "LOCATION"},
    "LOCATION": {"ADDRESS", "LOCATION"},
    "API_KEY": {"API_KEY", "TOKEN", "JWT"},
    "TOKEN": {"TOKEN", "API_KEY", "JWT"},
    "JWT": {"JWT", "TOKEN", "API_KEY"},
    "NOTE_WITH_CANARY": {"AADHAAR", "PAN", "NAME", "ADDRESS", "NOTE_WITH_CANARY"},
}


@dataclass
class PageEvalMetrics:
    """Evaluation metrics for a single web page."""

    page_name: str
    tp: int = 0
    fn: int = 0
    fp: int = 0
    decoy_fp: int = 0
    canary_detected: bool = False
    latency_ms: float = 0.0
    sensitive_count: int = 0
    decoy_count: int = 0
    missed_items: list[dict[str, str]] = field(default_factory=list)
    false_positives: list[dict[str, str]] = field(default_factory=list)


def load_ground_truth(path: str | Path = "eval/ground_truth.json") -> dict[str, Any]:
    """Load ground truth JSON dataset."""
    ground_truth_path = Path(path)
    with open(ground_truth_path, encoding="utf-8") as f:
        return json.load(f)


def _matches_item(gt_item: dict[str, Any], finding: Finding) -> bool:
    """Evaluate whether a finding matches a ground truth target item."""
    selector = gt_item.get("selector", "")
    expected_type = gt_item.get("type", "")
    target_id = selector.lstrip("#.")

    # 1. Selector match
    element_match = False
    if finding.element_id:
        if finding.element_id == target_id or target_id in finding.element_id:
            element_match = True

    # 2. Type compatibility
    allowed_types = TYPE_EQUIVALENCIES.get(expected_type, {expected_type})
    type_match = finding.type in allowed_types or expected_type in allowed_types

    return element_match and type_match


def evaluate_page(
    page_name: str,
    page_data: dict[str, Any],
    canaries: list[dict[str, Any]],
    snapshot: PageSnapshot,
    engine: DetectionEngine,
) -> tuple[PageEvalMetrics, list[Finding]]:
    """Evaluate detector findings against page ground truth."""
    t0 = time.perf_counter()
    findings = engine.detect_snapshot(snapshot)
    latency_ms = (time.perf_counter() - t0) * 1000.0

    sensitive_items = page_data.get("sensitive_items", [])
    decoys = page_data.get("decoys", [])

    metrics = PageEvalMetrics(
        page_name=page_name,
        sensitive_count=len(sensitive_items),
        decoy_count=len(decoys),
        latency_ms=latency_ms,
    )

    # Check canary detection
    page_canary = next((c for c in canaries if c["page"] == page_name), None)
    if page_canary:
        canary_target = page_canary["target"]
        canary_findings = [
            f
            for f in findings
            if f.element_id and (f.element_id == canary_target or canary_target in f.element_id)
        ]
        if canary_findings:
            metrics.canary_detected = True

    # Match sensitive items (True Positives & False Negatives)
    matched_finding_indices = set()
    for item_idx, s_item in enumerate(sensitive_items):
        matched = False
        for f_idx, f in enumerate(findings):
            if _matches_item(s_item, f):
                matched = True
                matched_finding_indices.add(f_idx)
                break
        if matched:
            metrics.tp += 1
        else:
            metrics.fn += 1
            metrics.missed_items.append({
                "item_id": f"{page_name}:item_{item_idx}",
                "selector": s_item.get("selector", ""),
                "type": s_item.get("type", ""),
            })

    # Check for decoy false positives
    for d_idx, decoy in enumerate(decoys):
        decoy_selector = decoy.get("selector", "").lstrip("#.")
        flagged = False
        for f in findings:
            if f.element_id and (f.element_id == decoy_selector or decoy_selector in f.element_id):
                flagged = True
                break
        if flagged:
            metrics.decoy_fp += 1
            metrics.fp += 1
            metrics.false_positives.append({
                "item_id": f"{page_name}:decoy_{d_idx}",
                "selector": decoy.get("selector", ""),
                "type": decoy.get("type", ""),
                "reason": decoy.get("reason", ""),
            })

    # Additional false positives
    for f_idx, f in enumerate(findings):
        if f_idx not in matched_finding_indices:
            matches_decoy = any(
                f.element_id and (f.element_id == d.get("selector", "").lstrip("#."))
                for d in decoys
            )
            if not matches_decoy:
                metrics.fp += 1
                metrics.false_positives.append({
                    "item_id": f"{page_name}:fp_{f_idx}",
                    "selector": f.element_id or "unknown",
                    "type": f.type,
                    "rule_id": f.rule_id,
                })

    return metrics, findings


def run_full_eval() -> dict[str, Any]:
    """Execute evaluation benchmark across all pages and configurations."""
    gt = load_ground_truth()
    canaries = gt.get("canaries", [])
    pages = gt.get("pages", {})

    testsite_dir = Path("testsite").resolve()
    server, thread = start_test_server_if_needed(testsite_dir, PORT)

    try:
        # Pre-capture all page snapshots
        snapshots: dict[str, PageSnapshot] = {}
        for page_name in pages:
            url = f"http://127.0.0.1:{PORT}/{page_name}"
            snapshot = asyncio.run(capture_async(url))
            snapshots[page_name] = snapshot

        # Define ablation detector configurations
        ablation_configs = {
            "all": ["pattern", "structural", "presidio"],
            "pattern_only": ["pattern"],
            "structural_only": ["structural"],
            "presidio_only": ["presidio"],
        }

        ablation_results = {}
        for config_name, detectors in ablation_configs.items():
            engine = DetectionEngine(enabled_detectors=detectors)
            page_metrics: list[PageEvalMetrics] = []

            for page_name, page_data in pages.items():
                snap = snapshots[page_name]
                m, _ = evaluate_page(page_name, page_data, canaries, snap, engine)
                page_metrics.append(m)

            total_tp = sum(m.tp for m in page_metrics)
            total_fn = sum(m.fn for m in page_metrics)
            total_fp = sum(m.fp for m in page_metrics)
            total_decoy_fp = sum(m.decoy_fp for m in page_metrics)
            canaries_detected = sum(1 for m in page_metrics if m.canary_detected)
            total_latency = sum(m.latency_ms for m in page_metrics)

            precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
            recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0

            ablation_results[config_name] = {
                "detectors": detectors,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "tp": total_tp,
                "fn": total_fn,
                "fp": total_fp,
                "decoy_fp": total_decoy_fp,
                "canary_coverage": f"{canaries_detected}/{len(canaries)}",
                "total_latency_ms": round(total_latency, 2),
                "pages": [
                    {
                        "page": m.page_name,
                        "tp": m.tp,
                        "fn": m.fn,
                        "fp": m.fp,
                        "decoy_fp": m.decoy_fp,
                        "latency_ms": round(m.latency_ms, 2),
                        "missed": m.missed_items,
                        "false_positives": m.false_positives,
                    }
                    for m in page_metrics
                ],
            }

        # Format output
        primary_res = ablation_results["all"]
        final_output = {
            "version": "1.0",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "overall": {
                "precision": primary_res["precision"],
                "recall": primary_res["recall"],
                "tp": primary_res["tp"],
                "fn": primary_res["fn"],
                "fp": primary_res["fp"],
                "decoy_fp": primary_res["decoy_fp"],
                "canary_coverage": primary_res["canary_coverage"],
                "total_latency_ms": primary_res["total_latency_ms"],
            },
            "ablations": ablation_results,
        }

        # Write latest.json
        EVAL_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        with open(EVAL_RESULTS_JSON, "w", encoding="utf-8") as f:
            json.dump(final_output, f, indent=2)

        # Write EVAL_RESULTS.md
        write_markdown_results(final_output)

        return final_output

    finally:
        if server:
            server.shutdown()
            server.server_close()


def write_markdown_results(results: dict[str, Any]) -> None:
    """Generate Markdown report summarizing evaluation metrics."""
    overall = results["overall"]
    ablations = results["ablations"]
    primary = ablations["all"]

    md = [
        "# PrivacyLens Evaluation Benchmark Report",
        "",
        f"**Generated:** {results.get('timestamp')}",
        "",
        "## Overall Summary",
        "",
        "| Metric | Score |",
        "| :--- | :--- |",
        f"| **Overall Precision** | **{overall['precision'] * 100:.1f}%** |",
        f"| **Overall Recall** | **{overall['recall'] * 100:.1f}%** |",
        f"| **True Positives** | {overall['tp']} |",
        f"| **False Negatives (Misses)** | {overall['fn']} |",
        f"| **False Positives** | {overall['fp']} |",
        f"| **Decoy False Positives** | {overall['decoy_fp']} |",
        f"| **Canary Coverage** | {overall['canary_coverage']} |",
        f"| **Total Latency** | {overall['total_latency_ms']:.2f} ms |",
        "",
        "## Per-Page Performance",
        "",
        "| Page | Sensitive Items | Detected (TP) | Misses (FN) | Decoy FP | Latency (ms) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: |",
    ]

    for p in primary["pages"]:
        sens_total = p["tp"] + p["fn"]
        md.append(
            f"| `{p['page']}` | {sens_total} | {p['tp']} | {p['fn']} | "
            f"{p['decoy_fp']} | {p['latency_ms']:.1f} |"
        )

    md.extend([
        "",
        "## Ablation Study",
        "",
        "| Configuration | Precision | Recall | TP | FN | Decoy FP | Canary | Latency (ms) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ])

    for cfg_name, cfg in ablations.items():
        md.append(
            f"| `{cfg_name}` | {cfg['precision'] * 100:.1f}% | {cfg['recall'] * 100:.1f}% | "
            f"{cfg['tp']} | {cfg['fn']} | {cfg['decoy_fp']} | {cfg['canary_coverage']} | "
            f"{cfg['total_latency_ms']:.1f} |"
        )

    md.extend([
        "",
        "## Missed Items and False Positives (Item IDs)",
        "",
    ])

    has_misses = False
    for p in primary["pages"]:
        if p["missed"]:
            has_misses = True
            md.append(f"### Misses on `{p['page']}`")
            for m in p["missed"]:
                md.append(
                    f"- **ID:** `{m['item_id']}` | **Selector:** `{m['selector']}` | "
                    f"**Type:** `{m['type']}`"
                )
        if p["false_positives"]:
            has_misses = True
            md.append(f"### False Positives on `{p['page']}`")
            for fp in p["false_positives"]:
                md.append(
                    f"- **ID:** `{fp['item_id']}` | **Selector:** `{fp['selector']}` | "
                    f"**Type:** `{fp['type']}`"
                )

    if not has_misses:
        md.append("No misses or false positives observed.")

    DOCS_EVAL_MD.parent.mkdir(parents=True, exist_ok=True)
    with open(DOCS_EVAL_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")


def main() -> None:
    """Entry point for python -m eval.run_eval."""
    print("Running PrivacyLens Evaluation Benchmark...")
    results = run_full_eval()
    overall = results["overall"]
    print("\nBenchmark Execution Complete:")
    print(f"  Precision: {overall['precision'] * 100:.1f}%")
    print(f"  Recall:    {overall['recall'] * 100:.1f}%")
    print(f"  Canaries:  {overall['canary_coverage']}")
    print(f"  Decoy FP:  {overall['decoy_fp']}")
    print(f"Results written to {EVAL_RESULTS_JSON} and {DOCS_EVAL_MD}")


if __name__ == "__main__":
    main()

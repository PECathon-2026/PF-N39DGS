"""Evaluation benchmark comparing PrivacyLens detectors against ground truth dataset."""

from __future__ import annotations

import asyncio
import http.server
import json
import logging
import re
import socket
import socketserver
import threading
import time
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

from privacylens.capture import ElementSnapshot, PageSnapshot, capture_async
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
    "NOTE_WITH_CANARY": {"NOTE_WITH_CANARY"},
}


@dataclass
class PageEvalMetrics:
    """Evaluation metrics for a single web page."""

    page_name: str
    tp: int = 0
    fn: int = 0
    fp: int = 0
    decoy_fp: int = 0
    type_mismatches: int = 0
    pure_extras: int = 0
    canary_detected: bool = False
    latency_ms: float = 0.0
    sensitive_count: int = 0
    decoy_count: int = 0
    total_findings: int = 0
    precision: float = 0.0
    recall: float = 0.0
    decoy_over_redaction_rate: float = 0.0
    char_over_redaction_rate: float = 0.0
    total_non_sensitive_chars: int = 0
    over_redacted_chars: int = 0
    missed_items: list[dict[str, Any]] = field(default_factory=list)
    false_positives: list[dict[str, Any]] = field(default_factory=list)
    type_mismatch_items: list[dict[str, Any]] = field(default_factory=list)


def load_ground_truth(path: str | Path = "eval/ground_truth.json") -> dict[str, Any]:
    """Load ground truth JSON dataset."""
    ground_truth_path = Path(path)
    with open(ground_truth_path, encoding="utf-8") as f:
        return json.load(f)


def _resolve_target_id(selector: str, elements: list[ElementSnapshot]) -> str:
    """Resolve ground truth selector to matching element ID."""
    if not selector:
        return ""
    if selector.startswith("#"):
        return selector[1:]
    # Check by exact element_id
    for el in elements:
        if el.element_id == selector:
            return el.element_id
    # Check input[name='...']
    m_name = re.search(r"name=['\"]?([^'\"\]]+)['\"]?", selector)
    if m_name:
        name_val = m_name.group(1)
        for el in elements:
            if el.name == name_val:
                return el.element_id
    # Check [aria-label='...']
    m_aria = re.search(r"aria-label=['\"]?([^'\"\]]+)['\"]?", selector)
    if m_aria:
        aria_val = m_aria.group(1)
        for el in elements:
            if el.aria_label == aria_val:
                return el.element_id
    # Check .class
    if selector.startswith("."):
        cls_val = selector[1:].strip()
        for el in elements:
            if cls_val in (el.element_id or ""):
                return el.element_id
    return selector.lstrip("#.")


def _matches_item(
    gt_item: dict[str, Any],
    finding: Finding,
    elem_text: str = "",
    target_id: str = "",
) -> bool:
    """Evaluate whether a finding strictly matches a ground truth target item."""
    expected_type = gt_item.get("type", "")
    target_elem_id = target_id or gt_item.get("selector", "").lstrip("#.")

    # 1. Selector match
    if not finding.element_id:
        return False
    if finding.element_id != target_elem_id:
        return False

    # 2. Type compatibility
    allowed_types = TYPE_EQUIVALENCIES.get(expected_type, {expected_type})
    if finding.type != expected_type and finding.type not in allowed_types:
        return False

    # 3. Span match (if GT has span or finding has span)
    gt_start = gt_item.get("start")
    gt_end = gt_item.get("end")
    if gt_start is None and elem_text and gt_item.get("value"):
        val = str(gt_item["value"])
        pos = elem_text.find(val)
        if pos != -1:
            gt_start = pos
            gt_end = pos + len(val)

    if gt_start is not None and gt_end is not None:
        if finding.start is not None and finding.end is not None:
            # Overlapping character span
            return max(finding.start, gt_start) < min(finding.end, gt_end)
        elif finding.is_structural:
            # Structural finding covers the full element
            return True

    return True


def evaluate_page(
    page_name: str,
    page_data: dict[str, Any],
    canaries: list[dict[str, Any]],
    snapshot: PageSnapshot,
    engine: DetectionEngine,
) -> tuple[PageEvalMetrics, list[Finding]]:
    """Evaluate detector findings against page ground truth with strict matching."""
    t0 = time.perf_counter()
    findings = engine.detect_snapshot(snapshot)
    latency_ms = (time.perf_counter() - t0) * 1000.0

    sensitive_items = page_data.get("sensitive_items", [])
    decoys = page_data.get("decoys", [])

    metrics = PageEvalMetrics(
        page_name=page_name,
        sensitive_count=len(sensitive_items),
        decoy_count=len(decoys),
        total_findings=len(findings),
        latency_ms=latency_ms,
    )

    # 1. Check canary detection
    page_canary = next((c for c in canaries if c["page"] == page_name), None)
    if page_canary:
        canary_target = _resolve_target_id(page_canary["target"], snapshot.elements)
        canary_findings = [
            f for f in findings if f.element_id and f.element_id == canary_target
        ]
        if canary_findings:
            metrics.canary_detected = True

    # 2. Bipartite 1-to-1 matching for sensitive items (True Positives & False Negatives)
    matched_finding_indices: set[int] = set()
    matched_gt_indices: set[int] = set()

    for gt_idx, s_item in enumerate(sensitive_items):
        target_id = _resolve_target_id(s_item.get("selector", ""), snapshot.elements)
        elem = next((e for e in snapshot.elements if e.element_id == target_id), None)
        elem_text = ""
        if elem:
            val = elem.input_value if elem.input_value is not None else elem.visible_text
            elem_text = val or ""

        for f_idx, f in enumerate(findings):
            if f_idx in matched_finding_indices:
                continue
            if _matches_item(s_item, f, elem_text=elem_text, target_id=target_id):
                matched_finding_indices.add(f_idx)
                matched_gt_indices.add(gt_idx)
                break

    metrics.tp = len(matched_gt_indices)
    metrics.fn = len(sensitive_items) - metrics.tp

    for gt_idx, s_item in enumerate(sensitive_items):
        if gt_idx not in matched_gt_indices:
            metrics.missed_items.append({
                "item_id": f"{page_name}:item_{gt_idx}",
                "selector": s_item.get("selector", ""),
                "type": s_item.get("type", ""),
            })

    # 3. Decoy false positives: check each decoy element
    decoy_ids = {_resolve_target_id(d.get("selector", ""), snapshot.elements): d for d in decoys}
    flagged_decoy_ids: set[str] = set()
    for f in findings:
        if f.element_id and f.element_id in decoy_ids:
            flagged_decoy_ids.add(f.element_id)

    metrics.decoy_fp = len(flagged_decoy_ids)
    metrics.decoy_over_redaction_rate = (
        metrics.decoy_fp / len(decoys) if decoys else 0.0
    )

    # 4. Classify unmatched findings: type mismatches vs pure extras vs decoy FPs
    sensitive_target_ids = {
        _resolve_target_id(s.get("selector", ""), snapshot.elements)
        for s in sensitive_items
    }
    for f_idx, f in enumerate(findings):
        if f_idx in matched_finding_indices:
            continue
        metrics.fp += 1
        if f.element_id in decoy_ids:
            decoy_meta = decoy_ids[f.element_id]
            metrics.false_positives.append({
                "item_id": f"{page_name}:decoy_fp_{f_idx}",
                "selector": f.element_id,
                "type": f.type,
                "category": "DECOY_FP",
                "reason": decoy_meta.get("reason", ""),
            })
        elif f.element_id in sensitive_target_ids:
            metrics.type_mismatches += 1
            metrics.type_mismatch_items.append({
                "item_id": f"{page_name}:mismatch_{f_idx}",
                "selector": f.element_id,
                "type": f.type,
                "category": "TYPE_MISMATCH",
                "rule_id": f.rule_id,
            })
        else:
            metrics.pure_extras += 1
            metrics.false_positives.append({
                "item_id": f"{page_name}:fp_{f_idx}",
                "selector": f.element_id or "unknown",
                "type": f.type,
                "category": "PURE_EXTRA",
                "rule_id": f.rule_id,
            })

    # 5. Over-redaction: Character-level metric across all leaf elements
    total_non_sens = 0
    over_redacted = 0
    for elem in snapshot.elements:
        text = elem.input_value if elem.input_value is not None else (elem.visible_text or "")
        if not text:
            continue
        n_chars = len(text)
        sens_mask = [False] * n_chars
        redact_mask = [False] * n_chars

        # Mark ground-truth sensitive positions
        for s_item in sensitive_items:
            if s_item.get("selector", "").lstrip("#.") == elem.element_id:
                val = str(s_item.get("value", ""))
                pos = text.find(val)
                if pos != -1:
                    for k in range(pos, min(pos + len(val), n_chars)):
                        sens_mask[k] = True
                else:
                    for k in range(n_chars):
                        sens_mask[k] = True

        # Mark detector-redacted positions
        for f in findings:
            if f.element_id == elem.element_id:
                if f.start is not None and f.end is not None:
                    for k in range(max(0, f.start), min(f.end, n_chars)):
                        redact_mask[k] = True
                else:
                    for k in range(n_chars):
                        redact_mask[k] = True

        for k in range(n_chars):
            if not sens_mask[k]:
                total_non_sens += 1
                if redact_mask[k]:
                    over_redacted += 1

    metrics.total_non_sensitive_chars = total_non_sens
    metrics.over_redacted_chars = over_redacted
    metrics.char_over_redaction_rate = (
        over_redacted / total_non_sens if total_non_sens > 0 else 0.0
    )

    metrics.precision = (
        metrics.tp / len(findings) if findings else (1.0 if not sensitive_items else 0.0)
    )
    metrics.recall = (
        metrics.tp / len(sensitive_items) if sensitive_items else 1.0
    )

    return metrics, findings


def run_full_eval(
    ground_truth_path: str | Path = "eval/ground_truth.json",
    output_md_path: Path | None = None,
) -> dict[str, Any]:
    """Execute evaluation benchmark across all pages and configurations."""
    gt = load_ground_truth(ground_truth_path)
    canaries = gt.get("canaries", [])
    pages = gt.get("pages", {})

    testsite_dir = Path("testsite").resolve()
    print(f"Starting test server on port {PORT}...", flush=True)
    server, thread = start_test_server_if_needed(testsite_dir, PORT)
    print("Test server ready.", flush=True)

    try:
        # Pre-capture all page snapshots
        snapshots: dict[str, PageSnapshot] = {}
        for page_name, pdata in pages.items():
            page_url = pdata.get("url") or f"http://127.0.0.1:{PORT}/{page_name}"
            print(f"Capturing snapshot for {page_name} from {page_url}...", flush=True)
            snapshot = asyncio.run(capture_async(page_url))
            snapshots[page_name] = snapshot
            print(f"Captured {page_name} ({len(snapshot.elements)} elements)", flush=True)

        print("All snapshots captured. Starting detection ablations...", flush=True)

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
            total_findings = sum(m.total_findings for m in page_metrics)
            total_sensitive = sum(m.sensitive_count for m in page_metrics)
            total_decoys = sum(m.decoy_count for m in page_metrics)
            total_non_sens_chars = sum(m.total_non_sensitive_chars for m in page_metrics)
            total_over_redacted_chars = sum(m.over_redacted_chars for m in page_metrics)
            total_type_mismatches = sum(m.type_mismatches for m in page_metrics)
            total_pure_extras = sum(m.pure_extras for m in page_metrics)
            canaries_detected = sum(1 for m in page_metrics if m.canary_detected)
            total_latency = sum(m.latency_ms for m in page_metrics)

            precision = total_tp / total_findings if total_findings > 0 else 1.0
            recall = total_tp / total_sensitive if total_sensitive > 0 else 0.0
            decoy_over_redaction = total_decoy_fp / total_decoys if total_decoys > 0 else 0.0
            char_over_redaction = (
                total_over_redacted_chars / total_non_sens_chars
                if total_non_sens_chars > 0
                else 0.0
            )

            ablation_results[config_name] = {
                "detectors": detectors,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "tp": total_tp,
                "fn": total_fn,
                "fp": total_fp,
                "total_findings": total_findings,
                "decoy_fp": total_decoy_fp,
                "type_mismatches": total_type_mismatches,
                "pure_extras": total_pure_extras,
                "decoy_over_redaction_rate": round(decoy_over_redaction, 4),
                "char_over_redaction_rate": round(char_over_redaction, 4),
                "canary_coverage": f"{canaries_detected}/{len(canaries)}",
                "total_latency_ms": round(total_latency, 2),
                "pages": [
                    {
                        "page": m.page_name,
                        "tp": m.tp,
                        "fn": m.fn,
                        "fp": m.fp,
                        "total_findings": m.total_findings,
                        "precision": round(m.precision, 4),
                        "recall": round(m.recall, 4),
                        "decoy_fp": m.decoy_fp,
                        "type_mismatches": m.type_mismatches,
                        "pure_extras": m.pure_extras,
                        "decoy_over_redaction_rate": round(m.decoy_over_redaction_rate, 4),
                        "char_over_redaction_rate": round(m.char_over_redaction_rate, 4),
                        "latency_ms": round(m.latency_ms, 2),
                        "missed": m.missed_items,
                        "false_positives": m.false_positives,
                        "type_mismatches_items": m.type_mismatch_items,
                    }
                    for m in page_metrics
                ],
            }

        # Format output
        primary_res = ablation_results["all"]
        final_output = {
            "version": "1.0",
            "ground_truth_source": str(ground_truth_path),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "overall": {
                "precision": primary_res["precision"],
                "recall": primary_res["recall"],
                "tp": primary_res["tp"],
                "fn": primary_res["fn"],
                "fp": primary_res["fp"],
                "total_findings": primary_res["total_findings"],
                "decoy_fp": primary_res["decoy_fp"],
                "type_mismatches": primary_res["type_mismatches"],
                "pure_extras": primary_res["pure_extras"],
                "decoy_over_redaction_rate": primary_res["decoy_over_redaction_rate"],
                "char_over_redaction_rate": primary_res["char_over_redaction_rate"],
                "canary_coverage": primary_res["canary_coverage"],
                "total_latency_ms": primary_res["total_latency_ms"],
            },
            "ablations": ablation_results,
        }

        # Write latest.json
        EVAL_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        with open(EVAL_RESULTS_JSON, "w", encoding="utf-8") as f:
            json.dump(final_output, f, indent=2)

        # Write Markdown results
        target_md = output_md_path or DOCS_EVAL_MD
        write_markdown_results(final_output, target_md)

        return final_output

    finally:
        if server:
            server.shutdown()
            server.server_close()


def write_markdown_results(results: dict[str, Any], output_path: Path = DOCS_EVAL_MD) -> None:
    """Generate Markdown report summarizing evaluation metrics."""
    overall = results["overall"]
    ablations = results["ablations"]
    primary = ablations["all"]

    md = [
        "# PrivacyLens Evaluation Benchmark Report",
        "",
        f"**Generated:** {results.get('timestamp')}",
        (
            f"**Ground Truth Dataset:** "
            f"`{results.get('ground_truth_source', 'eval/ground_truth.json')}`"
        ),
        "",
        "## Overall Summary",
        "",
        "| Metric | Score |",
        "| :--- | :--- |",
        f"| **Overall Precision (Finding-Level)** | **{overall['precision'] * 100:.1f}%** |",
        f"| **Overall Recall** | **{overall['recall'] * 100:.1f}%** |",
        f"| **True Positives** | {overall['tp']} |",
        f"| **False Negatives (Misses)** | {overall['fn']} |",
        f"| **Total Findings (After Dedupe)** | {overall['total_findings']} |",
        f"| **False Positives (Unmatched)** | {overall['fp']} |",
        f"| **Type Mismatches on Sensitive Elements** | {overall.get('type_mismatches', 0)} |",
        f"| **Pure Extras on Non-Sensitive Elements** | {overall.get('pure_extras', 0)} |",
        f"| **Decoy False Positives** | {overall['decoy_fp']} |",
        (
            f"| **Decoy Over-Redaction Rate** | "
            f"{overall.get('decoy_over_redaction_rate', 0.0) * 100:.1f}% |"
        ),
        (
            f"| **Character Over-Redaction Rate** | "
            f"{overall.get('char_over_redaction_rate', 0.0) * 100:.2f}% |"
        ),
        f"| **Canary Coverage** | {overall['canary_coverage']} |",
        f"| **Total Latency** | {overall['total_latency_ms']:.2f} ms |",
        "",
        "## Per-Page Performance",
        "",
        (
            "| Page | Sensitive Items | Detected (TP) | Misses (FN) | Findings | "
            "Precision | Recall | Decoy FP | Decoy Over-Redact | Char Over-Redact | Latency (ms) |"
        ),
        (
            "| :--- | :---: | :---: | :---: | :---: | "
            ":---: | :---: | :---: | :---: | :---: | :---: |"
        ),
    ]

    for p in primary["pages"]:
        sens_total = p["tp"] + p["fn"]
        f_count = p.get("total_findings", p["tp"] + p["fp"])
        d_rate = p.get("decoy_over_redaction_rate", 0.0) * 100
        c_rate = p.get("char_over_redaction_rate", 0.0) * 100
        md.append(
            f"| `{p['page']}` | {sens_total} | {p['tp']} | {p['fn']} | {f_count} | "
            f"{p.get('precision', 0.0) * 100:.1f}% | {p.get('recall', 0.0) * 100:.1f}% | "
            f"{p['decoy_fp']} | {d_rate:.1f}% | {c_rate:.2f}% | {p['latency_ms']:.1f} |"
        )

    md.extend([
        "",
        "## Ablation Study",
        "",
        (
            "| Configuration | Precision | Recall | TP | FN | "
            "Decoy FP | Decoy Over-Redact | Char Over-Redact | Canary | Latency (ms) |"
        ),
        (
            "| :--- | :---: | :---: | :---: | :---: | "
            ":---: | :---: | :---: | :---: | :---: |"
        ),
    ])

    for cfg_name, cfg in ablations.items():
        cd_rate = cfg.get("decoy_over_redaction_rate", 0.0) * 100
        cc_rate = cfg.get("char_over_redaction_rate", 0.0) * 100
        md.append(
            f"| `{cfg_name}` | {cfg['precision'] * 100:.1f}% | {cfg['recall'] * 100:.1f}% | "
            f"{cfg['tp']} | {cfg['fn']} | {cfg['decoy_fp']} | "
            f"{cd_rate:.1f}% | {cc_rate:.2f}% | "
            f"{cfg['canary_coverage']} | {cfg['total_latency_ms']:.1f} |"
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
                cat = fp.get("category", "FP")
                reason = f" ({fp['reason']})" if fp.get("reason") else ""
                md.append(
                    f"- **ID:** `{fp['item_id']}` | **Selector:** `{fp['selector']}` | "
                    f"**Type:** `{fp['type']}` | **Category:** `{cat}`{reason}"
                )

    if not has_misses:
        md.append("No misses or false positives observed.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")


def main() -> None:
    """Entry point for python -m eval.run_eval."""
    import sys
    gt_path = "eval/ground_truth.json"
    if "--holdout" in sys.argv:
        gt_path = "eval/ground_truth_holdout.json"
    elif len(sys.argv) > 1 and sys.argv[1].endswith(".json"):
        gt_path = sys.argv[1]

    print(f"Running PrivacyLens Evaluation Benchmark on {gt_path}...")
    results = run_full_eval(ground_truth_path=gt_path)
    overall = results["overall"]
    print("\nBenchmark Execution Complete:")
    print(f"  Precision: {overall['precision'] * 100:.1f}%")
    print(f"  Recall:    {overall['recall'] * 100:.1f}%")
    print(f"  Canaries:  {overall['canary_coverage']}")
    print(f"  Decoy FP:  {overall['decoy_fp']}")
    print(f"Results written to {EVAL_RESULTS_JSON} and {DOCS_EVAL_MD}")


if __name__ == "__main__":
    main()

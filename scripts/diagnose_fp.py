"""Diagnosis script for False Positives in PrivacyLens evaluation."""

import asyncio
from collections import Counter
from pathlib import Path

from eval.run_eval import _matches_item, load_ground_truth, start_test_server_if_needed
from privacylens.capture import capture_async
from privacylens.detect.engine import DetectionEngine


def main() -> None:
    gt = load_ground_truth()
    pages = gt["pages"]
    engine = DetectionEngine(enabled_detectors=["pattern", "structural", "presidio"])

    server, thread = start_test_server_if_needed(Path("testsite").resolve(), 8765)
    fp_rows = []
    counts = Counter()

    try:
        for page_name, pdata in pages.items():
            url = f"http://127.0.0.1:8765/{page_name}"
            snap = asyncio.run(capture_async(url))
            findings = engine.detect_snapshot(snap)
            sens_items = pdata.get("sensitive_items", [])

            elem_map = {el.element_id: el for el in snap.elements}

            matched_indices = set()
            for s_item in sens_items:
                for idx, f in enumerate(findings):
                    if _matches_item(s_item, f):
                        matched_indices.add(idx)
                        break

            for idx, f in enumerate(findings):
                if idx not in matched_indices:
                    el = elem_map.get(f.element_id)
                    tag = el.tag if el else "unknown"
                    has_dup = any(
                        idx2 != idx and f2.type == f.type and f2.element_id != f.element_id
                        for idx2, f2 in enumerate(findings)
                    )
                    src = f.source
                    fp_rows.append({
                        "page": page_name,
                        "type": f.type,
                        "rule_id": f.rule_id,
                        "source": src,
                        "element_id": f.element_id or "none",
                        "tag": tag,
                        "has_dup": has_dup,
                    })
                    counts[(src, tag)] += 1

        print(f"Total False Positives: {len(fp_rows)}")
        header = (
            f"{'Page':<16} | {'Type':<10} | {'Rule':<25} | "
            f"{'Source':<15} | {'Element ID':<22} | {'Tag':<6} | {'Dup Val?'}"
        )
        print(header)
        print("-" * len(header))
        for r in fp_rows:
            rule_trunc = r['rule_id'][:25]
            src_trunc = r['source'][:15]
            line = (
                f"{r['page']:<16} | {r['type']:<10} | {rule_trunc:<25} | "
                f"{src_trunc:<15} | {r['element_id']:<22} | {r['tag']:<6} | {str(r['has_dup'])}"
            )
            print(line)

        print("\nCounts by (detector source, tag):")
        for k, v in sorted(counts.items()):
            print(f"  {k}: {v}")
    finally:
        if server:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()

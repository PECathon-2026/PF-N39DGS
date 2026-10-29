from __future__ import annotations

from typing import Any, Dict, List

from core.detect.regex_layer import Finding


def _is_box(loc: Any) -> bool:
    return isinstance(loc, dict) and "x" in loc and "y" in loc and "w" in loc and "h" in loc


def _is_span(loc: Any) -> bool:
    return isinstance(loc, dict) and "start" in loc and "end" in loc


def _is_elem(loc: Any) -> bool:
    return isinstance(loc, dict) and "element" in loc


def _boxes_overlap(b1: Dict[str, Any], b2: Dict[str, Any], margin: int = 2) -> bool:
    l1, r1 = b1["x"], b1["x"] + b1["w"]
    t1, bt1 = b1["y"], b1["y"] + b1["h"]
    l2, r2 = b2["x"], b2["x"] + b2["w"]
    t2, bt2 = b2["y"], b2["y"] + b2["h"]
    return not (r1 + margin < l2 or r2 + margin < l1 or bt1 + margin < t2 or bt2 + margin < t1)


def _intersection_ratio(b1: Dict[str, Any], b2: Dict[str, Any]) -> float:
    x_overlap = max(0, min(b1["x"] + b1["w"], b2["x"] + b2["w"]) - max(b1["x"], b2["x"]))
    y_overlap = max(0, min(b1["y"] + b1["h"], b2["y"] + b2["h"]) - max(b1["y"], b2["y"]))
    intersection = x_overlap * y_overlap
    a1 = max(1, b1["w"] * b1["h"])
    a2 = max(1, b2["w"] * b2["h"])
    return intersection / min(a1, a2)


def _union_box(b1: Dict[str, Any], b2: Dict[str, Any]) -> Dict[str, Any]:
    l1, r1 = b1["x"], b1["x"] + b1["w"]
    t1, bt1 = b1["y"], b1["y"] + b1["h"]
    l2, r2 = b2["x"], b2["x"] + b2["w"]
    t2, bt2 = b2["y"], b2["y"] + b2["h"]
    min_x = min(l1, l2)
    min_y = min(t1, t2)
    max_x = max(r1, r2)
    max_y = max(bt1, bt2)
    res: Dict[str, Any] = {
        "x": int(min_x),
        "y": int(min_y),
        "w": int(max_x - min_x),
        "h": int(max_y - min_y),
    }
    el = b1.get("element") or b2.get("element")
    if el:
        res["element"] = el
    return res


def _merge_two_findings(f1: Finding, f2: Finding, new_loc: Any) -> Finding:
    combined_layers = sorted(list(set((f1.source_layers or [f1.layer]) + (f2.source_layers or [f2.layer]))))
    best_cat = f1.category if f1.confidence >= f2.confidence else f2.category
    best_conf = max(f1.confidence, f2.confidence)
    primary_layer = "+".join(combined_layers)
    return Finding(
        category=best_cat,
        location=new_loc,
        layer=primary_layer,
        confidence=best_conf,
        source_layers=combined_layers,
    )


def _merge_boxes(box_findings: List[Finding]) -> List[Finding]:
    merged: List[Finding] = []
    for f in box_findings:
        combined = False
        for i, existing in enumerate(merged):
            # Merge if same category and boxes overlap
            if f.category == existing.category and _boxes_overlap(f.location, existing.location):
                u_box = _union_box(f.location, existing.location)
                merged[i] = _merge_two_findings(existing, f, u_box)
                combined = True
                break
            # Also merge near-duplicate bounding boxes with high overlap (>60%)
            elif _intersection_ratio(f.location, existing.location) > 0.6:
                u_box = _union_box(f.location, existing.location)
                merged[i] = _merge_two_findings(existing, f, u_box)
                combined = True
                break
        if not combined:
            merged.append(f)
    return merged


def _merge_spans(span_findings: List[Finding]) -> List[Finding]:
    merged: List[Finding] = []
    for f in span_findings:
        combined = False
        s1, e1 = f.location["start"], f.location["end"]
        for i, existing in enumerate(merged):
            s2, e2 = existing.location["start"], existing.location["end"]
            if f.category == existing.category and not (e1 < s2 or e2 < s1):
                new_span = {"start": min(s1, s2), "end": max(e1, e2)}
                merged[i] = _merge_two_findings(existing, f, new_span)
                combined = True
                break
            elif not (e1 < s2 or e2 < s1):
                # overlapping spans: union if one contains the other or close
                overlap = max(0, min(e1, e2) - max(s1, s2))
                min_len = min(e1 - s1, e2 - s2)
                if min_len > 0 and overlap / min_len > 0.7:
                    new_span = {"start": min(s1, s2), "end": max(e1, e2)}
                    merged[i] = _merge_two_findings(existing, f, new_span)
                    combined = True
                    break
        if not combined:
            merged.append(f)
    return merged


def _merge_elements(elem_findings: List[Finding]) -> List[Finding]:
    merged_map: Dict[str, Finding] = {}
    for f in elem_findings:
        el_id = f.location.get("element")
        key = str(el_id)
        if key in merged_map:
            loc = dict(merged_map[key].location)
            if "x" in f.location and "x" not in loc:
                loc["x"] = f.location["x"]
                loc["y"] = f.location["y"]
                loc["w"] = f.location["w"]
                loc["h"] = f.location["h"]
            merged_map[key] = _merge_two_findings(merged_map[key], f, loc)
        else:
            merged_map[key] = f
    return list(merged_map.values())


def fuse(findings: List[Finding]) -> List[Finding]:
    """Fuse findings from multiple detection layers.

    Resolves overlaps, unions bounding boxes/spans, preserves all detected entities
    to favour recall, and records all source layers for dashboard explainability.
    """
    if not findings:
        return []

    # Ensure source_layers are populated on all input findings
    normalized: List[Finding] = []
    for f in findings:
        src = list(f.source_layers) if f.source_layers else [f.layer]
        normalized.append(
            Finding(
                category=f.category,
                location=f.location,
                layer=f.layer,
                confidence=f.confidence,
                source_layers=src,
            )
        )

    # Segregate by location type
    boxes: List[Finding] = [f for f in normalized if _is_box(f.location)]
    spans: List[Finding] = [f for f in normalized if _is_span(f.location)]
    elems: List[Finding] = [f for f in normalized if _is_elem(f.location) and not _is_box(f.location)]
    others: List[Finding] = [
        f for f in normalized
        if not (_is_box(f.location) or _is_span(f.location) or _is_elem(f.location))
    ]

    fused_boxes = _merge_boxes(boxes)
    fused_spans = _merge_spans(spans)
    fused_elems = _merge_elements(elems)

    # Combine all and de-duplicate any identical (category, location_str)
    all_fused = fused_boxes + fused_spans + fused_elems + others
    seen: Dict[tuple, Finding] = {}
    for f in all_fused:
        loc_key = str(sorted(f.location.items())) if isinstance(f.location, dict) else str(f.location)
        key = (f.category, loc_key)
        if key in seen:
            seen[key] = _merge_two_findings(seen[key], f, f.location)
        else:
            seen[key] = f

    return list(seen.values())

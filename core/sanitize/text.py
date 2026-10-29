from __future__ import annotations

import copy
import re
from typing import Any, Dict, List, Optional, Set

from core.detect.regex_layer import Finding, scan_text


def sanitize_text(text: str, findings: Optional[List[Finding]] = None) -> str:
    """Sanitize raw text by replacing sensitive spans with [REDACTED:<CATEGORY>].

    Ensures exact placeholder format without revealing length, partial digits, or hashes.
    """
    if not text:
        return ""

    # Always scan the specific text string directly to get exact character offsets
    direct_findings = scan_text(text)

    # Collect valid text spans
    spans: List[Dict[str, Any]] = []
    for f in direct_findings:
        loc = f.location
        if isinstance(loc, dict) and "start" in loc and "end" in loc:
            s, e = loc["start"], loc["end"]
            if 0 <= s < e <= len(text):
                spans.append({
                    "start": s,
                    "end": e,
                    "category": f.category.upper(),
                })

    # If external findings are provided, include matching spans if within bounds
    if findings:
        for f in findings:
            loc = f.location
            if isinstance(loc, dict) and "start" in loc and "end" in loc:
                s, e = loc["start"], loc["end"]
                # Only include if span is within text bounds
                if 0 <= s < e <= len(text):
                    spans.append({
                        "start": s,
                        "end": e,
                        "category": f.category.upper(),
                    })

    if not spans:
        return text

    # Sort spans in ascending order to merge overlapping/adjacent spans
    spans.sort(key=lambda s: (s["start"], s["end"]))
    merged_spans: List[Dict[str, Any]] = []
    for s in spans:
        if not merged_spans:
            merged_spans.append(s)
            continue
        last = merged_spans[-1]
        if s["start"] <= last["end"]:
            # Overlapping or contiguous: extend end and retain category
            last["end"] = max(last["end"], s["end"])
        else:
            merged_spans.append(s)

    # Replace from end to start so earlier character indices remain valid
    result = list(text)
    for s in reversed(merged_spans):
        cat = s["category"]
        placeholder = f"[REDACTED:{cat}]"
        result[s["start"]:s["end"]] = list(placeholder)

    return "".join(result)


def sanitize_dom(snapshot: Dict[str, Any], findings: Optional[List[Finding]] = None) -> Dict[str, Any]:
    """Produce a sanitized DOM/elements snapshot.

    Replaces sensitive input values and element texts with [REDACTED:<CATEGORY>].
    Preserves element tags, el_N ids, names, types, labels, and buttons intact
    so the agent can reason about layout and act on elements.
    """
    sanitized = copy.deepcopy(snapshot)

    # Element-level findings map: el_id -> category
    element_flags: Dict[str, str] = {}
    if findings:
        for f in findings:
            loc = f.location
            if isinstance(loc, dict) and "element" in loc:
                element_flags[str(loc["element"])] = f.category.upper()

    elements = sanitized.get("elements", [])
    for el in elements:
        el_id = str(el.get("el_id", ""))
        val = el.get("value")
        txt = el.get("text")

        # 1. Element identified as sensitive by DOM layer
        if el_id in element_flags:
            cat = element_flags[el_id]
            if val is not None and str(val).strip():
                el["value"] = f"[REDACTED:{cat}]"
            elif txt is not None and str(txt).strip():
                el["text"] = f"[REDACTED:{cat}]"

        # 2. Sanitize any remaining sensitive text or values inside the element
        if el.get("value"):
            el["value"] = sanitize_text(str(el["value"]))
        if el.get("text"):
            el["text"] = sanitize_text(str(el["text"]))
        if el.get("aria_label"):
            el["aria_label"] = sanitize_text(str(el["aria_label"]))

    # Sanitize general page text if present
    if "text" in sanitized and sanitized["text"]:
        sanitized["text"] = sanitize_text(sanitized["text"])

    return sanitized


def render_sanitized_view(sanitized_snapshot: Dict[str, Any]) -> str:
    """Format sanitized snapshot into a clean structured string for the agent.

    Includes page metadata, layout text, and interactive elements with stable [el_N] ids.
    """
    lines: List[str] = []
    title = sanitized_snapshot.get("title", "")
    url = sanitized_snapshot.get("url", "")
    lines.append(f"PAGE TITLE: {title}")
    lines.append(f"PAGE URL: {url}")
    lines.append("")

    page_text = sanitized_snapshot.get("text", "").strip()
    if page_text:
        lines.append("PAGE CONTENT:")
        lines.append(page_text)
        lines.append("")

    lines.append("INTERACTIVE ELEMENTS:")
    for el in sanitized_snapshot.get("elements", []):
        el_id = el.get("el_id", "")
        tag = el.get("tag", "")
        typ = el.get("type")
        eid = el.get("id")
        name = el.get("name")
        val = el.get("value")
        txt = el.get("text", "").strip()

        attrs = [f"tag={tag}"]
        if typ:
            attrs.append(f"type={typ}")
        if eid:
            attrs.append(f"id={eid}")
        if name:
            attrs.append(f"name={name}")
        if val is not None and str(val).strip():
            attrs.append(f'value="{val}"')
        if txt:
            attrs.append(f'text="{txt}"')

        lines.append(f"[{el_id}] <{' '.join(attrs)}>")

    return "\n".join(lines)


def calculate_context_preservation(original_text: str, sanitized_text: str, canary_values: Set[str]) -> float:
    """Calculate the percentage of non-sensitive context preserved after redaction.

    Measures retention of UI structure, non-sensitive words, and layout cues.
    """
    if not original_text:
        return 100.0

    # Extract non-sensitive words from original
    clean_orig = original_text
    for c in canary_values:
        clean_orig = clean_orig.replace(c, " ")

    orig_words = [w.lower() for w in re.findall(r"\b\w+\b", clean_orig)]
    if not orig_words:
        return 100.0

    sanitized_words = set(
        w.lower() for w in re.findall(r"\b\w+\b", sanitized_text)
        if not w.upper().startswith("REDACTED")
    )
    preserved_count = sum(1 for w in orig_words if w in sanitized_words)

    return (preserved_count / len(orig_words)) * 100.0

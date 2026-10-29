from __future__ import annotations

import base64
import os
import sys
import pytest
from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.agent.client import (
    clear_outbound_transmission_records,
    get_outbound_transmission_records,
    send_to_model,
)
from core.detect import dom_layer, face_layer, fusion, ocr_layer, regex_layer
from core.egress.guard import check_payload
from core.perception.capture import capture
from core.sanitize import mask_image_bytes, render_sanitized_view, sanitize_dom
from eval.canaries.registry import generate_registry


def test_baseline_versus_protected_leakage():
    """Verify that unprotected baseline leaks canaries while protected pipeline yields 0 leaks."""
    reg = generate_registry(42)
    canaries = set(reg.all_values())

    pages_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")
    scen_path = os.path.abspath(os.path.join(pages_dir, "scenario_1_ecommerce.html")).replace("\\", "/")

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(f"file:///{scen_path}")
        page.wait_for_load_state("networkidle")
        snap = capture(page)
        page.close()
        browser.close()

    raw_text = " ".join([el.get("text", "") + " " + el.get("value", "") for el in snap.get("elements", [])])
    if snap.get("text"):
        raw_text += " " + snap["text"]

    # 1. Baseline leakage check (No protection)
    baseline_leaks = [c for c in canaries if c in raw_text]
    assert len(baseline_leaks) > 0, "Baseline run must demonstrate canary leakage"

    # 2. Protected pipeline leakage check
    screenshot_bytes = base64.b64decode(snap["screenshot_b64"])
    d_findings = dom_layer.scan_dom(snap)
    r_findings = regex_layer.scan_text(raw_text)
    o_findings = ocr_layer.scan_image(screenshot_bytes)
    f_findings = face_layer.scan_image(screenshot_bytes)
    fused = fusion.fuse(d_findings + r_findings + o_findings + f_findings)

    san_snap = sanitize_dom(snap, fused)
    san_text = render_sanitized_view(san_snap)
    masked_bytes = mask_image_bytes(screenshot_bytes, fused, padding=4)

    # Protected text leakage
    protected_text_leaks = [c for c in canaries if c in san_text]
    assert protected_text_leaks == [], f"Protected text must have zero canary leakage: {protected_text_leaks}"

    # Egress Guard check
    guard_result = check_payload(san_text, masked_bytes)
    assert guard_result.passed is True
    assert guard_result.category_counts == {}


def test_fallback_recorder_in_send_to_model():
    """Verify fallback recorder in send_to_model captures payload hash and canary-hit boolean."""
    clear_outbound_transmission_records()

    # Clean payload
    safe_prompt = "Click button [el_4] on the page"
    send_to_model(safe_prompt)

    records = get_outbound_transmission_records()
    assert len(records) >= 1
    last_rec = records[-1]

    # Invariant: Stores only hash and boolean, never raw payload content
    assert "payload_hash" in last_rec
    assert "canary_hit" in last_rec
    assert last_rec["canary_hit"] is False
    assert safe_prompt not in str(last_rec)
    assert len(last_rec["payload_hash"]) == 64  # SHA-256

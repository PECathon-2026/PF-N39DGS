from __future__ import annotations

import base64
import os
import sys
from typing import Set

import pytest
import pytesseract
from PIL import Image, ImageDraw
from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.detect import dom_layer, face_layer, fusion, ocr_layer, regex_layer
from core.detect.regex_layer import Finding
from core.perception.capture import capture
from core.sanitize import (
    calculate_context_preservation,
    mask_image,
    render_sanitized_view,
    sanitize_dom,
    sanitize_text,
)
from eval.canaries.registry import generate_registry


def test_sanitize_text_placeholders():
    reg = generate_registry(42)
    card = reg.by_category("CARD")[0].value
    email = reg.by_category("EMAIL")[0].value
    pwd = reg.by_category("PASSWORD")[0].value

    sample = f"User with card {card} and email {email} used password {pwd}"
    sanitized = sanitize_text(sample)

    assert card not in sanitized
    assert email not in sanitized
    assert pwd not in sanitized

    assert "[REDACTED:CARD]" in sanitized
    assert "[REDACTED:EMAIL]" in sanitized
    assert "[REDACTED:PASSWORD]" in sanitized

    # No partial digits or length hints
    assert str(len(card)) not in sanitized
    assert card[:4] not in sanitized
    assert card[-4:] not in sanitized


def test_sanitize_dom_preserves_elements():
    reg = generate_registry(42)
    card = reg.by_category("CARD")[0].value

    mock_snapshot = {
        "url": "http://localhost/test",
        "title": "Test Page",
        "text": f"Payment Page with card {card}",
        "elements": [
            {
                "el_id": "el_0",
                "tag": "input",
                "type": "text",
                "id": "card",
                "name": "cc_num",
                "value": card,
                "text": "",
            },
            {
                "el_id": "el_1",
                "tag": "button",
                "type": "submit",
                "id": "pay",
                "name": "pay_btn",
                "value": "",
                "text": "Pay Now",
            },
        ],
    }

    findings = [
        Finding("CARD", {"element": "el_0"}, "dom", 0.95, ["dom"]),
    ]

    sanitized = sanitize_dom(mock_snapshot, findings)

    # Element preservation
    assert len(sanitized["elements"]) == 2
    el0 = sanitized["elements"][0]
    el1 = sanitized["elements"][1]

    assert el0["el_id"] == "el_0"
    assert el0["tag"] == "input"
    assert el0["id"] == "card"
    assert el0["value"] == "[REDACTED:CARD]"

    assert el1["el_id"] == "el_1"
    assert el1["tag"] == "button"
    assert el1["id"] == "pay"
    assert el1["text"] == "Pay Now"

    # Rendered string keeps labels and el_N ids
    view = render_sanitized_view(sanitized)
    assert "[el_0]" in view
    assert "[el_1]" in view
    assert "Pay Now" in view
    assert card not in view


def test_masked_image_opaque_and_no_canary_survives():
    reg = generate_registry(42)
    card = reg.by_category("CARD")[0].value

    img = Image.new("RGB", (400, 100), color="white")
    d = ImageDraw.Draw(img)
    d.text((20, 30), f"Card: {card}", fill="black")

    findings = ocr_layer.scan_image(img)
    assert len(findings) >= 1

    masked = mask_image(img, findings, padding=3)

    # Verify pixels inside finding box are opaque black (0, 0, 0)
    box = findings[0].location
    center_x = box["x"] + box["w"] // 2
    center_y = box["y"] + box["h"] // 2
    assert masked.getpixel((center_x, center_y)) == (0, 0, 0)

    # Re-OCR verification
    re_ocr_text = pytesseract.image_to_string(masked)
    assert card not in re_ocr_text


def test_all_5_scenarios_zero_canary_leakage_and_preservation():
    reg = generate_registry(42)
    all_canaries: Set[str] = set(reg.all_values())

    base_dir = os.path.dirname(os.path.abspath(__file__))
    pages_dir = os.path.join(base_dir, "pages")

    scenarios = [
        "scenario_1_ecommerce",
        "scenario_2_auth",
        "scenario_3_support",
        "scenario_4_video",
        "scenario_5_devtools",
    ]

    scenario_reports = []

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

            # 1. Detection
            d_findings = dom_layer.scan_dom(snap)
            full_text = " ".join([el.get("text", "") + " " + el.get("value", "") for el in snap.get("elements", [])])
            if snap.get("text"):
                full_text += " " + snap["text"]
            r_findings = regex_layer.scan_text(full_text)
            o_findings = ocr_layer.scan_image(screenshot_bytes)
            f_findings = face_layer.scan_image(screenshot_bytes)

            fused = fusion.fuse(d_findings + r_findings + o_findings + f_findings)

            # 2. Sanitization
            san_snap = sanitize_dom(snap, fused)
            san_rendered = render_sanitized_view(san_snap)
            masked_img = mask_image(screenshot_bytes, fused, padding=4)

            # 3. Verification - Re-OCR of masked screenshot
            re_ocr_text = pytesseract.image_to_string(masked_img)

            # Check leakage in both modalities
            leaked_text = [c for c in all_canaries if c in san_rendered]
            leaked_img = [c for c in all_canaries if c in re_ocr_text]

            # Invariant: Zero canaries survive
            assert leaked_text == [], f"Canaries leaked in sanitized text of {scn}: {leaked_text}"
            assert leaked_img == [], f"Canaries leaked in masked image of {scn}: {leaked_img}"

            # Context preservation
            orig_text = full_text
            pres_pct = calculate_context_preservation(orig_text, san_rendered, all_canaries)

            scenario_reports.append({
                "scenario": scn,
                "leaked_text_count": len(leaked_text),
                "leaked_img_count": len(leaked_img),
                "preservation_pct": pres_pct,
            })

        browser.close()

    print("\n" + "=" * 80)
    print("PRIVACY LENS: STAGE 4 SANITIZATION GATE REPORT (ALL 5 SCENARIOS)")
    print("=" * 80)
    print(f"{'Scenario':<25} | {'Text Leakage':<15} | {'Image Leakage':<15} | {'Context Preserved':<18}")
    print("-" * 80)
    for r in scenario_reports:
        print(
            f"{r['scenario']:<25} | {r['leaked_text_count']:<15} | {r['leaked_img_count']:<15} | {r['preservation_pct']:>15.1f}%"
        )
    print("=" * 80 + "\n")

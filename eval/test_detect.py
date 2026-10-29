from __future__ import annotations

import os
import sys
import pytest
from PIL import Image, ImageDraw

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.detect import dom_layer, face_layer, fusion, ocr_layer, regex_layer
from core.detect.regex_layer import Finding, scan_text
from eval.canaries.registry import generate_registry, luhn_check, verhoeff_check


def test_negative_invalid_checksum():
    assert not verhoeff_check("123456789012")
    assert not luhn_check("4111111111111112")


def test_recall_per_category():
    reg = generate_registry(42)
    bycat = {e.category: e.value for e in reg.entries}
    # build a text blob of all canaries
    text = " ".join(bycat.values())
    findings = scan_text(text)
    cats = {f.category for f in findings}
    assert "CARD" in cats
    assert "EMAIL" in cats
    assert "IP" in cats
    assert "AADHAAR" in cats
    assert "PAN" in cats
    assert "PHONE" in cats
    assert "API_KEY" in cats


def test_ocr_word_bounding_boxes():
    img = Image.new("RGB", (400, 100), color="white")
    draw = ImageDraw.Draw(img)
    draw.text((20, 30), "Card: 4104332181960018", fill="black")
    
    findings = ocr_layer.scan_image(img)
    assert any(f.category == "CARD" for f in findings)
    card_finding = next(f for f in findings if f.category == "CARD")
    assert card_finding.layer == "ocr"
    assert "ocr" in card_finding.source_layers
    assert isinstance(card_finding.location, dict)
    assert "x" in card_finding.location and "y" in card_finding.location
    assert "w" in card_finding.location and "h" in card_finding.location
    assert card_finding.location["w"] > 0
    assert card_finding.location["h"] > 0


def test_ocr_missing_binary_error(monkeypatch):
    monkeypatch.setattr(ocr_layer.pytesseract.pytesseract, "tesseract_cmd", "C:\\nonexistent\\tesseract.exe")
    with pytest.raises(RuntimeError) as excinfo:
        ocr_layer.scan_image(Image.new("RGB", (10, 10)))
    err_msg = str(excinfo.value)
    assert "Tesseract binary not found" in err_msg
    # Ensure no raw text or secret leaked in error message
    assert "4104332181960018" not in err_msg


def test_face_layer_detection():
    face_path = os.path.join(os.path.dirname(__file__), "pages", "face.jpg")
    if not os.path.exists(face_path):
        pytest.skip("Sample face image not available")
    findings = face_layer.scan_image(face_path)
    assert len(findings) >= 1
    assert any(f.category == "FACE" for f in findings)
    f = findings[0]
    assert f.layer == "face"
    assert "face" in f.source_layers
    assert f.location["w"] > 0
    assert f.location["h"] > 0


def test_fusion_overlap_and_layers():
    f1 = Finding("CARD", {"x": 10, "y": 10, "w": 50, "h": 20}, "ocr", 0.9, ["ocr"])
    f2 = Finding("CARD", {"x": 20, "y": 12, "w": 60, "h": 25}, "regex", 0.95, ["regex"])
    fused = fusion.fuse([f1, f2])
    
    # Overlapping boxes must be merged into 1 union box
    assert len(fused) == 1
    m = fused[0]
    assert m.category == "CARD"
    assert m.location["x"] == 10
    assert m.location["y"] == 10
    assert m.location["w"] == 70  # max(10+50, 20+60) - 10 = 80 - 10 = 70
    assert m.location["h"] == 27  # max(10+20, 12+25) - 10 = 37 - 10 = 27
    assert "ocr" in m.source_layers
    assert "regex" in m.source_layers
    assert m.confidence == 0.95


def test_fusion_favours_recall():
    f1 = Finding("CARD", {"x": 10, "y": 10, "w": 20, "h": 20}, "ocr", 0.9, ["ocr"])
    f2 = Finding("FACE", {"x": 100, "y": 100, "w": 50, "h": 50}, "face", 0.9, ["face"])
    f3 = Finding("PASSWORD", {"element": "el_1"}, "dom", 0.99, ["dom"])
    fused = fusion.fuse([f1, f2, f3])
    
    assert len(fused) == 3
    cats = {f.category for f in fused}
    assert cats == {"CARD", "FACE", "PASSWORD"}


def test_full_ablation_100_percent_fused_recall():
    from eval.ablation import run_ablation
    report = run_ablation()
    all_cfg = next(r for r in report["ablation_results"] if r["configuration"] == "All (Fused)")
    assert all_cfg["overall_recall"] == 1.0
    assert all_cfg["detected_count"] == all_cfg["expected_count"]

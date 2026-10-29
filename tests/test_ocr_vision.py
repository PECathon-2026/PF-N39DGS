"""Unit tests for OCR vision detection and defence-in-depth redaction."""

import io

from PIL import Image, ImageDraw

from privacylens.detect.vision import ocr_detect, ocr_redact_defence_in_depth


def test_ocr_detect_finds_card_and_bbox() -> None:
    """Test OCR detection of sensitive card in image."""
    img = Image.new("RGB", (600, 100), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((30, 35), "Visa Card: 4532 0151 1283 0366", fill=(0, 0, 0))

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    png_bytes = buf.getvalue()

    findings = ocr_detect(png_bytes)
    assert len(findings) >= 1
    card_f = next((f for f in findings if f.type == "CARD"), None)
    assert card_f is not None
    assert card_f.bbox is not None
    ymin, xmin, ymax, xmax = card_f.bbox
    assert xmax > xmin
    assert ymax > ymin


def test_ocr_redact_defence_in_depth_patches_and_verifies() -> None:
    """Test secondary OCR layer redacts residual text and verifies cleanliness."""
    img = Image.new("RGB", (500, 100), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 30), "Contact: support.team@privacylens.test", fill=(0, 0, 0))

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    raw_bytes = buf.getvalue()

    patched_png, withheld = ocr_redact_defence_in_depth(raw_bytes, padding_px=6)
    assert not withheld
    assert patched_png is not None

    # Verify that patched PNG no longer contains the sensitive email finding
    remaining = ocr_detect(patched_png)
    assert not any(f.type == "EMAIL" for f in remaining)

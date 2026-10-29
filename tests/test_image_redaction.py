"""Unit tests for visual screenshot redaction and pixel verification."""

from PIL import Image, ImageDraw

from privacylens.sanitize.image import (
    draw_secondary_pillow_masks,
    verify_redaction_pixels,
)


def test_verify_redaction_pixels_success() -> None:
    """Test pixel verification passes when rect is fully black."""
    img = Image.new("RGB", (200, 200), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    # Draw solid black box from (20, 20) to (80, 80)
    draw.rectangle([20, 20, 80, 80], fill=(0, 0, 0))

    rect = {"x": 20.0, "y": 20.0, "w": 60.0, "h": 60.0}
    assert verify_redaction_pixels(img, [rect], dpr=1.0, threshold=0.99) is True


def test_verify_redaction_pixels_fails_when_unmasked() -> None:
    """Test pixel verification fails closed when a sensitive rect has unmasked pixels."""
    img = Image.new("RGB", (200, 200), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    # Partially black box: 50% black, 50% white
    draw.rectangle([20, 20, 50, 80], fill=(0, 0, 0))

    rect = {"x": 20.0, "y": 20.0, "w": 60.0, "h": 60.0}
    assert verify_redaction_pixels(img, [rect], dpr=1.0, threshold=0.99) is False


def test_draw_secondary_pillow_masks_and_dpr() -> None:
    """Test secondary Pillow masking with device pixel ratio 2."""
    img = Image.new("RGB", (400, 400), color=(255, 255, 255))
    rects = [{"x": 10.0, "y": 10.0, "w": 50.0, "h": 20.0}]

    # With DPR = 2.0, rect should cover (20, 20) to (120, 60)
    masked_img = draw_secondary_pillow_masks(img, rects, dpr=2.0)
    assert verify_redaction_pixels(masked_img, rects, dpr=2.0, threshold=0.99) is True


def test_scrolled_and_wrapped_rects() -> None:
    """Test pixel verification on multi-line wrapped and scrolled coordinates."""
    img = Image.new("RGB", (500, 1000), color=(255, 255, 255))
    # Line 1 and Line 2 of a wrapped paragraph, scrolled down at y=600
    rect_line1 = {"x": 50.0, "y": 600.0, "w": 200.0, "h": 20.0}
    rect_line2 = {"x": 50.0, "y": 625.0, "w": 150.0, "h": 20.0}

    masked = draw_secondary_pillow_masks(img, [rect_line1, rect_line2], dpr=1.0)
    assert verify_redaction_pixels(masked, [rect_line1, rect_line2], dpr=1.0) is True


def test_empty_and_zero_size_rects_handled_safely() -> None:
    """Ensure zero-width or out-of-bounds rects do not crash pixel verification."""
    img = Image.new("RGB", (100, 100), color=(255, 255, 255))
    zero_rect = {"x": 10.0, "y": 10.0, "w": 0.0, "h": 0.0}
    out_of_bounds = {"x": 500.0, "y": 500.0, "w": 50.0, "h": 50.0}

    assert verify_redaction_pixels(img, [zero_rect, out_of_bounds], dpr=1.0) is True

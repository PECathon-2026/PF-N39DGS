"""Computer vision and OCR detector for rendered browser screens."""

from __future__ import annotations

import io
import logging
from typing import Any

import pytesseract
from PIL import Image, ImageDraw

from privacylens.config import settings
from privacylens.detect.base import Detector, register_detector
from privacylens.detect.text_api import detect_text
from privacylens.models import Finding

logger = logging.getLogger(__name__)

# Ensure pytesseract uses configured binary path
if settings.tesseract.tesseract_cmd:
    pytesseract.pytesseract.tesseract_cmd = settings.tesseract.tesseract_cmd


def ocr_words(png: bytes | Image.Image) -> list[dict[str, Any]]:
    """Extract individual words with spatial bounding boxes from an image via Tesseract.

    Args:
        png: PNG image bytes or PIL Image instance.

    Returns:
        List of word dictionaries containing text, left, top, width, height, and line indices.
    """
    image = Image.open(io.BytesIO(png)) if isinstance(png, (bytes, bytearray)) else png

    # Upscale low-resolution images for higher OCR recognition accuracy
    scale_factor = 2 if image.height < 600 else 1
    if scale_factor > 1:
        ocr_image = image.resize(
            (image.width * scale_factor, image.height * scale_factor),
            Image.Resampling.BICUBIC,
        )
    else:
        ocr_image = image

    try:
        data = pytesseract.image_to_data(ocr_image, output_type=pytesseract.Output.DICT)
    except Exception:
        logger.warning("Tesseract OCR extraction failed", exc_info=True)
        return []

    words: list[dict[str, Any]] = []
    n_boxes = len(data.get("text", []))

    for i in range(n_boxes):
        text = (data["text"][i] or "").strip()
        if not text:
            continue
        try:
            conf = float(data["conf"][i])
        except (ValueError, TypeError):
            conf = 0.0

        left = int(data["left"][i]) / scale_factor
        top = int(data["top"][i]) / scale_factor
        width = int(data["width"][i]) / scale_factor
        height = int(data["height"][i]) / scale_factor

        words.append(
            {
                "text": text,
                "left": int(left),
                "top": int(top),
                "width": max(1, int(width)),
                "height": max(1, int(height)),
                "conf": conf,
                "line_key": (
                    data.get("block_num", [0])[i],
                    data.get("par_num", [0])[i],
                    data.get("line_num", [0])[i],
                ),
            }
        )
    return words


def ocr_detect(png: bytes | Image.Image) -> list[Finding]:
    """Group OCR words into lines, run pattern detection, and return findings with bboxes.

    Args:
        png: PNG image bytes or PIL Image instance.

    Returns:
        List of Finding objects with image-space pixel bounding boxes.
    """
    words = ocr_words(png)
    if not words:
        return []

    # Group words by line key
    lines: dict[tuple[int, int, int], list[dict[str, Any]]] = {}
    for w in words:
        lines.setdefault(w["line_key"], []).append(w)

    findings: list[Finding] = []

    for line_words in lines.values():
        # Construct line text while tracking character offsets per word
        line_parts: list[str] = []
        word_spans: list[tuple[int, int, dict[str, Any]]] = []
        curr_offset = 0

        for idx, w in enumerate(line_words):
            if idx > 0:
                line_parts.append(" ")
                curr_offset += 1
            w_text = w["text"]
            start_off = curr_offset
            end_off = curr_offset + len(w_text)
            line_parts.append(w_text)
            word_spans.append((start_off, end_off, w))
            curr_offset = end_off

        full_line = "".join(line_parts)
        if not full_line.strip():
            continue

        # Run text detection on assembled line
        text_findings = detect_text(full_line, enable_presidio=False)

        for tf in text_findings:
            f_start = tf.start if tf.start is not None else 0
            f_end = tf.end if tf.end is not None else len(full_line)

            # Find all words that intersect the finding span
            intersecting_words = [
                w
                for (s_off, e_off, w) in word_spans
                if max(s_off, f_start) < min(e_off, f_end)
            ]
            if not intersecting_words:
                continue

            ymin = float(min(w["top"] for w in intersecting_words))
            xmin = float(min(w["left"] for w in intersecting_words))
            ymax = float(max(w["top"] + w["height"] for w in intersecting_words))
            xmax = float(max(w["left"] + w["width"] for w in intersecting_words))

            findings.append(
                Finding(
                    type=tf.type,
                    start=tf.start,
                    end=tf.end,
                    bbox=(ymin, xmin, ymax, xmax),
                    confidence=tf.confidence * 0.9,
                    source="ocr",
                    rule_id=f"ocr_{tf.rule_id}",
                    element_id=None,
                )
            )

    return findings


def ocr_redact_defence_in_depth(
    png: bytes,
    padding_px: int = 4,
) -> tuple[bytes | None, bool]:
    """Run secondary OCR defence-in-depth on a redacted screenshot.

    Inspects redacted PNG for any residual text leaks. If detected, applies
    padded black bounding boxes and re-verifies. If any sensitive finding
    persists after secondary patching, withholds the image (fail closed).

    Args:
        png: PNG screenshot bytes.
        padding_px: Extra pixel padding around detected OCR text boxes.

    Returns:
        Tuple of (sanitized_png_bytes, withheld_flag).
    """
    initial_findings = ocr_detect(png)
    if not initial_findings:
        return png, False

    logger.warning("OCR defence layer detected %d unmasked text items", len(initial_findings))

    try:
        img = Image.open(io.BytesIO(png)).convert("RGB")
        draw = ImageDraw.Draw(img)
        img_w, img_h = img.size

        for f in initial_findings:
            if not f.bbox:
                continue
            ymin, xmin, ymax, xmax = f.bbox
            x0 = max(0, int(xmin - padding_px))
            y0 = max(0, int(ymin - padding_px))
            x1 = min(img_w, int(xmax + padding_px))
            y1 = min(img_h, int(ymax + padding_px))
            draw.rectangle([x0, y0, x1, y1], fill=(0, 0, 0))

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        patched_png = buf.getvalue()

        # Re-run OCR verification
        recheck_findings = ocr_detect(patched_png)
        if recheck_findings:
            logger.error(
                "OCR defence layer still detected %d items after patching; withholding image",
                len(recheck_findings),
            )
            return None, True

        return patched_png, False
    except Exception:
        logger.error("OCR defence patching failed; withholding image", exc_info=True)
        return None, True


@register_detector
class VisionDetector(Detector):
    """Detects visual PII such as human faces and on-screen text via OCR."""

    @property
    def name(self) -> str:
        """Detector name identifier."""
        return "vision"

    def detect(self, context: Any) -> list[Finding]:
        """Process screenshot buffer or visual frame for sensitive objects."""
        if isinstance(context, (bytes, bytearray)):
            return ocr_detect(context)
        if isinstance(context, Image.Image):
            return ocr_detect(context)
        return []

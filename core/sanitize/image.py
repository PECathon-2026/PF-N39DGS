from __future__ import annotations

import base64
import io
import os
from typing import Any, Dict, List, Union

from PIL import Image, ImageDraw

from core.detect.regex_layer import Finding


def _load_image(image_input: Union[str, bytes, Image.Image]) -> Image.Image:
    if isinstance(image_input, Image.Image):
        return image_input.copy()
    if isinstance(image_input, bytes):
        return Image.open(io.BytesIO(image_input))
    if isinstance(image_input, str):
        # Support base64 string or file path
        if os.path.isfile(image_input):
            return Image.open(image_input)
        try:
            raw_bytes = base64.b64decode(image_input)
            return Image.open(io.BytesIO(raw_bytes))
        except Exception:
            raise FileNotFoundError(f"Image not found at path and not valid base64: {image_input[:50]}")
    raise TypeError(f"Unsupported image input type: {type(image_input).__name__}")


def mask_image(
    image_input: Union[str, bytes, Image.Image],
    findings: List[Finding],
    padding: int = 3,
) -> Image.Image:
    """Mask sensitive visual regions with opaque rectangles using Pillow.

    Uses completely solid opaque blackout (fill=(0, 0, 0)) with padding to prevent
    edge-bleed leakage. Does not use reversible blur or pixelation.
    """
    from core.sanitize.text import is_sanitization_enabled

    img = _load_image(image_input)
    if not is_sanitization_enabled():
        return img

    if img.mode != "RGB":
        img = img.convert("RGB")

    draw = ImageDraw.Draw(img)

    for f in findings:
        loc = f.location
        if isinstance(loc, dict) and "x" in loc and "y" in loc:
            w = loc.get("w", loc.get("width"))
            h = loc.get("h", loc.get("height"))
            if w is not None and h is not None:
                x0 = max(0, int(loc["x"] - padding))
                y0 = max(0, int(loc["y"] - padding))
                x1 = min(img.width, int(loc["x"] + w + padding))
                y1 = min(img.height, int(loc["y"] + h + padding))

                # Skip if clamped box has zero or negative area
                # (happens when image is smaller than the DOM bounding box, e.g. tiny test PNGs)
                if x1 <= x0 or y1 <= y0:
                    continue

                # Draw completely opaque solid black fill (no blur, no pixelation)
                draw.rectangle([x0, y0, x1, y1], fill=(0, 0, 0), outline=None)

    return img


def mask_image_bytes(
    image_input: Union[str, bytes, Image.Image],
    findings: List[Finding],
    padding: int = 3,
    format: str = "PNG",
) -> bytes:
    """Return the masked image as raw bytes."""
    masked = mask_image(image_input, findings, padding=padding)
    buf = io.BytesIO()
    masked.save(buf, format=format)
    return buf.getvalue()


def mask_image_b64(
    image_input: Union[str, bytes, Image.Image],
    findings: List[Finding],
    padding: int = 3,
    format: str = "PNG",
) -> str:
    """Return the masked image as a base64 encoded string."""
    raw_bytes = mask_image_bytes(image_input, findings, padding=padding, format=format)
    return base64.b64encode(raw_bytes).decode("ascii")

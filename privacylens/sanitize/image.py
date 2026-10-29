"""Visual screenshot redaction engine with live in-page DOM masking and pixel verification."""

from __future__ import annotations

import io
import logging
from typing import TYPE_CHECKING, Any

from PIL import Image, ImageDraw

from privacylens.capture import ElementSnapshot
from privacylens.models import Finding

if TYPE_CHECKING:
    from playwright.async_api import Page

logger = logging.getLogger(__name__)

# Script to inject live DOM masks before taking screenshots
_INJECT_MASKS_JS = """
(findingsData) => {
    window.__privacylensAltered = [];
    const recordedRects = [];
    const scrollX = window.scrollX || window.pageXOffset || 0;
    const scrollY = window.scrollY || window.pageYOffset || 0;

    for (const f of findingsData) {
        if (!f.element_id) continue;
        const selector = `[data-pl-id="${f.element_id}"]`;
        const elem = document.getElementById(f.element_id) || document.querySelector(selector);
        if (!elem) continue;

        const isInput = elem.tagName === 'INPUT' || elem.tagName === 'TEXTAREA';
        const isMedia = (
            elem.tagName === 'IMG' || elem.tagName === 'SVG' ||
            elem.tagName === 'VIDEO' || elem.tagName === 'CANVAS'
        );

        if (f.is_structural || f.start === null || isInput || isMedia) {
            // Element-level masking
            const origStyle = elem.getAttribute('style') || '';
            window.__privacylensAltered.push({ elem, origStyle });
            elem.style.setProperty('background', '#000000', 'important');
            elem.style.setProperty('color', '#000000', 'important');
            elem.style.setProperty('border-color', '#000000', 'important');
            elem.style.setProperty('filter', 'brightness(0)', 'important');
            if (isInput) {
                elem.style.setProperty('-webkit-text-fill-color', '#000000', 'important');
            }
            const r = elem.getBoundingClientRect();
            if (r.width > 0 && r.height > 0) {
                recordedRects.push({
                    x: r.left + scrollX,
                    y: r.top + scrollY,
                    w: r.width,
                    h: r.height,
                    element_id: f.element_id,
                });
            }
        } else {
            // Text Range masking
            try {
                let currentOffset = 0;
                const walker = document.createTreeWalker(elem, NodeFilter.SHOW_TEXT, null, false);
                let node;
                let startNode = null, startNodeOffset = 0;
                let endNode = null, endNodeOffset = 0;

                while ((node = walker.nextNode())) {
                    const len = node.nodeValue.length;
                    if (!startNode && currentOffset + len >= f.start) {
                        startNode = node;
                        startNodeOffset = f.start - currentOffset;
                    }
                    if (startNode && currentOffset + len >= f.end) {
                        endNode = node;
                        endNodeOffset = f.end - currentOffset;
                        break;
                    }
                    currentOffset += len;
                }

                if (startNode && endNode) {
                    const range = document.createRange();
                    range.setStart(startNode, startNodeOffset);
                    range.setEnd(endNode, endNodeOffset);

                    const span = document.createElement('span');
                    span.className = 'privacylens-mask-span';
                    span.style.setProperty('background', '#000000', 'important');
                    span.style.setProperty('color', '#000000', 'important');
                    span.style.setProperty('display', 'inline', 'important');
                    span.style.setProperty('border-radius', '2px', 'important');

                    range.surroundContents(span);
                    const r = span.getBoundingClientRect();
                    if (r.width > 0 && r.height > 0) {
                        recordedRects.push({
                            x: r.left + scrollX,
                            y: r.top + scrollY,
                            w: r.width,
                            h: r.height,
                            element_id: f.element_id,
                        });
                    }
                }
            } catch (err) {
                // Fallback to element bounding rect if text range wrapping fails
                const r = elem.getBoundingClientRect();
                if (r.width > 0 && r.height > 0) {
                    recordedRects.push({
                        x: r.left + scrollX,
                        y: r.top + scrollY,
                        w: r.width,
                        h: r.height,
                        element_id: f.element_id,
                    });
                }
            }
        }
    }
    return recordedRects;
}
"""

_REMOVE_MASKS_JS = """
() => {
    // 1. Unwrap all created mask spans
    const spans = Array.from(document.querySelectorAll('.privacylens-mask-span'));
    for (const span of spans) {
        const parent = span.parentNode;
        if (!parent) continue;
        while (span.firstChild) {
            parent.insertBefore(span.firstChild, span);
        }
        parent.removeChild(span);
    }

    // 2. Restore altered element inline styles
    if (window.__privacylensAltered) {
        for (const item of window.__privacylensAltered) {
            if (item.origStyle) {
                item.elem.setAttribute('style', item.origStyle);
            } else {
                item.elem.removeAttribute('style');
            }
        }
        window.__privacylensAltered = [];
    }
}
"""


def verify_redaction_pixels(
    image: Image.Image,
    rects: list[dict[str, float]],
    dpr: float = 1.0,
    threshold: float = 0.99,
) -> bool:
    """Verify that every redaction rectangle in the final PNG is at least 99% mask color.

    Args:
        image: PIL RGB or RGBA Image.
        rects: List of bounding rect dicts with x, y, w, h in CSS pixels.
        dpr: Device pixel ratio.
        threshold: Minimum fraction of black pixels required (default: 0.99).

    Returns:
        True if all rectangles meet the 99% mask threshold, False otherwise.
    """
    img_w, img_h = image.size
    rgb_img = image.convert("RGB")

    for r in rects:
        x0 = max(0, int(r["x"] * dpr))
        y0 = max(0, int(r["y"] * dpr))
        x1 = min(img_w, int((r["x"] + r["w"]) * dpr))
        y1 = min(img_h, int((r["y"] + r["h"]) * dpr))

        if x1 <= x0 or y1 <= y0:
            continue

        box = rgb_img.crop((x0, y0, x1, y1))
        total_pixels = box.width * box.height
        if total_pixels == 0:
            continue

        # Count mask pixels (RGB <= 5 to allow slight compression tolerances)
        colors = box.getcolors(maxcolors=max(256, total_pixels)) or []
        mask_pixels = sum(
            count
            for count, col in colors
            if len(col) >= 3 and col[0] <= 5 and col[1] <= 5 and col[2] <= 5
        )
        ratio = mask_pixels / total_pixels

        if ratio < threshold:
            logger.warning(
                "Redaction pixel verification failed on rect %s: %.2f%% black (required %.2f%%)",
                r,
                ratio * 100,
                threshold * 100,
            )
            return False

    return True


def draw_secondary_pillow_masks(
    image: Image.Image,
    rects: list[dict[str, float]],
    dpr: float = 1.0,
) -> Image.Image:
    """Draw solid opaque black rectangles over sensitive rects using Pillow."""
    img_copy = image.copy().convert("RGB")
    draw = ImageDraw.Draw(img_copy)
    img_w, img_h = img_copy.size

    for r in rects:
        x0 = max(0, int(r["x"] * dpr))
        y0 = max(0, int(r["y"] * dpr))
        x1 = min(img_w, int((r["x"] + r["w"]) * dpr))
        y1 = min(img_h, int((r["y"] + r["h"]) * dpr))
        if x1 > x0 and y1 > y0:
            draw.rectangle([x0, y0, x1, y1], fill=(0, 0, 0))

    return img_copy


async def sanitize_screenshot(
    page: Page,
    findings: list[Finding],
    raw_png: bytes | None = None,
    elements: list[ElementSnapshot] | None = None,
) -> tuple[bytes | None, bool]:
    """Capture and sanitize a visual screenshot with pixel verification.

    Applies primary in-page DOM masking (wrapping text ranges, styling inputs/media),
    captures the full page screenshot, verifies that 99%+ of pixels in sensitive
    rectangles are black, and always removes in-page DOM masks in a finally block.

    Args:
        page: Live Playwright Page instance.
        findings: List of sensitive findings to redact.
        raw_png: Optional raw screenshot bytes for fallback processing.
        elements: Optional list of ElementSnapshots.

    Returns:
        Tuple of (redacted_png_bytes, withheld_flag).
        If withheld_flag is True, png_bytes is None (fail closed).
    """
    if not findings:
        # No DOM findings: capture screenshot and run OCR defence layer
        try:
            shot = await page.screenshot(full_page=True)
            from privacylens.detect.vision import ocr_redact_defence_in_depth

            final_png, ocr_withheld = ocr_redact_defence_in_depth(shot)
            return final_png, ocr_withheld
        except Exception:
            return None, True

    # Prepare findings data for injection
    findings_data = [
        {
            "element_id": f.element_id,
            "start": f.start,
            "end": f.end,
            "is_structural": f.is_structural,
            "type": f.type,
        }
        for f in findings
        if f.element_id
    ]

    recorded_rects: list[dict[str, float]] = []

    try:
        # 1. Primary method: Inject in-page live masks
        raw_rects = await page.evaluate(_INJECT_MASKS_JS, findings_data)
        recorded_rects = [dict(r) for r in raw_rects]

        # 2. Capture screenshot with live masks rendered
        shot_bytes = await page.screenshot(full_page=True)
        img = Image.open(io.BytesIO(shot_bytes))

        # Determine device pixel ratio
        dpr = float(await page.evaluate("() => window.devicePixelRatio || 1.0"))

        # 3. Secondary Pillow fallback: reinforce all recorded rects
        if recorded_rects:
            img = draw_secondary_pillow_masks(img, recorded_rects, dpr=dpr)

        # 4. Pixel verification: assert >= 99% black in every redaction box
        if not verify_redaction_pixels(img, recorded_rects, dpr=dpr, threshold=0.99):
            logger.error("Pixel verification failed for screenshot; withholding image")
            return None, True

        out_buf = io.BytesIO()
        img.save(out_buf, format="PNG")
        masked_png = out_buf.getvalue()

        # 5. Part 3: OCR defence-in-depth layer
        from privacylens.detect.vision import ocr_redact_defence_in_depth

        final_png, ocr_withheld = ocr_redact_defence_in_depth(masked_png)
        if ocr_withheld or final_png is None:
            logger.warning("OCR defence layer withheld image")
            return None, True

        return final_png, False

    except Exception:
        logger.error(
            "Screenshot redaction encountered unexpected error; withholding image",
            exc_info=True,
        )
        return None, True

    finally:
        # ALWAYS remove live masks from the page DOM
        try:
            await page.evaluate(_REMOVE_MASKS_JS)
        except Exception:
            logger.warning("Failed to clean up in-page visual masks", exc_info=True)


class ImageSanitizer:
    """Wrapper class providing backward-compatible interface for image redaction."""

    def sanitize_image(self, image: Any, findings: list[Finding]) -> Any:
        """Sanitize a PIL Image or byte stream using secondary masking."""
        if not isinstance(image, Image.Image):
            return image
        rects: list[dict[str, float]] = []
        for f in findings:
            if f.bbox:
                ymin, xmin, ymax, xmax = f.bbox
                rects.append({"x": xmin, "y": ymin, "w": xmax - xmin, "h": ymax - ymin})
        return draw_secondary_pillow_masks(image, rects, dpr=1.0)

from __future__ import annotations

import io
import os
import shutil
from typing import Any, Dict, List, Union

from PIL import Image
import pytesseract

from core.detect.regex_layer import Finding, scan_text

# Windows tesseract path - explicitly set default or env
TESSERACT_CMD = os.environ.get(
    "TESSERACT_CMD",
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    if os.path.exists(r"C:\Program Files\Tesseract-OCR\tesseract.exe")
    else (shutil.which("tesseract") or r"C:\Program Files\Tesseract-OCR\tesseract.exe"),
)
pytesseract.pytesseract.tesseract_cmd = TESSERACT_CMD


def _ensure_tesseract_binary() -> None:
    cmd = pytesseract.pytesseract.tesseract_cmd
    if not cmd or not os.path.isfile(cmd):
        raise RuntimeError(
            "Tesseract binary not found; please install Tesseract-OCR and configure TESSERACT_CMD"
        )


def _load_image(image_input: Union[str, bytes, Image.Image]) -> Image.Image:
    if isinstance(image_input, Image.Image):
        return image_input
    if isinstance(image_input, bytes):
        return Image.open(io.BytesIO(image_input))
    if isinstance(image_input, str):
        if not os.path.isfile(image_input):
            raise FileNotFoundError("Image file does not exist at specified path")
        return Image.open(image_input)
    raise TypeError(f"Unsupported image input type: {type(image_input).__name__}")


def scan_image(image_input: Union[str, bytes, Image.Image]) -> List[Finding]:
    _ensure_tesseract_binary()
    img = _load_image(image_input)

    # Extract word bounding box data
    data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)

    tokens: List[Dict[str, Any]] = []
    char_offset = 0
    num_entries = len(data.get("text", []))

    for i in range(num_entries):
        raw_text = data["text"][i]
        word = raw_text.strip()
        if not word:
            continue
        start_char = char_offset
        end_char = start_char + len(word)
        box = {
            "x": int(data["left"][i]),
            "y": int(data["top"][i]),
            "w": int(data["width"][i]),
            "h": int(data["height"][i]),
        }
        tokens.append({
            "word": word,
            "start": start_char,
            "end": end_char,
            "box": box,
        })
        char_offset = end_char + 1  # 1 space between words

    if not tokens:
        return []

    full_text = " ".join(t["word"] for t in tokens)
    text_findings = scan_text(full_text)

    ocr_findings: List[Finding] = []
    for f in text_findings:
        loc = f.location
        if not isinstance(loc, dict) or "start" not in loc or "end" not in loc:
            continue
        m_start = loc["start"]
        m_end = loc["end"]

        # Find all tokens overlapping with the match span
        matched_tokens = [
            t for t in tokens
            if t["start"] < m_end and t["end"] > m_start
        ]

        if matched_tokens:
            min_x = min(t["box"]["x"] for t in matched_tokens)
            min_y = min(t["box"]["y"] for t in matched_tokens)
            max_x = max(t["box"]["x"] + t["box"]["w"] for t in matched_tokens)
            max_y = max(t["box"]["y"] + t["box"]["h"] for t in matched_tokens)
            bbox = {
                "x": int(min_x),
                "y": int(min_y),
                "w": int(max_x - min_x),
                "h": int(max_y - min_y),
            }
        else:
            bbox = loc

        ocr_findings.append(
            Finding(
                category=f.category,
                location=bbox,
                layer="ocr",
                confidence=f.confidence,
                source_layers=["ocr"],
            )
        )

    return ocr_findings

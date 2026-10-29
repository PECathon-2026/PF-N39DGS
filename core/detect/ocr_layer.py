from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List

import pytesseract
from PIL import Image

from core.detect.regex_layer import Finding, scan_text

# Windows tesseract path
TESSERACT_CMD = os.environ.get("TESSERACT_CMD", r"C:\Program Files\Tesseract-OCR\tesseract.exe")
pytesseract.pytesseract.tesseract_cmd = TESSERACT_CMD


def scan_image(image_path: str) -> List[Finding]:
    if not os.path.exists(TESSERACT_CMD):
        raise RuntimeError("Tesseract binary not found; install it and set TESSERACT_CMD")
    img = Image.open(image_path)
    text = pytesseract.image_to_string(img)
    findings = scan_text(text)
    # map each finding layer to ocr
    out = []
    for f in findings:
        out.append(Finding(f.category, f.location, "ocr", f.confidence))
    return out
PY
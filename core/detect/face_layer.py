from __future__ import annotations

import io
import os
from typing import List, Union

import cv2
import numpy as np
from PIL import Image

from core.detect.regex_layer import Finding


def _get_cascade_path() -> str:
    candidates = []
    if hasattr(cv2, "data") and hasattr(cv2.data, "haarcascades"):
        candidates.append(os.path.join(cv2.data.haarcascades, "haarcascade_frontalface_default.xml"))
    env_path = os.environ.get("HAARCASCADE_PATH")
    if env_path:
        candidates.insert(0, env_path)
    for p in candidates:
        if p and os.path.isfile(p):
            return p
    return ""


def _to_cv2_image(image_input: Union[str, bytes, np.ndarray, Image.Image]) -> np.ndarray | None:
    if isinstance(image_input, np.ndarray):
        return image_input
    if isinstance(image_input, Image.Image):
        rgb = np.array(image_input.convert("RGB"))
        return cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
    if isinstance(image_input, bytes):
        nparr = np.frombuffer(image_input, np.uint8)
        return cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if isinstance(image_input, str):
        if not os.path.isfile(image_input):
            return None
        return cv2.imread(image_input)
    return None


def scan_image(image_input: Union[str, bytes, np.ndarray, Image.Image]) -> List[Finding]:
    findings: List[Finding] = []
    cascade_path = _get_cascade_path()
    if not cascade_path:
        return findings

    clf = cv2.CascadeClassifier(cascade_path)
    if clf.empty():
        return findings

    img = _to_cv2_image(image_input)
    if img is None:
        return findings

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    faces = clf.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=4, minSize=(30, 30))
    for (x, y, w, h) in faces:
        findings.append(
            Finding(
                category="FACE",
                location={"x": int(x), "y": int(y), "w": int(w), "h": int(h)},
                layer="face",
                confidence=0.9,
                source_layers=["face"],
            )
        )
    return findings

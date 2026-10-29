from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List

import cv2

from core.detect.regex_layer import Finding


def scan_image(image_path: str) -> List[Finding]:
    findings: List[Finding] = []
    cascade_path = os.path.join(cv2.data.haarcascades, "haarcascade_frontalface_default.xml")
    if not os.path.exists(cascade_path):
        return findings
    clf = cv2.CascadeClassifier(cascade_path)
    img = cv2.imread(image_path)
    if img is None:
        return findings
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    faces = clf.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
    for (x, y, w, h) in faces:
        findings.append(Finding("FACE", {"x": int(x), "y": int(y), "w": int(w), "h": int(h)}, "face", 0.9))
    return findings

"""Computer vision and OCR detector for rendered browser screens."""

from __future__ import annotations

import logging
from typing import Any

import pytesseract

from privacylens.config import settings
from privacylens.detect.base import Detector, register_detector
from privacylens.models import Finding

logger = logging.getLogger(__name__)

# Ensure pytesseract uses configured binary path
if settings.tesseract.tesseract_cmd:
    pytesseract.pytesseract.tesseract_cmd = settings.tesseract.tesseract_cmd


@register_detector
class VisionDetector(Detector):
    """Detects visual PII such as human faces and on-screen text via OCR."""

    @property
    def name(self) -> str:
        """Detector name identifier."""
        return "vision"

    def detect(self, context: Any) -> list[Finding]:
        """Process screenshot buffer or visual frame for sensitive objects.

        Args:
            context: Image bytes, numpy array, or PIL image.

        Returns:
            List of detected sensitive visual findings.
        """
        logger.debug("Executing VisionDetector")
        # Visual OCR and face detection stub
        return []

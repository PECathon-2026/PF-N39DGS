"""Text detection API for DOM-independent string sanitization and egress filtering."""

from __future__ import annotations

import logging

from privacylens.detect.engine import DetectionEngine
from privacylens.detect.patterns import PatternDetector
from privacylens.detect.presidio_detector import PresidioDetector
from privacylens.models import Finding

logger = logging.getLogger(__name__)

# Singletons for performance across calls
_PATTERN_DETECTOR = PatternDetector()
_PRESIDIO_DETECTOR = PresidioDetector()
_ENGINE = DetectionEngine(enabled_detectors=["pattern", "presidio"])


def detect_text(
    text: str,
    hint: str | None = None,
    enable_presidio: bool = True,
) -> list[Finding]:
    """Detect sensitive entities within a plain text string without DOM context.

    Uses pattern detectors (checksum-validated regexes) and optionally Presidio
    (restricted to PERSON and LOCATION). Overlapping spans are resolved via the
    DetectionEngine priority hierarchy.

    Args:
        text: Plain string to inspect for sensitive entities.
        hint: Optional contextual hint (e.g. 'cvv', 'password', 'token').
        enable_presidio: Whether to execute Presidio NER on the text.

    Returns:
        List of deduplicated, priority-resolved Finding objects with tight spans.
    """
    if not text or not text.strip():
        return []

    raw_findings: list[Finding] = []

    # 1. Pattern detector (Luhn, Verhoeff, PAN, API keys, JWT, emails, phones, IPs, OTP, CVV)
    try:
        pat_findings = _PATTERN_DETECTOR.detect_text(text, context_hint=hint)
        raw_findings.extend(pat_findings)
    except Exception:
        logger.warning("Pattern detection failed on text span", exc_info=True)

    # 2. Presidio detector (PERSON, LOCATION)
    if enable_presidio:
        try:
            pres_findings = _PRESIDIO_DETECTOR.detect_text(text)
            raw_findings.extend(pres_findings)
        except Exception:
            logger.warning("Presidio detection failed on text span", exc_info=True)

    # 3. Resolve conflicts, overlapping spans, and prioritize
    return _ENGINE.resolve_findings(raw_findings)


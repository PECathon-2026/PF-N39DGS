"""Orchestrator engine coordinating text, structural, Presidio, and vision detectors."""

from __future__ import annotations

import logging
from typing import Any

from privacylens.capture import PageSnapshot
from privacylens.config import Settings, settings
from privacylens.detect.base import get_detector, list_detectors
from privacylens.models import Finding

logger = logging.getLogger(__name__)

# Priority ranking to resolve conflicting cross-type entity detections
_TYPE_PRIORITY: dict[str, int] = {
    "CARD": 100,
    "AADHAAR": 95,
    "PAN": 90,
    "API_KEY": 85,
    "JWT": 84,
    "TOKEN": 83,
    "PASSWORD": 80,
    "OTP": 75,
    "CVV": 70,
    "EMAIL": 65,
    "PHONE": 60,
    "IP": 55,
    "NAME": 50,
    "ADDRESS": 45,
    "EXPIRY": 42,
    "FACE": 40,
}


def _overlaps(f1: Finding, f2: Finding) -> bool:
    """Determine whether two findings have overlapping text spans or element bounds."""
    # If on different elements, they do not overlap
    if f1.element_id and f2.element_id and f1.element_id != f2.element_id:
        return False

    # Check character spans
    if f1.start is not None and f1.end is not None and f2.start is not None and f2.end is not None:
        return max(f1.start, f2.start) < min(f1.end, f2.end)

    # One covers the entire element
    if (f1.start is None or f2.start is None) and f1.element_id == f2.element_id:
        return True

    return False


class DetectionEngine:
    """Coordinates detection strategies, deduplication, and priority resolution."""

    def __init__(
        self,
        enabled_detectors: list[str] | None = None,
        app_settings: Settings | None = None,
    ) -> None:
        """Initialize engine with enabled detectors.

        Args:
            enabled_detectors: List of detector names to load.
            app_settings: Optional application settings.
        """
        cfg = app_settings or settings
        if enabled_detectors is not None:
            self._detector_names = enabled_detectors
        else:
            self._detector_names = [
                d for d in cfg.detectors.enabled if d in list_detectors()
            ]
        logger.info("Initialized DetectionEngine with detectors: %s", self._detector_names)

    def scan(self, context: Any) -> list[Finding]:
        """Run all enabled detectors and aggregate findings."""
        raw_findings: list[Finding] = []
        for name in self._detector_names:
            detector_cls = get_detector(name)
            if detector_cls is None:
                continue
            try:
                detector = detector_cls()
                findings = detector.detect(context)
                raw_findings.extend(findings)
            except Exception as err:
                logger.error("Error executing detector '%s': %s", name, err)

        return self.resolve_findings(raw_findings)

    def detect_snapshot(self, snapshot: PageSnapshot) -> list[Finding]:
        """Detect all sensitive entities across a captured PageSnapshot."""
        return self.scan(snapshot)

    def detect_text(self, text: str) -> list[Finding]:
        """Scan raw text string across enabled text detectors."""
        return self.scan(text)

    def resolve_findings(self, findings: list[Finding]) -> list[Finding]:
        """Merge same-type overlaps and resolve cross-type conflicts by priority.

        Args:
            findings: Unfiltered list of findings.

        Returns:
            Resolved, non-overlapping findings sorted by position.
        """
        if not findings:
            return []

        # Sort findings by start span or element_id
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                f.element_id or "",
                f.start if f.start is not None else -1,
                -_TYPE_PRIORITY.get(f.type, 0),
                -f.confidence,
            ),
        )

        resolved: list[Finding] = []
        for candidate in sorted_findings:
            merged = False
            for idx, existing in enumerate(resolved):
                if _overlaps(candidate, existing):
                    merged = True
                    p_candidate = _TYPE_PRIORITY.get(candidate.type, 0)
                    p_existing = _TYPE_PRIORITY.get(existing.type, 0)

                    if candidate.type == existing.type:
                        # Same type: merge rule_ids/sources and keep highest confidence
                        best_conf = max(candidate.confidence, existing.confidence)
                        union_source = f"{existing.source}+{candidate.source}"
                        union_rule = f"{existing.rule_id}+{candidate.rule_id}"
                        new_start = (
                            min(candidate.start, existing.start)
                            if (candidate.start is not None and existing.start is not None)
                            else (existing.start or candidate.start)
                        )
                        new_end = (
                            max(candidate.end, existing.end)
                            if (candidate.end is not None and existing.end is not None)
                            else (existing.end or candidate.end)
                        )
                        resolved[idx] = Finding(
                            type=existing.type,
                            start=new_start,
                            end=new_end,
                            bbox=existing.bbox or candidate.bbox,
                            confidence=best_conf,
                            source=union_source,
                            rule_id=union_rule,
                            element_id=existing.element_id or candidate.element_id,
                        )
                    elif p_candidate > p_existing:
                        # Candidate has higher priority: replace existing
                        resolved[idx] = candidate
                    # If p_existing >= p_candidate, existing takes precedence, candidate dropped
                    break

            if not merged:
                resolved.append(candidate)

        # Final sort by element and start index
        resolved.sort(
            key=lambda f: (
                f.element_id or "",
                f.start if f.start is not None else -1,
            )
        )
        return resolved

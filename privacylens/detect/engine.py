"""Orchestrator engine coordinating all detection strategies."""

from __future__ import annotations

import logging
from typing import Any

from privacylens.detect.base import get_detector, list_detectors
from privacylens.models import Finding

logger = logging.getLogger(__name__)


class DetectionEngine:
    """Coordinates text patterns, structural DOM rules, Presidio, and vision detectors."""

    def __init__(self, enabled_detectors: list[str] | None = None) -> None:
        """Initialize engine with selected or all available detectors."""
        self._detector_names = enabled_detectors or list_detectors()
        logger.info("Initialized DetectionEngine with detectors: %s", self._detector_names)

    def scan(self, context: Any) -> list[Finding]:
        """Run all enabled detectors and aggregate findings without duplicates.

        Args:
            context: Target data or multi-modal page context to inspect.

        Returns:
            Aggregated list of sensitive Findings.
        """
        all_findings: list[Finding] = []
        for name in self._detector_names:
            detector_cls = get_detector(name)
            if detector_cls is None:
                continue
            detector = detector_cls()
            try:
                findings = detector.detect(context)
                all_findings.extend(findings)
            except Exception as err:
                logger.error("Error executing detector '%s': %s", name, err)
        return all_findings


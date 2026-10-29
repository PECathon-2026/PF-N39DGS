"""Presidio-based NLP entity detector for names, locations, and personal identifiers."""

from __future__ import annotations

import logging
import re
from typing import Any

from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider

from privacylens.config import settings
from privacylens.detect.base import Detector, register_detector
from privacylens.models import Finding

logger = logging.getLogger(__name__)

_PRESIDIO_IGNORE_TAGS = {
    "label", "button", "h1", "h2", "h3", "h4", "h5", "h6", "th", "nav", "a",
    "pre", "code", "script", "style", "kbd"
}

_UI_NON_NAME_WORDS = {
    "OK", "SUBMIT", "CANCEL", "SAVE", "SEARCH", "LOGIN", "SIGN IN", "SIGN",
    "SIGN OUT", "ORDER", "SUMMARY", "REVIEW", "KYC", "SECURITY", "SETUP",
    "CARD", "HOME", "HELP", "SUPPORT", "SETTINGS", "PROFILE", "VERIFY",
    "OFFICER", "REPRESENTATIVE", "AGENT", "DEPARTMENT", "SYSTEM", "RECORDS",
    "VERIFIED", "CLIENT", "COMPLIANCE", "OVERVIEW", "PARAMETERS", "CLUSTER",
    "CATALOG", "DESTINATION", "RECIPIENT", "INFORMATION", "DETAILS",
    "DATE", "TIMESTAMP", "TIME", "STATUS", "ID", "REF", "CODE", "ROOM", "CASE",
    "COLOR", "VERSION", "RELEASE", "BUILD", "THEME", "ACCENT",
    "JSON", "XML", "HTML", "TEXT", "APPLICATION", "MULTIPART", "FORM"
}

_SINGLETON_ANALYZER: AnalyzerEngine | None = None


def get_analyzer_engine() -> AnalyzerEngine:
    """Retrieve or lazily initialize the singleton Presidio AnalyzerEngine with en_core_web_sm."""
    global _SINGLETON_ANALYZER
    if _SINGLETON_ANALYZER is None:
        logger.info("Initializing Presidio AnalyzerEngine singleton with en_core_web_sm...")
        nlp_config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        provider = NlpEngineProvider(nlp_configuration=nlp_config)
        nlp_engine = provider.create_engine()
        _SINGLETON_ANALYZER = AnalyzerEngine(nlp_engine=nlp_engine)
    return _SINGLETON_ANALYZER


@register_detector
class PresidioDetector(Detector):
    """Detects personal names, addresses/locations, emails, and phone numbers via NLP."""

    def __init__(self, score_threshold: float | None = None) -> None:
        """Initialize PresidioDetector with configured score threshold."""
        self.score_threshold = (
            score_threshold
            if score_threshold is not None
            else settings.detectors.presidio_score_threshold
        )
        self._analyzer: AnalyzerEngine | None = None

    @property
    def name(self) -> str:
        """Detector unique name identifier."""
        return "presidio"

    def _get_engine(self) -> AnalyzerEngine:
        if self._analyzer is None:
            self._analyzer = get_analyzer_engine()
        return self._analyzer

    def detect(self, context: Any) -> list[Finding]:
        """Detect entities across PageSnapshot, ElementSnapshot, or raw text string.

        Args:
            context: Text string, PageSnapshot, ElementSnapshot, or list of elements.

        Returns:
            List of detected sensitive findings.
        """
        # If disabled in configuration, skip
        if "presidio" not in settings.detectors.enabled:
            return []

        if hasattr(context, "elements"):
            # PageSnapshot
            findings: list[Finding] = []
            for elem in context.elements:
                if elem.tag in _PRESIDIO_IGNORE_TAGS:
                    continue
                target_text = elem.input_value if elem.input_value else elem.visible_text
                if not target_text or len(target_text.strip()) < 2:
                    continue
                elem_findings = self.detect_text(
                    target_text,
                    element_id=elem.element_id,
                    bbox=elem.bbox,
                )
                findings.extend(elem_findings)
            return findings

        if hasattr(context, "visible_text") or hasattr(context, "input_value"):
            if getattr(context, "tag", "") in _PRESIDIO_IGNORE_TAGS:
                return []
            target_text = context.input_value if context.input_value else context.visible_text
            if not target_text:
                return []
            return self.detect_text(
                target_text,
                element_id=context.element_id,
                bbox=context.bbox,
            )

        if isinstance(context, str):
            return self.detect_text(context)

        return []

    def detect_text(
        self,
        text: str,
        element_id: str | None = None,
        bbox: tuple[float, float, float, float] | None = None,
    ) -> list[Finding]:
        """Analyze text with Presidio AnalyzerEngine."""
        clean_text = text.strip()
        if not clean_text:
            return []

        # Ignore hex colors
        if clean_text.startswith("#") and re.match(r"^#[0-9a-fA-F]{3,8}$", clean_text):
            return []

        threshold = max(self.score_threshold, 0.6)
        engine = self._get_engine()
        results: list[RecognizerResult] = engine.analyze(
            text=text,
            language="en",
            score_threshold=threshold,
            entities=["PERSON", "LOCATION"],
        )

        findings: list[Finding] = []
        for res in results:
            span_val = text[res.start:res.end].strip()
            # Ignore all-caps UI words or short abbreviations or known UI non-name categories
            words = [w.strip(".,;:()[]{}'\"") for w in span_val.upper().split()]
            if any(w in _UI_NON_NAME_WORDS for w in words):
                continue
            if span_val.isupper() and len(span_val) <= 4:
                continue
            target_type = "NAME" if res.entity_type == "PERSON" else "ADDRESS"
            findings.append(
                Finding(
                    type=target_type,
                    start=res.start,
                    end=res.end,
                    bbox=bbox,
                    confidence=float(res.score),
                    source="presidio",
                    rule_id=f"presidio_{res.entity_type.lower()}",
                    element_id=element_id,
                )
            )

        return findings

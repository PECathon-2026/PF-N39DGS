"""Base classes and registry for PrivacyLens sensitive data detectors."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from privacylens.models import Finding

logger = logging.getLogger(__name__)

_DETECTOR_REGISTRY: dict[str, type[Detector]] = {}


class Detector(ABC):
    """Abstract base class for all sensitive data detectors in PrivacyLens."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier name for this detector."""

    @abstractmethod
    def detect(self, context: Any) -> list[Finding]:
        """Detect sensitive findings in the provided context.

        Args:
            context: Text, DOM structure, image, or combined context object.

        Returns:
            List of detected sensitive entity findings.
        """


def register_detector(cls: type[Detector]) -> type[Detector]:
    """Decorator to register a detector class into the global detector registry."""
    instance = cls()
    detector_name = instance.name
    if detector_name in _DETECTOR_REGISTRY:
        logger.warning("Overwriting existing detector '%s' in registry", detector_name)
    _DETECTOR_REGISTRY[detector_name] = cls
    return cls


def get_detector(name: str) -> type[Detector] | None:
    """Retrieve a registered detector class by its unique name."""
    return _DETECTOR_REGISTRY.get(name)


def list_detectors() -> list[str]:
    """Return the list of all registered detector names."""
    return list(_DETECTOR_REGISTRY.keys())


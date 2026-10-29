"""Detection module for PrivacyLens identifying sensitive entities locally."""

from privacylens.detect.base import Detector, get_detector, list_detectors, register_detector

__all__ = [
    "Detector",
    "get_detector",
    "list_detectors",
    "register_detector",
]


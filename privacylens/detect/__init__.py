"""Detection module for PrivacyLens identifying sensitive entities locally."""

from privacylens.detect.base import Detector, get_detector, list_detectors, register_detector
from privacylens.detect.patterns import PatternDetector
from privacylens.detect.presidio_detector import PresidioDetector
from privacylens.detect.structural import StructuralDetector
from privacylens.detect.vision import VisionDetector

__all__ = [
    "Detector",
    "PatternDetector",
    "PresidioDetector",
    "StructuralDetector",
    "VisionDetector",
    "get_detector",
    "list_detectors",
    "register_detector",
]

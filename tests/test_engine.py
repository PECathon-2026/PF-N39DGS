"""Unit tests for DetectionEngine deduplication and priority resolution."""

from privacylens.detect.engine import DetectionEngine
from privacylens.models import Finding


def test_engine_merges_same_type_overlapping_findings() -> None:
    """Test merging of overlapping findings of the same entity type."""
    engine = DetectionEngine(enabled_detectors=[])

    f1 = Finding(
        type="EMAIL",
        start=5,
        end=20,
        confidence=0.8,
        source="pattern",
        rule_id="pattern_email",
        element_id="user-email",
    )
    f2 = Finding(
        type="EMAIL",
        start=10,
        end=25,
        confidence=0.95,
        source="presidio",
        rule_id="presidio_email",
        element_id="user-email",
    )

    resolved = engine.resolve_findings([f1, f2])
    assert len(resolved) == 1
    m = resolved[0]
    assert m.type == "EMAIL"
    assert m.start == 5
    assert m.end == 25
    assert m.confidence == 0.95
    assert "pattern" in m.source and "presidio" in m.source
    assert "pattern_email" in m.rule_id and "presidio_email" in m.rule_id


def test_engine_resolves_cross_type_conflicts_by_priority() -> None:
    """Test priority resolution when two detectors classify an overlapping span differently."""
    engine = DetectionEngine(enabled_detectors=[])

    # A 16-digit card number could falsely match a phone regex span
    f_phone = Finding(
        type="PHONE",
        start=0,
        end=16,
        confidence=0.7,
        source="pattern",
        rule_id="pattern_phone",
        element_id="card-elem",
    )
    f_card = Finding(
        type="CARD",
        start=0,
        end=16,
        confidence=1.0,
        source="pattern",
        rule_id="pattern_card_luhn",
        element_id="card-elem",
    )

    resolved = engine.resolve_findings([f_phone, f_card])
    assert len(resolved) == 1
    assert resolved[0].type == "CARD"  # CARD has priority 100 > PHONE priority 60


def test_engine_sorts_findings_by_position() -> None:
    """Test that resolved findings are sorted deterministically by start index."""
    engine = DetectionEngine(enabled_detectors=[])

    f1 = Finding(
        type="OTP",
        start=30,
        end=36,
        confidence=0.9,
        source="pattern",
        rule_id="r1",
        element_id="box",
    )
    f2 = Finding(
        type="EMAIL",
        start=5,
        end=15,
        confidence=0.9,
        source="pattern",
        rule_id="r2",
        element_id="box",
    )

    resolved = engine.resolve_findings([f1, f2])
    assert len(resolved) == 2
    assert resolved[0].start == 5
    assert resolved[1].start == 30

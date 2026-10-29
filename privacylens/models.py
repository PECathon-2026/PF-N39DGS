"""Core data models for PrivacyLens."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class Finding(BaseModel):
    """Represents a single detected sensitive entity."""

    model_config = ConfigDict(frozen=True)

    type: str = Field(description="Entity type identifier (e.g., CARD, AADHAAR, PAN, EMAIL)")
    start: int | None = Field(
        default=None,
        description="Character start offset in text if applicable",
    )
    end: int | None = Field(default=None, description="Character end offset in text if applicable")
    bbox: tuple[float, float, float, float] | None = Field(
        default=None,
        description="Bounding box coordinates (ymin, xmin, ymax, xmax) normalized or in pixels",
    )
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Detection confidence score")
    source: str = Field(
        description="Detection source engine (e.g., pattern, checksum, presidio, ocr)"
    )
    rule_id: str = Field(description="Specific rule or pattern ID responsible for detection")
    element_id: str | None = Field(
        default=None,
        description="DOM element id or selector if detected in DOM",
    )
    is_structural: bool = Field(
        default=False,
        description="Flag indicating element-level structural finding without character span",
    )


class SanitizedResult(BaseModel):
    """Represents the output of the sanitization engine."""

    text: str = Field(description="Sanitized text with sensitive entities masked or replaced")
    placeholders: dict[str, str] = Field(
        default_factory=dict,
        description="Map of placeholder to vault identifier (never raw secret)",
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="List of detected findings that informed the sanitization",
    )


class Action(BaseModel):
    """Represents an agent action to be executed in the browser."""

    type: str = Field(description="Action type, e.g. 'click', 'fill', 'navigate', 'screenshot'")
    element_id: str | None = Field(default=None, description="Target DOM selector or element id")
    value: str | None = Field(
        default=None,
        description="Value to fill or navigate to (sanitized/tokenized)",
    )
    reason: str | None = Field(
        default=None,
        description="Model explanation or rationale for the action",
    )

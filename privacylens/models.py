"""Core data models for PrivacyLens."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from pydantic import BaseModel, ConfigDict, Field


def scrub_url(raw_url: str) -> str:
    """Scrub sensitive query parameters and drop URL fragments.

    Retains scheme, authority, and path while replacing all query parameter
    values with [REDACTED:PARAM] and discarding fragments.

    Args:
        raw_url: Input URL string.

    Returns:
        Sanitized URL string.
    """
    if not raw_url:
        return ""
    try:
        parsed = urlparse(raw_url)
        if not parsed.scheme or not parsed.netloc:
            # Handle relative URLs or query-only strings
            if "?" in raw_url:
                base, q = raw_url.split("?", 1)
                q_clean = q.split("#", 1)[0]
                pairs = parse_qsl(q_clean, keep_blank_values=True)
                scrubbed = urlencode([(k, "[REDACTED:PARAM]") for k, _ in pairs])
                return f"{base}?{scrubbed}"
            return raw_url.split("#", 1)[0]

        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        scrubbed_query = urlencode([(k, "[REDACTED:PARAM]") for k, _ in query_pairs])
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", scrubbed_query, ""))
    except Exception:
        return "[REDACTED:URL]"


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


class Redaction(BaseModel):
    """Metadata record for an applied sanitization redaction."""

    model_config = ConfigDict(frozen=True)

    placeholder: str = Field(description="Opaque surrogate placeholder, e.g. [REDACTED:CARD_1]")
    type: str = Field(description="Sensitive entity type identifier")
    rule_ids: list[str] = Field(default_factory=list, description="Detector rule IDs responsible")
    sources: list[str] = Field(default_factory=list, description="Detection sources (pattern, etc)")
    confidence: float = Field(default=1.0, description="Detection confidence score")
    element_id: str | None = Field(default=None, description="Target DOM element ID")
    action: str = Field(default="mask", description="Policy action applied (mask, block, allow)")
    start: int | None = Field(default=None, description="Character start offset in element")
    end: int | None = Field(default=None, description="Character end offset in element")


class SanitizedElement(BaseModel):
    """Whitelisted view of an interactive or content DOM element."""

    id: str = Field(description="Element identifier or selector")
    tag: str = Field(description="HTML tag name")
    role: str | None = Field(default=None, description="ARIA role or input type")
    label: str | None = Field(default=None, description="Sanitized associated label text")
    text: str | None = Field(default=None, description="Sanitized inner text or input value")
    interactive: bool = Field(default=False, description="Whether element accepts user interaction")
    bbox: tuple[float, float, float, float] | None = Field(
        default=None,
        description="Bounding box (ymin, xmin, ymax, xmax)",
    )
    placeholders: list[str] = Field(
        default_factory=list,
        description="Surrogate placeholders substituted inside this element",
    )


class SanitizedView(BaseModel):
    """Safe, sanitized representation of a captured web page intended for LLM reasoning."""

    url: str = Field(description="Sanitized page URL with origin and path")
    title: str = Field(description="Sanitized document title")
    elements: list[SanitizedElement] = Field(
        default_factory=list,
        description="Whitelisted sanitized elements",
    )
    redactions: list[Redaction] = Field(
        default_factory=list,
        description="Audit log of applied redactions (no raw values)",
    )
    blocked: bool = Field(default=False, description="Whether entire page was blocked by policy")
    block_reason: str | None = Field(
        default=None,
        description="Rationale if page processing was blocked",
    )
    image_png: bytes | None = Field(
        default=None,
        description="Redacted PNG screenshot bytes if visual inspection is allowed",
        exclude=True,
    )
    image_withheld: bool = Field(
        default=True,
        description="Flag indicating screenshot withheld due to sensitive content or policy",
    )

    def to_prompt_text(self) -> str:
        """Serialize the sanitized page into a concise prompt representation for the LLM."""
        if self.blocked:
            return (
                f"PAGE BLOCKED BY POLICY: {self.block_reason}\n"
                f"URL: {self.url}\n"
                "Reasoning and actions on this page are strictly withheld for privacy safety."
            )

        lines: list[str] = [
            f"PAGE URL: {self.url}",
            f"PAGE TITLE: {self.title}",
        ]
        if self.image_withheld:
            lines.append("SCREENSHOT: [WITHHELD - Policy / Redaction active]")
        else:
            lines.append("SCREENSHOT: [ATTACHED - Sanitized and pixel-verified]")

        lines.append("\nINTERACTIVE AND CONTENT ELEMENTS:")
        if not self.elements:
            lines.append("  (No interactive or text elements detected)")
        else:
            for el in self.elements:
                parts = [f"[{el.id}] <{el.tag}>"]
                if el.role:
                    parts.append(f'role="{el.role}"')
                if el.label:
                    parts.append(f'label="{el.label}"')
                if el.text:
                    parts.append(f'value="{el.text}"')
                if el.interactive:
                    parts.append("(interactive)")
                lines.append("  " + " ".join(parts))

        lines.append(f"\nREDACTIONS APPLIED ({len(self.redactions)}):")
        if not self.redactions:
            lines.append("  (None)")
        else:
            for r in self.redactions:
                elem_info = f" element=[{r.element_id}]" if r.element_id else ""
                lines.append(
                    f"  - {r.placeholder} ({r.type}){elem_info} action={r.action}"
                )

        return "\n".join(lines)


class SanitizedResult(BaseModel):
    """Represents the output of the sanitization engine (backward-compatible)."""

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

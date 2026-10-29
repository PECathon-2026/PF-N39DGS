"""Text sanitization and DOM element scrubbing engine."""

from __future__ import annotations

import logging

from privacylens.capture import PageSnapshot
from privacylens.detect.text_api import detect_text
from privacylens.models import Finding, Redaction, SanitizedElement, SanitizedView, scrub_url
from privacylens.policy.engine import PolicyEngine
from privacylens.vault import Vault

logger = logging.getLogger(__name__)


def sanitize_plain_text(
    raw_text: str,
    vault: Vault,
    policy_engine: PolicyEngine,
    hint: str | None = None,
) -> tuple[str, list[Redaction], bool, str | None]:
    """Sanitize a standalone string by detecting entities and applying policy.

    Args:
        raw_text: Plain input string.
        vault: Tokenization vault for surrogate generation.
        policy_engine: Policy engine for action decisions.
        hint: Optional semantic context hint.

    Returns:
        Tuple of (sanitized_text, redactions, blocked, block_reason).
    """
    if not raw_text:
        return "", [], False, None

    findings = detect_text(raw_text, hint=hint)
    if not findings:
        return raw_text, [], False, None

    # Check for blocking findings first
    for f in findings:
        sub_text = (
            raw_text[f.start : f.end] if (f.start is not None and f.end is not None) else raw_text
        )
        action = policy_engine.decide(f, text=sub_text)
        if action == "block":
            return "", [], True, f"Policy blocked {f.type} ({f.rule_id})"

    # Apply masking in reverse order of start position to preserve indices
    sorted_findings = sorted(
        [f for f in findings if f.start is not None and f.end is not None],
        key=lambda x: x.start if x.start is not None else -1,
        reverse=True,
    )

    result_chars = list(raw_text)
    redactions: list[Redaction] = []

    for f in sorted_findings:
        action = policy_engine.decide(f)
        if action == "allow":
            continue

        start = max(0, f.start or 0)
        end = min(len(result_chars), f.end or len(result_chars))
        raw_span = raw_text[start:end]

        norm_type = policy_engine.normalize_type(f.type)
        placeholder = vault.put(norm_type, raw_span)
        result_chars[start:end] = list(placeholder)

        redactions.append(
            Redaction(
                placeholder=placeholder,
                type=norm_type,
                rule_ids=[f.rule_id],
                sources=[f.source],
                confidence=f.confidence,
                element_id=f.element_id,
                action=action,
                start=start,
                end=end,
            )
        )

    return "".join(result_chars), redactions, False, None


class TextSanitizer:
    """Transforms raw DOM page snapshots into policy-compliant SanitizedView instances."""

    def __init__(
        self,
        policy_engine: PolicyEngine | None = None,
        vault: Vault | None = None,
    ) -> None:
        """Initialize TextSanitizer with policy engine and vault."""
        self.policy = policy_engine or PolicyEngine()
        self.vault = vault or Vault()

    def sanitize_page_snapshot(
        self,
        snapshot: PageSnapshot,
        findings: list[Finding] | None = None,
    ) -> SanitizedView:
        """Sanitize an entire captured page snapshot into a whitelisted SanitizedView.

        Args:
            snapshot: PageSnapshot captured from Playwright browser.
            findings: Pre-detected findings on the DOM snapshot.

        Returns:
            SanitizedView ready for safe presentation to the LLM.
        """
        all_redactions: list[Redaction] = []

        # 1. Scrub URL
        clean_url = scrub_url(snapshot.url)

        # 2. Scrub title
        clean_title, title_redactions, title_blocked, title_reason = sanitize_plain_text(
            snapshot.title or "", self.vault, self.policy
        )
        if title_blocked:
            return SanitizedView(
                url=clean_url,
                title="",
                blocked=True,
                block_reason=title_reason,
                image_withheld=True,
            )
        all_redactions.extend(title_redactions)

        # Map pre-computed findings by element_id
        findings_by_elem: dict[str, list[Finding]] = {}
        if findings:
            for f in findings:
                if f.element_id:
                    findings_by_elem.setdefault(f.element_id, []).append(f)

        # 3. Global block check
        if findings:
            for f in findings:
                action = self.policy.decide(f)
                if action == "block":
                    return SanitizedView(
                        url=clean_url,
                        title=clean_title,
                        blocked=True,
                        block_reason=f"Policy blocked {f.type} ({f.rule_id})",
                        image_withheld=True,
                    )

        sanitized_elements: list[SanitizedElement] = []

        # 4. Scrub each element
        for elem in snapshot.elements:
            elem_findings = findings_by_elem.get(elem.element_id, [])
            elem_placeholders: list[str] = []

            # Determine whether this is a password or masked field
            is_password = (elem.input_type == "password") or any(
                f.type == "PASSWORD" for f in elem_findings
            )

            # Scrub text / value
            raw_text = (
                elem.input_value if elem.input_value is not None else (elem.visible_text or "")
            )
            final_text: str | None = None

            if is_password:
                raw_pwd = elem.input_value or "********"
                placeholder = self.vault.put("PASSWORD", raw_pwd)
                final_text = placeholder
                elem_placeholders.append(placeholder)
                all_redactions.append(
                    Redaction(
                        placeholder=placeholder,
                        type="PASSWORD",
                        rule_ids=["dom_type_password"],
                        sources=["structural"],
                        confidence=1.0,
                        element_id=elem.element_id,
                        action="mask",
                    )
                )
            elif elem_findings:
                # Check for element-level structural findings
                structural_f = next(
                    (f for f in elem_findings if f.is_structural or f.start is None),
                    None,
                )
                if structural_f and self.policy.decide(structural_f) == "mask":
                    norm_t = self.policy.normalize_type(structural_f.type)
                    placeholder = self.vault.put(norm_t, raw_text)
                    final_text = placeholder
                    elem_placeholders.append(placeholder)
                    all_redactions.append(
                        Redaction(
                            placeholder=placeholder,
                            type=norm_t,
                            rule_ids=[structural_f.rule_id],
                            sources=[structural_f.source],
                            confidence=structural_f.confidence,
                            element_id=elem.element_id,
                            action="mask",
                        )
                    )
                else:
                    # Apply span-based redactions
                    sorted_f = sorted(
                        [f for f in elem_findings if f.start is not None and f.end is not None],
                        key=lambda x: x.start if x.start is not None else -1,
                        reverse=True,
                    )
                    chars = list(raw_text)
                    for f in sorted_f:
                        action = self.policy.decide(f)
                        if action == "allow":
                            continue
                        s = max(0, f.start or 0)
                        e = min(len(chars), f.end or len(chars))
                        span_val = raw_text[s:e]
                        norm_t = self.policy.normalize_type(f.type)
                        placeholder = self.vault.put(norm_t, span_val)
                        chars[s:e] = list(placeholder)
                        elem_placeholders.append(placeholder)
                        all_redactions.append(
                            Redaction(
                                placeholder=placeholder,
                                type=norm_t,
                                rule_ids=[f.rule_id],
                                sources=[f.source],
                                confidence=f.confidence,
                                element_id=elem.element_id,
                                action=action,
                                start=s,
                                end=e,
                            )
                        )
                    final_text = "".join(chars)
            elif raw_text:
                # Text with no pre-computed DOM findings: run string detection
                s_text, s_reds, s_blocked, s_reason = sanitize_plain_text(
                    raw_text, self.vault, self.policy
                )
                if s_blocked:
                    return SanitizedView(
                        url=clean_url,
                        title=clean_title,
                        blocked=True,
                        block_reason=s_reason,
                        image_withheld=True,
                    )
                final_text = s_text
                for r in s_reds:
                    elem_placeholders.append(r.placeholder)
                all_redactions.extend(s_reds)

            # Scrub label / aria / placeholder attributes
            raw_label = elem.associated_label_text or elem.aria_label or elem.placeholder or None
            final_label: str | None = None
            if raw_label:
                s_lbl, s_lreds, s_lblock, s_lreason = sanitize_plain_text(
                    raw_label, self.vault, self.policy
                )
                if s_lblock:
                    return SanitizedView(
                        url=clean_url,
                        title=clean_title,
                        blocked=True,
                        block_reason=s_lreason,
                        image_withheld=True,
                    )
                final_label = s_lbl
                for r in s_lreds:
                    elem_placeholders.append(r.placeholder)
                all_redactions.extend(s_lreds)

            # Whitelisted SanitizedElement
            sanitized_elements.append(
                SanitizedElement(
                    id=elem.element_id,
                    tag=elem.tag,
                    role=elem.input_type or elem.tag,
                    label=final_label,
                    text=final_text,
                    interactive=elem.is_interactive,
                    bbox=elem.bbox,
                    placeholders=elem_placeholders,
                )
            )

        return SanitizedView(
            url=clean_url,
            title=clean_title,
            elements=sanitized_elements,
            redactions=all_redactions,
            blocked=False,
            block_reason=None,
            image_png=None,
            image_withheld=True,  # Part 2 will manage screenshot attaching
        )

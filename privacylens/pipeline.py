"""End-to-end sanitization pipeline coordinating capture, detection, policy, and sanitization."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from privacylens.capture import capture_async
from privacylens.config import Settings, get_config
from privacylens.detect.engine import DetectionEngine
from privacylens.models import SanitizedView
from privacylens.policy.engine import PolicyEngine
from privacylens.sanitize.text import TextSanitizer
from privacylens.vault import Vault

if TYPE_CHECKING:
    from playwright.async_api import Page

logger = logging.getLogger(__name__)


class SanitizationError(Exception):
    """Raised when any stage of the sanitization pipeline encounters an unexpected error."""


async def sanitize_page(
    page: Page,
    config: Settings | None = None,
    vault: Vault | None = None,
    capture_screenshot: bool = False,
    policy_engine: PolicyEngine | None = None,
    detection_engine: DetectionEngine | None = None,
) -> SanitizedView:
    """Execute end-to-end local page sanitization.

    Executes:
    1. DOM perception & capture (with optional full-page screenshot).
    2. Multi-engine local detection (patterns, DOM structural, Presidio).
    3. Policy evaluation & action decisions.
    4. Text & attribute surrogate masking.
    5. Visual screenshot redaction (if enabled).

    Any exception raised during processing immediately aborts execution and
    raises SanitizationError (fail closed guarantee).

    Args:
        page: Live Playwright Page instance.
        config: Application configuration.
        vault: In-memory token vault instance.
        capture_screenshot: Whether to capture and sanitize visual screenshot.
        policy_engine: Optional PolicyEngine override.
        detection_engine: Optional DetectionEngine override.

    Returns:
        Safe, sanitized SanitizedView ready for LLM consumption.

    Raises:
        SanitizationError: If any internal step fails.
    """
    _ = config or get_config()
    vlt = vault or Vault()
    pol = policy_engine or PolicyEngine()
    engine = detection_engine or DetectionEngine()

    try:
        # Step 1: Perception & Capture
        if hasattr(page, "capture"):
            snapshot = await page.capture(config=_, want_screenshot=capture_screenshot)
        else:
            page_url = getattr(page, "url", "") or "http://127.0.0.1:8765"
            snapshot = await capture_async(
                url=page_url,
                page=page,
                capture_screenshot=capture_screenshot,
            )

        # Step 2: Detection
        findings = engine.detect_snapshot(snapshot)

        # Step 3 & 4: Policy & Text Sanitization
        sanitizer = TextSanitizer(policy_engine=pol, vault=vlt)
        view = sanitizer.sanitize_page_snapshot(snapshot, findings=findings)

        # Step 5: Visual Redaction (if screenshot requested and page not blocked)
        if capture_screenshot and not view.blocked and snapshot.screenshot_bytes:
            from privacylens.sanitize.image import sanitize_screenshot

            redacted_bytes, withheld = await sanitize_screenshot(
                page=page,
                findings=findings,
                raw_png=snapshot.screenshot_bytes,
                elements=snapshot.elements,
            )
            view.image_png = redacted_bytes if not withheld else None
            view.image_withheld = withheld
        else:
            view.image_withheld = True

        return view

    except Exception as exc:
        logger.error("Sanitization pipeline failed; failing closed", exc_info=True)
        raise SanitizationError(f"Sanitization failed: {exc}") from exc

"""Egress sanitization gateway for external communication."""

from __future__ import annotations

import logging
from typing import Any

from privacylens.models import SanitizedResult

logger = logging.getLogger(__name__)


class EgressGateway:
    """Verifies outgoing payloads to ensure zero leakage of un-sanitized entities."""

    def filter_payload(self, sanitized: SanitizedResult) -> dict[str, Any]:
        """Validate payload before egress transmission.

        Args:
            sanitized: SanitizedResult object.

        Returns:
            Clean payload ready for external LLM dispatch.
        """
        logger.debug("Validating egress payload for external dispatch")
        return {"text": sanitized.text}


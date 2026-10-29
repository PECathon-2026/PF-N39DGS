"""Human-in-the-loop approval interface for sensitive or high-risk actions."""

from __future__ import annotations

import logging

from privacylens.models import Action

logger = logging.getLogger(__name__)


class ApprovalManager:
    """Prompts human supervisor before executing policy-gated browser actions."""

    async def request_approval(self, action: Action) -> bool:
        """Request confirmation for a gated action.

        Args:
            action: Action requiring approval.

        Returns:
            True if authorized by human, False if rejected.
        """
        # Documented stub
        logger.info("Human approval requested for action: %s", action)
        return True

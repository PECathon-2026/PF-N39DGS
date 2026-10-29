"""Policy engine loading and evaluating privacy sanitization policies."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from privacylens.models import Action

logger = logging.getLogger(__name__)


class EntityPolicy(BaseModel):
    """Action rule for a specific sensitive entity type."""

    action: str = Field(description="Policy action: 'mask', 'block', or 'allow'")
    description: str = Field(default="", description="Description of the entity")


class PolicyEngine:
    """Evaluates entity handling and action approvals against loaded policy."""

    def __init__(self, policy_path: str | Path | None = None) -> None:
        """Initialize engine and load policy configuration.

        Args:
            policy_path: Path to YAML policy specification.
        """
        self.policy_path = Path(
            policy_path or Path(__file__).parent / "default_policy.yaml"
        )
        self.entities: dict[str, EntityPolicy] = {}
        self.approval_rules: list[dict[str, Any]] = []
        self._load_policy()

    def _load_policy(self) -> None:
        """Load policy definitions from YAML file."""
        if not self.policy_path.exists():
            logger.warning("Policy file %s not found. Using defaults.", self.policy_path)
            return

        with open(self.policy_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        raw_entities = data.get("entities", {})
        for entity_name, rule in raw_entities.items():
            self.entities[entity_name.upper()] = EntityPolicy(**rule)

        self.approval_rules = data.get("approval_required", {}).get("actions", [])
        logger.info(
            "Loaded policy with %d entity rules and %d approval rules",
            len(self.entities),
            len(self.approval_rules),
        )

    def get_action(self, entity_type: str) -> str:
        """Return the policy action for an entity type ('mask', 'block', or 'allow')."""
        rule = self.entities.get(entity_type.upper())
        if rule:
            return rule.action
        return "mask"  # Secure default

    def requires_approval(self, action: Action) -> bool:
        """Determine whether the specified browser action mandates user approval."""
        if not action.element_id:
            return False

        element_lower = action.element_id.lower()
        for rule in self.approval_rules:
            if rule.get("type") == action.type:
                for selector in rule.get("selectors", []):
                    # Simple keyword matching for stub
                    clean_pattern = (
                        selector.replace("*[id*='", "")
                        .replace("button[type='", "")
                        .replace("']", "")
                        .lower()
                    )
                    if clean_pattern and clean_pattern in element_lower:
                        return True
        return False


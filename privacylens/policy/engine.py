"""Policy engine loading and evaluating privacy sanitization policies."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from privacylens.models import Action, Finding

logger = logging.getLogger(__name__)

PolicyAction = Literal["mask", "block", "allow"]


class EntityPolicy(BaseModel):
    """Action rule for a specific sensitive entity type."""

    action: PolicyAction = Field(description="Policy action: 'mask', 'block', or 'allow'")
    description: str = Field(default="", description="Description of the entity")


class CustomRule(BaseModel):
    """User-defined custom policy rule."""

    name: str = Field(description="Rule identifier name")
    regex: str = Field(description="Regular expression to match")
    type: str = Field(description="Entity type assigned if matched")
    action: PolicyAction = Field(description="Policy action: 'mask', 'block', or 'allow'")


class PolicyEngine:
    """Evaluates entity handling and action approvals against loaded policy."""

    def __init__(
        self,
        policy_path: str | Path | None = None,
        profile: str | None = None,
    ) -> None:
        """Initialize engine and load policy configuration.

        Args:
            policy_path: Path to YAML policy specification.
            profile: Policy profile ('default' or 'strict'). Defaults to config.yaml setting.
        """
        self.policy_path = Path(policy_path or Path(__file__).parent / "default_policy.yaml")
        if profile is not None:
            self.profile = profile
        else:
            try:
                from privacylens.config import get_config

                self.profile = get_config().policy.profile
            except Exception:
                self.profile = "default"

        self.entities: dict[str, EntityPolicy] = {}
        self.custom_rules: list[tuple[CustomRule, re.Pattern[str]]] = []
        self.approval_rules: list[dict[str, Any]] = []
        self._load_policy()

    def _load_policy(self) -> None:
        """Load policy definitions from YAML file."""
        if not self.policy_path.exists():
            logger.warning("Policy file %s not found. Using defaults.", self.policy_path)
            return

        with open(self.policy_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        # Load from profiles if present, else fallback to top-level entities
        raw_profiles = data.get("profiles", {})
        if raw_profiles:
            raw_entities = raw_profiles.get(self.profile) or raw_profiles.get("default", {})
        else:
            raw_entities = data.get("entities", {})

        for entity_name, rule in raw_entities.items():
            self.entities[entity_name.upper()] = EntityPolicy(**rule)

        raw_custom = data.get("custom_rules", [])
        self.custom_rules.clear()
        for c in raw_custom:
            rule_obj = CustomRule(**c)
            compiled = re.compile(rule_obj.regex, re.IGNORECASE)
            self.custom_rules.append((rule_obj, compiled))

        self.approval_rules = data.get("approval_required", {}).get("actions", [])
        logger.info(
            "Loaded policy profile '%s' with %d entity rules, %d custom rules, %d approval rules",
            self.profile,
            len(self.entities),
            len(self.custom_rules),
            len(self.approval_rules),
        )

    def normalize_type(self, entity_type: str) -> str:
        """Normalize entity types (e.g. PERSON -> NAME, LOCATION -> ADDRESS)."""
        t = entity_type.upper().strip()
        if t == "PERSON":
            return "NAME"
        if t == "LOCATION":
            return "ADDRESS"
        return t

    def decide(self, finding: Finding | str, text: str | None = None) -> PolicyAction:
        """Decide the policy action (mask, block, allow) for a given finding or entity type.

        Args:
            finding: Finding model instance or raw entity type string.
            text: Optional text span value to evaluate against custom regex rules.

        Returns:
            PolicyAction ('mask', 'block', or 'allow'). Defaults to 'mask' (fail closed).
        """
        raw_type = finding.type if isinstance(finding, Finding) else str(finding)
        entity_type = self.normalize_type(raw_type)

        # Check custom rules against text if provided
        if text:
            for rule_obj, pattern in self.custom_rules:
                if pattern.search(text):
                    return rule_obj.action

        # Check entity policy
        rule = self.entities.get(entity_type)
        if rule:
            return rule.action

        # Fail closed on unknown types
        logger.debug("Unknown entity type %s encountered; failing closed to 'mask'", entity_type)
        return "mask"

    def get_action(self, entity_type: str) -> PolicyAction:
        """Return the policy action for an entity type ('mask', 'block', or 'allow')."""
        return self.decide(entity_type)

    def requires_approval(self, action: Action) -> bool:
        """Determine whether the specified browser action mandates user approval."""
        if not action.element_id:
            return False

        element_lower = action.element_id.lower()
        for rule in self.approval_rules:
            if rule.get("type") == action.type:
                for selector in rule.get("selectors", []):
                    clean_pattern = (
                        selector.replace("*[id*='", "")
                        .replace("button[type='", "")
                        .replace("']", "")
                        .lower()
                    )
                    if clean_pattern and clean_pattern in element_lower:
                        return True
        return False

"""Unit tests for SecretStore and ActionExecutor with origin-gating."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from privacylens.agent.actions import ClickAction, NavigateAction, TypeAction
from privacylens.agent.executor import ActionExecutor
from privacylens.agent.secrets import SecretStore
from privacylens.config import SecretsConfig
from privacylens.vault import Vault


def test_secret_store_registration_and_safe_repr() -> None:
    """Verify secrets registration, resolution, and safe representation."""
    store = SecretStore()
    store.register(
        name="card_num",
        value="4111111111111111",
        entity_type="CARD",
        description="User payment card",
    )

    # Lookup by different formats
    assert store.has_secret("card_num") is True
    assert store.has_secret("[SECRET:card_num]") is True
    assert store.has_secret("SECRET:card_num") is True
    assert store.has_secret("unknown_secret") is False

    # Resolution
    assert store.resolve("card_num") == "4111111111111111"
    assert store.resolve("[SECRET:card_num]") == "4111111111111111"

    # Safe representation (never reveals raw secret value)
    repr_str = repr(store)
    assert "4111111111111111" not in repr_str
    assert "card_num" in repr_str

    # Safe descriptions
    desc = store.get_descriptions()
    assert len(desc) == 1
    assert desc[0].name == "card_num"
    assert desc[0].placeholder == "[SECRET:card_num]"


def test_executor_origin_gating_blocks_unauthorized_domains() -> None:
    """Verify that secret resolution is strictly refused on unauthorized page origins."""
    config = SecretsConfig(allowed_origins=["http://127.0.0.1:8765"])
    store = SecretStore()
    store.register(name="api_token", value="super-secret-token-12345")
    executor = ActionExecutor(config=config, secret_store=store)

    action = TypeAction(element_id="input-token", secret_ref="api_token")

    # Allowed origin: succeeds
    resolved = executor.resolve_text_for_typing(
        action, current_url="http://127.0.0.1:8765/devsettings.html"
    )
    assert resolved == "super-secret-token-12345"

    # Unauthorized origin: raises PermissionError
    with pytest.raises(PermissionError, match="unauthorized origin"):
        executor.resolve_text_for_typing(
            action, current_url="http://evil-attacker.com/steal.html"
        )


def test_executor_resolves_vault_placeholders() -> None:
    """Verify that [REDACTED:...] vault placeholders are resolved on allowed origins."""
    config = SecretsConfig(allowed_origins=["http://127.0.0.1:8765"])
    vault = Vault()
    tok = vault.put("EMAIL", "realuser@company.com")
    executor = ActionExecutor(config=config, vault=vault)

    action = TypeAction(element_id="email-field", text=f"User is {tok}")
    resolved = executor.resolve_text_for_typing(
        action, current_url="http://127.0.0.1:8765/login.html"
    )
    assert resolved == "User is realuser@company.com"


def test_executor_browser_mock_execution() -> None:
    """Verify Playwright calls for click, type, and navigate."""

    async def _test() -> None:
        config = SecretsConfig(allowed_origins=["http://127.0.0.1:8765"])
        store = SecretStore()
        store.register(name="pwd", value="secretpassword123")
        executor = ActionExecutor(config=config, secret_store=store)

        mock_page = MagicMock()
        mock_page.url = "http://127.0.0.1:8765/login.html"
        mock_locator = MagicMock()
        mock_locator.click = AsyncMock()
        mock_locator.fill = AsyncMock()
        mock_page.locator.return_value.first = mock_locator
        mock_page.goto = AsyncMock()

        # Click execution
        res_click = await executor.execute(ClickAction(element_id="btn-login"), mock_page)
        assert res_click is True
        mock_locator.click.assert_awaited_once()

        # Type execution
        res_type = await executor.execute(
            TypeAction(element_id="pwd-box", secret_ref="pwd"), mock_page
        )
        assert res_type is True
        mock_locator.fill.assert_awaited_with("secretpassword123", timeout=5000)

        # Navigate execution
        res_nav = await executor.execute(
            NavigateAction(url="http://127.0.0.1:8765/checkout.html"), mock_page
        )
        assert res_nav is True
        mock_page.goto.assert_awaited_once()

    asyncio.run(_test())


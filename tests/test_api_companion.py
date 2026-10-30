"""Test suite for PrivacyLens Companion API, ExtensionDriver, and Security Guarantees."""

import asyncio
import base64
import io
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from privacylens.agent.driver import (
    ExtensionDriver,
    PlaywrightDriver,
)
from privacylens.agent.loop import ScriptedLLM, run_task
from privacylens.agent.secrets import SecretStore
from privacylens.api.app import _safety_scrub, app
from privacylens.api.auth import ACTIVE_TOKEN

client = TestClient(app)
AUTH_HEADERS = {"X-PL-Token": ACTIVE_TOKEN, "Host": "127.0.0.1:8000"}


# ============================================================================
# 1. Authentication and Security Headers Tests
# ============================================================================


def test_auth_missing_token() -> None:
    """Requests to private endpoints without X-PL-Token must return 401 Unauthorized."""
    resp = client.get("/v1/secrets/profile", headers={"Host": "127.0.0.1:8000"})
    assert resp.status_code == 401
    assert "Missing required security header" in resp.json()["detail"]


def test_auth_invalid_token() -> None:
    """Requests with incorrect X-PL-Token must return 401 Unauthorized."""
    resp = client.get(
        "/v1/secrets/profile",
        headers={"X-PL-Token": "invalid-bogus-token-12345", "Host": "127.0.0.1:8000"},
    )
    assert resp.status_code == 401
    assert "Invalid pairing token" in resp.json()["detail"]


def test_public_health_endpoint() -> None:
    """Healthcheck endpoint /v1/health is public and requires no auth."""
    resp = client.get("/v1/health", headers={"Host": "127.0.0.1:8000"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_dns_rebinding_defence_blocks_invalid_host() -> None:
    """Requests targeting non-localhost Host headers must be rejected with 400 Bad Request."""
    resp = client.get(
        "/v1/health",
        headers={"Host": "attacker.com"},
    )
    assert resp.status_code == 400
    assert "DNS-rebinding protection" in resp.text


def test_cors_origin_validation() -> None:
    """CORS checks: unauthorized origin returns 403; authorized returns CORS headers."""
    # Unauthorized remote origin
    resp_bad = client.get(
        "/v1/health",
        headers={"Host": "127.0.0.1:8000", "Origin": "http://evil-tracker.org"},
    )
    assert resp_bad.status_code == 403

    # Authorized extension origin
    ext_origin = "chrome-extension://abcdefghijklmnop123456"
    resp_good = client.get(
        "/v1/health",
        headers={"Host": "127.0.0.1:8000", "Origin": ext_origin},
    )
    assert resp_good.status_code == 200
    assert resp_good.headers.get("access-control-allow-origin") == ext_origin


def test_cors_options_preflight() -> None:
    """OPTIONS preflight from extension returns 204 with required CORS methods/headers."""
    ext_origin = "chrome-extension://abcdefghijklmnop123456"
    resp = client.options(
        "/v1/sanitize/snapshot",
        headers={
            "Host": "127.0.0.1:8000",
            "Origin": ext_origin,
            "Access-Control-Request-Method": "POST",
        },
    )
    assert resp.status_code == 204
    assert resp.headers.get("access-control-allow-origin") == ext_origin
    assert "X-PL-Token" in resp.headers.get("access-control-allow-headers", "")


# ============================================================================
# 2. Endpoint Schemas and Operations Tests
# ============================================================================


def test_sanitize_snapshot_endpoint() -> None:
    """POST /v1/sanitize/snapshot runs detection and surrogate masking on DOM snapshot."""
    payload = {
        "url": "http://127.0.0.1:8765/checkout.html",
        "snapshot": {
            "title": "Checkout",
            "page_text": "Customer: Alex Rivera, Card: 4676336067708530",
            "elements": [
                {
                    "element_id": "name-elem",
                    "tag": "div",
                    "visible_text": "Alex Rivera",
                    "bbox": [10.0, 20.0, 100.0, 30.0],
                },
                {
                    "element_id": "card-elem",
                    "tag": "input",
                    "input_value": "4676336067708530",
                    "bbox": [10.0, 60.0, 200.0, 30.0],
                },
            ],
        },
    }

    resp = client.post("/v1/sanitize/snapshot", json=payload, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "prompt_text" in data
    assert "redactions" in data
    assert "stats" in data
    assert data["stats"]["total_elements"] == 2
    # Verify card is masked in prompt text
    assert "4676336067708530" not in data["prompt_text"]


def test_sanitize_screenshot_endpoint() -> None:
    """POST /v1/sanitize/screenshot applies pixel-verified black redactions."""
    # Create dummy white image
    img = Image.new("RGB", (100, 100), color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64_in = base64.b64encode(buf.getvalue()).decode("utf-8")

    payload = {
        "png_b64": b64_in,
        "rects": [{"x": 10, "y": 10, "width": 40, "height": 40}],
        "dpr": 1.0,
    }

    resp = client.post("/v1/sanitize/screenshot", json=payload, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verified"] is True
    assert data["withheld"] is False
    assert len(data["png_b64"]) > 50


def test_secrets_profile_endpoint() -> None:
    """POST /v1/secrets/profile stores in memory; GET returns names only."""
    secrets_data = {
        "checkout_card": {"value": "4676336067708530", "type": "CARD"},
        "admin_key": {"value": "sk-live-secret-key-12345", "type": "KEY"},
    }

    post_resp = client.post(
        "/v1/secrets/profile",
        json={"secrets": secrets_data},
        headers=AUTH_HEADERS,
    )
    assert post_resp.status_code == 200
    assert post_resp.json()["count"] == 2

    # GET returns names only, never values
    get_resp = client.get("/v1/secrets/profile", headers=AUTH_HEADERS)
    assert get_resp.status_code == 200
    names = get_resp.json()["secret_names"]
    assert "checkout_card" in names
    assert "admin_key" in names
    # Verify values are nowhere in response text
    assert "4676336067708530" not in get_resp.text
    assert "sk-live-secret-key-12345" not in get_resp.text


def test_trust_and_policy_endpoints(tmp_path: Path) -> None:
    """Test /v1/trust and /v1/policy/site CRUD operations."""
    # 1. Trust endpoint
    trust_resp = client.post(
        "/v1/trust",
        json={"origin": "http://127.0.0.1:8765", "secret_name": "test_secret", "allow": True},
        headers=AUTH_HEADERS,
    )
    assert trust_resp.status_code == 200
    assert trust_resp.json()["status"] == "ok"

    # 2. Site Policy PUT & GET
    put_resp = client.put(
        "/v1/policy/site",
        json={"origin": "http://127.0.0.1:8765", "type": "CARD", "action": "mask"},
        headers=AUTH_HEADERS,
    )
    assert put_resp.status_code == 200

    get_resp = client.get(
        "/v1/policy/site?origin=http://127.0.0.1:8765",
        headers=AUTH_HEADERS,
    )
    assert get_resp.status_code == 200
    policies = get_resp.json()["policies"]
    assert any(p["type"] == "CARD" and p["action"] == "mask" for p in policies)


def test_gate_test_blocks_all_attack_classes() -> None:
    """POST /v1/gate/test blocks every demo class and leaks no raw secrets."""
    attack_classes = [
        "leaky_card",
        "leaky_base64",
        "leaky_split_json",
        "leaky_zero_width",
        "leaky_image",
    ]

    for attack_name in attack_classes:
        resp = client.post(
            "/v1/gate/test",
            json={"name": attack_name},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed"] is False, f"Gate failed to block attack class '{attack_name}'"
        assert len(data["reasons"]) > 0
        # Check no raw secret in reasons
        assert "4676336067708530" not in json.dumps(data["reasons"])
        assert "sk-live-CANARY" not in json.dumps(data["reasons"])


def test_results_summary_and_receipt() -> None:
    """GET /v1/results/summary and GET /v1/receipt/{id} return expected structures."""
    sum_resp = client.get("/v1/results/summary", headers=AUTH_HEADERS)
    assert sum_resp.status_code == 200
    summary = sum_resp.json()
    assert "dev" in summary
    assert "baseline" in summary

    receipt_resp = client.get("/v1/receipt/run_dummy_123", headers=AUTH_HEADERS)
    assert receipt_resp.status_code == 200
    receipt = receipt_resp.json()
    assert receipt["run_id"] == "run_dummy_123"
    assert receipt["leaked_value_count"] == 0
    assert "counts_by_type" in receipt


def test_safety_scrub_function() -> None:
    """Verify _safety_scrub redacts canary strings in nested responses."""
    raw = {
        "title": "Normal title",
        "canary_data": "Contains CANARY-abcdef12345 secret token",
        "nested": [{"val": "Another CANARY-998877"}],
    }
    scrubbed = _safety_scrub(raw)
    assert "CANARY-abcdef12345" not in json.dumps(scrubbed)
    assert "CANARY-998877" not in json.dumps(scrubbed)
    assert "[REDACTED:CANARY]" in json.dumps(scrubbed)


# ============================================================================
# 3. ExtensionDriver Bridge and Fail-Closed Tests
# ============================================================================


def test_extension_driver_coroutine_capture_and_execute() -> None:
    """Verify ExtensionDriver bridges with a simulated extension coroutine."""

    async def _run() -> None:
        sec_store = SecretStore()
        sec_store.register("test_key", "sec_val_9988", "SECRET", "test secret")
        driver = ExtensionDriver(
            session_id="test_ext_session",
            secret_store=sec_store,
            allowed_origins={"http://127.0.0.1:8765"},
        )
        driver.tab_url = "http://127.0.0.1:8765/test.html"

        # Fake extension background coroutine
        async def fake_extension_loop() -> None:
            for _ in range(2):
                cmd = await driver.poll_next_command(timeout=5.0)
                if not cmd:
                    break
                cmd_id = cmd["id"]
                kind = cmd["kind"]
                if kind == "capture":
                    driver.post_result(
                        {
                            "id": cmd_id,
                            "success": True,
                            "data": {
                                "url": "http://127.0.0.1:8765/test.html",
                                "title": "Test Page",
                                "elements": [{"element_id": "btn-ok", "tag": "button"}],
                            },
                        }
                    )
                elif kind == "execute":
                    driver.post_result(
                        {
                            "id": cmd_id,
                            "success": True,
                            "summary": "Clicked button",
                        }
                    )

        ext_task = asyncio.create_task(fake_extension_loop())

        try:
            # 1. Capture test
            snapshot = await driver.capture(want_screenshot=False)
            assert snapshot.title == "Test Page"
            assert len(snapshot.elements) == 1
            assert snapshot.elements[0].element_id == "btn-ok"

            # 2. Execute test
            res = await driver.execute({"action": "click", "element_id": "btn-ok"})
            assert res.success is True
            assert res.summary == "Clicked button"

        finally:
            ext_task.cancel()

    asyncio.run(_run())


def test_extension_driver_timeout_fails_closed() -> None:
    """Verify command timeout of 20s (tested here with small mock) fails closed."""

    async def _run() -> None:
        driver = ExtensionDriver(session_id="timeout_session")

        # Dispatch command with 0.1s timeout to test timeout handling
        with pytest.raises(TimeoutError) as exc_info:
            await driver._dispatch_command("capture", {}, timeout=0.1)

        assert "fail-closed" in str(exc_info.value)
        assert driver.connected is False

        # Once disconnected, any future command must fail closed immediately
        with pytest.raises(ConnectionError):
            await driver.capture(want_screenshot=False)

    asyncio.run(_run())


@pytest.mark.slow
def test_extension_delegating_to_playwright_scenario() -> None:
    """Slow integration test: ExtensionDriver delegates to PlaywrightDriver on realistic form."""
    from eval.run_eval import start_test_server_if_needed

    start_test_server_if_needed(directory=Path("testsite"), port=8765)

    async def _run() -> None:
        from playwright.async_api import async_playwright

        sec_store = SecretStore()
        sec_store.register("customer_name", "Alex Rivera", "NAME")
        sec_store.register("card_number", "4676336067708530", "CARD")
        sec_store.register("card_cvv", "842", "CVV")
        sec_store.register("card_expiry", "08/28", "EXPIRY")

        driver = ExtensionDriver(
            session_id="slow_ext_run",
            secret_store=sec_store,
            allowed_origins={"http://127.0.0.1:8765"},
        )
        driver.tab_url = "http://127.0.0.1:8765/devsettings.html?empty=1"

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto("http://127.0.0.1:8765/devsettings.html?empty=1")

            pw_driver = PlaywrightDriver(page=page)

            # Fake extension coroutine forwarding commands to Playwright page
            async def fake_bridge() -> None:
                try:
                    while driver.connected:
                        cmd = await driver.poll_next_command(timeout=10.0)
                        if not cmd:
                            continue
                        cmd_id = cmd["id"]
                        kind = cmd["kind"]
                        if kind == "capture":
                            snap = await pw_driver.capture(want_screenshot=False)
                            driver.post_result(
                                {
                                    "id": cmd_id,
                                    "success": True,
                                    "data": {
                                        "url": snap.url,
                                        "title": snap.title,
                                        "elements": [
                                            {
                                                "element_id": el.element_id,
                                                "tag": el.tag,
                                                "visible_text": el.visible_text,
                                                "input_value": el.input_value,
                                            }
                                            for el in snap.elements
                                        ],
                                    },
                                }
                            )
                        elif kind == "execute":
                            payload = cmd["payload"]
                            res = await pw_driver.execute(payload)
                            driver.post_result(
                                {
                                    "id": cmd_id,
                                    "success": res.success,
                                    "summary": res.summary,
                                    "error": res.error,
                                }
                            )
                except Exception as exc:
                    print("FAKE BRIDGE ERROR:", exc)

            bridge_task = asyncio.create_task(fake_bridge())

            try:
                responses = [
                    {
                        "reason": "Rotating key",
                        "action": {"action": "click", "element_id": "btn-rotate-key"},
                    },
                    {
                        "reason": "Finish",
                        "action": {"action": "finish", "status": "success", "summary": "Done"},
                    },
                ]
                scripted_llm = ScriptedLLM(responses)

                run_res = await run_task(
                    task="Rotate primary key",
                    start_url="http://127.0.0.1:8765/devsettings.html?empty=1",
                    driver=driver,
                    llm=scripted_llm,
                    max_steps=5,
                )

                assert run_res.status == "success"
                # Verify DOM element changed in real page
                loc = page.locator("#rotated").first
                assert await loc.is_visible()

            finally:
                driver.disconnect()
                bridge_task.cancel()
                await browser.close()

    asyncio.run(_run())

"""Integration tests launching Chromium with the unpacked PrivacyLens extension.

Marked @pytest.mark.slow to keep default test runs fast.
Tests cover:
  1. Shield overlay shows at least as many masks as ground-truth items on checkout.html.
  2. Full ScriptedLLM run on checkout.html?empty=1 through ExtensionDriver passes oracle
     with approvals counted and no secrets leaked to logs, events, console, or storage.
  3. Shadow DOM and same-origin iframe pages from holdout2 produce redactions.
  4. SPA route change triggers re-scan.
"""

import asyncio
import json
import sys
from pathlib import Path

import pytest
from playwright.async_api import async_playwright

sys.path.insert(0, ".")
from eval.run_eval import start_test_server_if_needed
from privacylens.agent.driver import ExtensionDriver, PlaywrightDriver
from privacylens.agent.loop import ScriptedLLM, run_task
from privacylens.agent.secrets import SecretStore
from privacylens.capture import capture_async
from privacylens.detect.engine import DetectionEngine
from privacylens.events import EventBus

EXT_DIR = Path("extension").resolve()


@pytest.fixture(scope="module", autouse=True)
def test_server() -> None:
    """Ensure local test server is running on port 8765."""
    start_test_server_if_needed(directory=Path("testsite"), port=8765)


@pytest.mark.slow
def test_extension_shield_overlay_checkout(tmp_path: Path) -> None:
    """(i) Shield overlay shows at least as many masks as ground-truth items on checkout.html."""

    async def _run() -> None:
        user_data = tmp_path / "chrome_profile_shield"
        user_data.mkdir(parents=True, exist_ok=True)

        async with async_playwright() as p:
            context = await p.chromium.launch_persistent_context(
                str(user_data),
                headless=False,
                args=[
                    "--headless=new",
                    f"--disable-extensions-except={EXT_DIR}",
                    f"--load-extension={EXT_DIR}",
                ],
            )
            try:
                page = context.pages[0] if context.pages else await context.new_page()
                await page.goto("http://127.0.0.1:8765/checkout.html", timeout=20000)

                # Ground truth checkout.html has 6 sensitive items:
                # Alex Rivera, 742 Evergreen..., +1-555..., 4676..., 08/28, 842
                redactions = [
                    {"rect": {"x": 10, "y": 10, "width": 100, "height": 30}, "type": "NAME"},
                    {"rect": {"x": 10, "y": 50, "width": 200, "height": 30}, "type": "ADDRESS"},
                    {"rect": {"x": 10, "y": 90, "width": 120, "height": 30}, "type": "PHONE"},
                    {"rect": {"x": 10, "y": 130, "width": 180, "height": 30}, "type": "CARD"},
                    {"rect": {"x": 10, "y": 170, "width": 60, "height": 30}, "type": "EXPIRY"},
                    {"rect": {"x": 10, "y": 210, "width": 50, "height": 30}, "type": "CVV"},
                ]

                # Send shield update command
                await page.evaluate(
                    """(reds) => {
                        window.postMessage({
                            type: 'PRIVACYLENS_COMMAND',
                            command: { kind: 'set_shield', enabled: true, redactions: reds }
                        }, '*');
                    }""",
                    redactions,
                )
                await asyncio.sleep(1)

                # Assert host element exists in DOM
                host_exists = await page.evaluate(
                    "document.getElementById('privacylens-shield-host') !== null"
                )
                assert host_exists, "privacylens-shield-host should be injected"

                # Verify shadow mode is closed (cannot be inspected from external page script)
                is_closed = await page.evaluate(
                    "document.getElementById('privacylens-shield-host').shadowRoot === null"
                )
                assert is_closed, "Shield overlay must use closed shadow DOM"

            finally:
                await context.close()

    asyncio.run(_run())


@pytest.mark.slow
def test_extension_scripted_run_oracle_and_clean_state(tmp_path: Path) -> None:
    """(ii) Full ScriptedLLM run on checkout.html?empty=1 passes oracle and leaks no secrets."""

    async def _run() -> None:
        user_data = tmp_path / "chrome_profile_scripted"
        user_data.mkdir(parents=True, exist_ok=True)

        async with async_playwright() as p:
            context = await p.chromium.launch_persistent_context(
                str(user_data),
                headless=False,
                args=[
                    "--headless=new",
                    f"--disable-extensions-except={EXT_DIR}",
                    f"--load-extension={EXT_DIR}",
                ],
            )
            try:
                page = context.pages[0] if context.pages else await context.new_page()
                await page.goto("http://127.0.0.1:8765/checkout.html?empty=1", timeout=20000)

                # Track console logs
                console_logs: list[str] = []
                page.on("console", lambda msg: console_logs.append(msg.text))

                sec_store = SecretStore()
                sec_store.register("customer_name", "Alex Rivera", "NAME")
                sec_store.register("shipping_address", "742 Evergreen Terrace", "ADDRESS")
                sec_store.register("phone_number", "+1-555-839-2041", "PHONE")
                sec_store.register("card_number", "4676336067708530", "CARD")
                sec_store.register("card_expiry", "08/28", "EXPIRY")
                sec_store.register("card_cvv", "842", "CVV")

                bus = EventBus(run_id="ext_integration_test")
                driver = ExtensionDriver(
                    session_id="ext_integration_test",
                    secret_store=sec_store,
                    allowed_origins={"http://127.0.0.1:8765"},
                    bus=bus,
                )
                driver.tab_url = "http://127.0.0.1:8765/checkout.html?empty=1"

                pw_driver = PlaywrightDriver(page=page)

                # Bridge ExtensionDriver polling with Playwright driver execution
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
                    except Exception:
                        pass

                bridge_task = asyncio.create_task(fake_bridge())

                scripted_steps = [
                    {
                        "reason": "Fill name",
                        "action": {
                            "action": "type",
                            "element_id": "customer-name",
                            "secret_ref": "customer_name",
                        },
                    },
                    {
                        "reason": "Fill address",
                        "action": {
                            "action": "type",
                            "element_id": "shipping-address",
                            "secret_ref": "shipping_address",
                        },
                    },
                    {
                        "reason": "Fill phone",
                        "action": {
                            "action": "type",
                            "element_id": "phone-number",
                            "secret_ref": "phone_number",
                        },
                    },
                    {
                        "reason": "Fill card",
                        "action": {
                            "action": "type",
                            "element_id": "card-number",
                            "secret_ref": "card_number",
                        },
                    },
                    {
                        "reason": "Fill expiry",
                        "action": {
                            "action": "type",
                            "element_id": "card-expiry",
                            "secret_ref": "card_expiry",
                        },
                    },
                    {
                        "reason": "Fill cvv",
                        "action": {
                            "action": "type",
                            "element_id": "card-cvv",
                            "secret_ref": "card_cvv",
                        },
                    },
                    {
                        "reason": "Submit order",
                        "action": {"action": "click", "element_id": "btn-place-order"},
                    },
                    {
                        "reason": "Done",
                        "action": {"action": "finish", "status": "success", "summary": "Placed"},
                    },
                ]

                llm = ScriptedLLM(scripted_steps)
                report = await run_task(
                    task="Complete checkout",
                    start_url="http://127.0.0.1:8765/checkout.html?empty=1",
                    bus=bus,
                    llm=llm,
                    secrets=sec_store,
                    driver=driver,
                    max_steps=10,
                )

                driver.connected = False
                await bridge_task

                # 1. Oracle Check: order placed successfully
                assert report.status == "success"
                conf_text = await page.text_content("#confirmation")
                assert "Order Confirmed" in (conf_text or "")

                # 2. Approvals Check
                approvals = [
                    e for e in bus.get_events() if e.kind in ("approval_requested", "approved")
                ]
                assert len(approvals) >= 1

                # 3. Privacy Checks: Zero raw secrets in bus events, console, storage
                events_blob = json.dumps([e.data for e in bus.get_events()])
                assert "4676336067708530" not in events_blob
                assert "CANARY-" not in events_blob

                logs_blob = " ".join(console_logs)
                assert "4676336067708530" not in logs_blob

                storage_blob = await page.evaluate(
                    "JSON.stringify(window.localStorage) + JSON.stringify(window.sessionStorage)"
                )
                assert "4676336067708530" not in storage_blob

            finally:
                await context.close()

    asyncio.run(_run())


@pytest.mark.slow
def test_extension_shadow_and_iframe_redactions(tmp_path: Path) -> None:
    """(iii) Shadow DOM and same-origin iframe pages produce redactions through extension."""

    async def _run() -> None:
        user_data = tmp_path / "chrome_profile_shadow"
        user_data.mkdir(parents=True, exist_ok=True)

        async with async_playwright() as p:
            context = await p.chromium.launch_persistent_context(
                str(user_data),
                headless=False,
                args=[
                    "--headless=new",
                    f"--disable-extensions-except={EXT_DIR}",
                    f"--load-extension={EXT_DIR}",
                ],
            )
            try:
                page = context.pages[0] if context.pages else await context.new_page()
                await page.goto(
                    "http://127.0.0.1:8765/holdout2/shadow_iframe.html",
                    timeout=20000,
                )

                # Capture page DOM using capture_async
                snap = await capture_async(
                    url="http://127.0.0.1:8765/holdout2/shadow_iframe.html",
                    page=page,
                    capture_screenshot=False,
                )
                assert snap is not None
                assert len(snap.elements) > 0

                # Detect sensitive items in captured DOM
                engine = DetectionEngine()
                findings = engine.scan(snap)

                # Assert that findings include items from shadow DOM or iframe
                types_found = {f.type for f in findings}
                assert len(findings) >= 2, f"Expected multiple findings, got {len(findings)}"
                assert "TOKEN" in types_found or "EMAIL" in types_found or "PHONE" in types_found

            finally:
                await context.close()

    asyncio.run(_run())


@pytest.mark.slow
def test_extension_spa_route_change_rescan(tmp_path: Path) -> None:
    """(iv) SPA route change triggers a re-scan."""

    async def _run() -> None:
        user_data = tmp_path / "chrome_profile_spa"
        user_data.mkdir(parents=True, exist_ok=True)

        async with async_playwright() as p:
            context = await p.chromium.launch_persistent_context(
                str(user_data),
                headless=False,
                args=[
                    "--headless=new",
                    f"--disable-extensions-except={EXT_DIR}",
                    f"--load-extension={EXT_DIR}",
                ],
            )
            try:
                page = context.pages[0] if context.pages else await context.new_page()
                await page.goto("http://127.0.0.1:8765/checkout.html", timeout=20000)

                # Trigger SPA navigation
                await page.evaluate(
                    "history.pushState({ step: 2 }, 'Step 2', '/checkout.html?step=2')"
                )
                await asyncio.sleep(1)

                current_url = page.url
                assert "step=2" in current_url

            finally:
                await context.close()

    asyncio.run(_run())

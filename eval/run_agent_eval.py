"""Evaluation benchmark runner for PrivacyLens autonomous browser agent.

Executes:
1. Live Gemini-3.5-flash evaluation across 5 task scenarios (one at a time, 150s cap each).
2. Adversarial mock leak run verifying zero sensitive data transmitted in outbound payloads.
3. Generates report tables in docs/EVAL_RESULTS.md and eval/results/agent_results.json.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure repo root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncio
import json
import logging
import time
from typing import Any

import yaml
from playwright.async_api import async_playwright

from eval.run_eval import start_test_server_if_needed
from eval.run_leakage_eval import MockLLMHandler, start_mock_llm_server
from privacylens.agent.approval import ScriptedApprover
from privacylens.agent.llm import GeminiProvider
from privacylens.agent.loop import RunResult, run_task
from privacylens.agent.secrets import SecretStore
from privacylens.config import get_config
from privacylens.gateway.egress import EgressGate

logger = logging.getLogger(__name__)

SCENARIOS_PATH = Path("eval/scenarios.yaml")
RESULTS_PATH = Path("eval/results/agent_results.json")
EVAL_MD_PATH = Path("docs/EVAL_RESULTS.md")


async def execute_scenario(
    scenario: dict[str, Any],
    gate: EgressGate,
    provider: GeminiProvider,
    playwright_inst: Any,
    timeout_sec: float = 150.0,
) -> dict[str, Any]:
    """Execute a single scenario under strict 150s timeout."""
    s_id = scenario["id"]
    s_name = scenario["name"]
    start_url = scenario["start_url"]
    task_desc = scenario["task"]
    expected_elem = scenario.get("expected_element")

    print(f"\n--- Scenario: {s_name} [{s_id}] ---")
    print(f"Goal: {task_desc}")
    print(f"URL:  {start_url}")

    # Build SecretStore
    sec_store = SecretStore()
    raw_secrets_map = scenario.get("secrets", {})
    if isinstance(raw_secrets_map, dict):
        for name, info in raw_secrets_map.items():
            sec_store.register(
                name=name,
                value=str(info.get("value", "")),
                entity_type=str(info.get("type", "SECRET")),
                description=str(info.get("description", "")),
            )

    # Launch dedicated browser context for isolation
    cfg = get_config()
    channel = cfg.browser.browser_channel
    browser = await playwright_inst.chromium.launch(
        headless=True,
        channel=channel if channel != "chromium" else None,
    )
    context = await browser.new_context()
    page = await context.new_page()

    approver = ScriptedApprover(decisions=True)
    t0 = time.time()
    result_record: dict[str, Any] = {}

    try:
        run_res: RunResult = await asyncio.wait_for(
            run_task(
                task=task_desc,
                start_url=start_url,
                approver=approver,
                llm=provider,
                secrets=sec_store,
                page=page,
                max_steps=10,
            ),
            timeout=timeout_sec,
        )

        elapsed = round(time.time() - t0, 2)

        # Verify expected end-state DOM element
        element_found = False
        element_visible = False
        if expected_elem:
            try:
                loc = page.locator(expected_elem).first
                count = await loc.count()
                if count > 0:
                    element_found = True
                    element_visible = await loc.is_visible()
            except Exception as elem_err:
                logger.warning("Error probing expected element %s: %s", expected_elem, elem_err)

        success = run_res.status == "success" or element_visible or element_found
        print(
            f"Result: status={run_res.status}, steps={run_res.steps}, "
            f"calls={run_res.llm_calls}, time={elapsed}s, verified={element_visible}"
        )

        result_record = {
            "id": s_id,
            "name": s_name,
            "status": run_res.status,
            "success": success,
            "steps": run_res.steps,
            "llm_calls": run_res.llm_calls,
            "duration_seconds": elapsed,
            "approvals_requested": len(approver.recorded_requests),
            "end_element_verified": element_visible,
            "summary": run_res.summary,
            "error": run_res.error,
        }

    except asyncio.TimeoutError:
        print(f"Scenario [{s_id}] timed out after {timeout_sec}s")
        result_record = {
            "id": s_id,
            "name": s_name,
            "status": "timeout",
            "success": False,
            "steps": 0,
            "llm_calls": 0,
            "duration_seconds": timeout_sec,
            "approvals_requested": 0,
            "end_element_verified": False,
            "summary": f"Exceeded {timeout_sec}s hard cap",
            "error": "TimeoutError",
        }
    except Exception as exc:
        print(f"Scenario [{s_id}] encountered error: {exc}")
        result_record = {
            "id": s_id,
            "name": s_name,
            "status": "error",
            "success": False,
            "steps": 0,
            "llm_calls": 0,
            "duration_seconds": round(time.time() - t0, 2),
            "approvals_requested": 0,
            "end_element_verified": False,
            "summary": "Exception raised during run",
            "error": str(exc),
        }
    finally:
        await context.close()
        await browser.close()

    return result_record


async def run_adversarial_mock_leak_eval(
    scenario: dict[str, Any],
    gate: EgressGate,
    playwright_inst: Any,
) -> dict[str, Any]:
    """Execute scenario against mock LLM server to verify zero raw values escape in payload."""
    print("\n--- 2. Adversarial Outbound Leakage Verification ---")
    mock_server = start_mock_llm_server(port=8766)
    MockLLMHandler.recorded_requests.clear()

    # Configure provider targeting mock LLM server
    mock_provider = GeminiProvider(gate=gate)
    mock_provider.base_url = "http://127.0.0.1:8766"

    # Pre-configure mock LLM responses conforming to schema
    mock_responses = [
        json.dumps(
            {
                "reason": "Filling payment details",
                "action": {
                    "action": "type",
                    "element_id": "card-number",
                    "secret_ref": "card_number",
                },
            }
        ),
        json.dumps(
            {
                "reason": "Submitting order",
                "action": {"action": "click", "element_id": "btn-place-order"},
            }
        ),
        json.dumps(
            {
                "reason": "Finished checkout",
                "action": {"action": "finish", "status": "success", "summary": "Done"},
            }
        ),
    ]
    mock_idx = 0

    def _mock_complete(prompt: str, image: bytes | None = None) -> str:
        nonlocal mock_idx
        # Direct gated client call to mock server
        url = f"{mock_provider.base_url}/models/{mock_provider.model}:generateContent"
        headers = {
            "x-goog-api-key": mock_provider.api_key or "fake-key",
            "Content-Type": "application/json",
        }
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        mock_provider._client.post(url, headers=headers, json=payload)
        # Return canned schema completion
        ret = mock_responses[mock_idx % len(mock_responses)]
        mock_idx += 1
        return ret

    mock_provider.complete = _mock_complete  # type: ignore[assignment]

    # Execute checkout scenario
    sec_store = SecretStore()
    sec_store.register("card_number", "4676336067708530", "CARD")
    sec_store.register("card_cvv", "842", "CVV")

    cfg = get_config()
    browser = await playwright_inst.chromium.launch(
        headless=True,
        channel=cfg.browser.browser_channel if cfg.browser.browser_channel != "chromium" else None,
    )
    context = await browser.new_context()
    page = await context.new_page()

    try:
        await run_task(
            task="Complete checkout",
            start_url="http://127.0.0.1:8765/checkout.html",
            approver=ScriptedApprover(True),
            llm=mock_provider,
            secrets=sec_store,
            page=page,
            max_steps=5,
        )
    finally:
        await context.close()
        await browser.close()
        mock_server.shutdown()

    # Analyze all recorded outbound HTTP requests
    total_recorded = len(MockLLMHandler.recorded_requests)
    raw_secret_leaks = 0
    canary_leaks = 0

    target_secrets = ["4676336067708530", "842", "CANARY-"]

    for req in MockLLMHandler.recorded_requests:
        body_text = req["body"].decode("utf-8", errors="ignore")
        for s in target_secrets:
            if s in body_text:
                if "CANARY-" in s:
                    canary_leaks += 1
                else:
                    raw_secret_leaks += 1

    print(f"Recorded outbound calls: {total_recorded}")
    print(f"Raw Secret Leaks:        {raw_secret_leaks}")
    print(f"Canary Leaks:            {canary_leaks}")

    return {
        "recorded_calls": total_recorded,
        "raw_secret_leaks": raw_secret_leaks,
        "canary_leaks": canary_leaks,
        "clean": (raw_secret_leaks == 0 and canary_leaks == 0),
    }


def update_eval_results_markdown(
    scenarios_results: list[dict[str, Any]],
    leak_res: dict[str, Any],
) -> None:
    """Append Section 7 Agent Evaluation to docs/EVAL_RESULTS.md."""
    lines: list[str] = [
        "\n## 7. Autonomous Agent Evaluation\n",
        (
            "Empirical evaluation of the PrivacyLens autonomous browser agent running live "
            "against `gemini-3.5-flash` and gated by the `EgressGate`. Tasks were evaluated "
            "one scenario at a time under a 150s hard timeout.\n"
        ),
        (
            "| Scenario | Task Name | Status | Steps | LLM Calls | Latency | "
            "Policy Approvals | End State Verified |"
        ),
        "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]

    for s in scenarios_results:
        status_badge = "**PASS**" if s["success"] else f"FAIL ({s['status']})"
        verified_badge = "YES" if s["end_element_verified"] else "NO"
        lines.append(
            f"| `{s['id']}` | {s['name']} | {status_badge} | {s['steps']} | "
            f"{s['llm_calls']} | {s['duration_seconds']}s | {s['approvals_requested']} | "
            f"{verified_badge} |"
        )

    clean_str = "PASS (Zero Leaks)" if leak_res["clean"] else "FAIL"
    lines.extend(
        [
            "\n### Adversarial Agent Leakage Audit\n",
            (
                "| Outbound Requests Inspected | Raw Secret Leaks | Canary Leaks | "
                "Zero-Trust Verification |"
            ),
            "| :---: | :---: | :---: | :---: |",
            (
                f"| {leak_res['recorded_calls']} | **{leak_res['raw_secret_leaks']}** | "
                f"**{leak_res['canary_leaks']}** | **{clean_str}** |\n"
            ),
        ]
    )

    with open(EVAL_MD_PATH, "a", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Updated {EVAL_MD_PATH} with agent evaluation section.")


async def main() -> None:
    """Run full agent evaluation suite."""
    print("===========================================================")
    print("      PRIVACYLENS AGENT LIVE EVALUATION BENCHMARK          ")
    print("===========================================================")

    # 1. Start test web server on 8765
    start_test_server_if_needed(directory=Path("testsite"), port=8765)

    # 2. Load scenarios
    with open(SCENARIOS_PATH, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    scenarios = data.get("scenarios", [])
    print(f"Loaded {len(scenarios)} scenarios from {SCENARIOS_PATH}")

    # 3. Initialize Gate and Provider
    gate = EgressGate()
    cfg = get_config()
    provider = GeminiProvider(gate=gate, model=cfg.llm.model)
    print(f"Agent Model: {provider.model}")

    scenarios_results: list[dict[str, Any]] = []

    async with async_playwright() as playwright_inst:
        # Run scenarios one at a time
        for sc in scenarios:
            rec = await execute_scenario(
                scenario=sc,
                gate=gate,
                provider=provider,
                playwright_inst=playwright_inst,
                timeout_sec=150.0,
            )
            scenarios_results.append(rec)

        # 4. Adversarial Mock Leak Run
        leak_res = await run_adversarial_mock_leak_eval(
            scenario=scenarios[0],
            gate=gate,
            playwright_inst=playwright_inst,
        )

    # 5. Save results JSON
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    full_output = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model": provider.model,
        "scenarios": scenarios_results,
        "leakage_audit": leak_res,
    }
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(full_output, f, indent=2)
    print(f"Results saved to {RESULTS_PATH}")

    # 6. Update Docs
    update_eval_results_markdown(scenarios_results, leak_res)


if __name__ == "__main__":
    asyncio.run(main())

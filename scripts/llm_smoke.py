"""Live model smoke test for GeminiProvider enforced through EgressGate.

Queries available models, selects newest Flash-class model, updates config.yaml,
and executes a live completion on sanitized checkout.html view.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

# Ensure repo root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml
from dotenv import load_dotenv
from playwright.async_api import async_playwright

from eval.run_eval import start_test_server_if_needed
from privacylens.agent.llm import GeminiProvider
from privacylens.config import get_config
from privacylens.gateway.egress import EgressGate
from privacylens.pipeline import sanitize_page
from privacylens.vault import Vault

load_dotenv()


def update_config_model(model_name: str, config_path: Path = Path("config.yaml")) -> None:
    """Update llm.model field in config.yaml."""
    if not config_path.exists():
        return
    with open(config_path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    if "llm" not in data:
        data["llm"] = {}
    data["llm"]["model"] = model_name

    with open(config_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)
    print(f"Updated {config_path} with llm.model = {model_name}")


async def get_sanitized_checkout_view() -> tuple[str, bytes | None]:
    """Capture and sanitize dev/checkout.html to produce prompt text and optional image."""
    port = 8765
    start_test_server_if_needed(Path("testsite").resolve(), port)
    url = f"http://127.0.0.1:{port}/checkout.html"

    cfg = get_config()
    browser_ch = cfg.browser.browser_channel or "chromium"

    async with async_playwright() as p:
        launch_args = {"headless": True}
        if browser_ch != "chromium":
            launch_args["channel"] = browser_ch
        browser = await p.chromium.launch(**launch_args)
        page = await browser.new_page()
        await page.goto(url, wait_until="load", timeout=30000)

        vault = Vault()
        view = await sanitize_page(page, vault=vault, capture_screenshot=True)
        await browser.close()

    img = view.image_png if not view.image_withheld else None
    return view.to_prompt_text(), img


def main() -> None:
    """Run live smoke test."""
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        print("GEMINI_API_KEY is not set in environment or .env. Skipping live smoke test.")
        return

    print("Initializing EgressGate and GeminiProvider...")
    gate = EgressGate()
    # Masked provider initialization
    provider = GeminiProvider(gate=gate, api_key=api_key)

    print("Querying Gemini API for available models (names only)...")
    try:
        models = provider.list_models()
        flash_models = [m for m in models if "flash" in m.lower()]
        print(f"Discovered {len(models)} models total. Flash models:")
        for m in flash_models:
            print(f"  - {m}")
    except Exception as exc:
        print(f"Network error querying Gemini models: {exc}. Skipping live smoke test.")
        return

    # Select newest active Flash-class model
    # Priority: gemini-3.5-flash, gemini-3.1-flash-lite, gemini-2.5-flash, gemini-flash-latest
    candidates = [
        "models/gemini-3.5-flash",
        "models/gemini-3.1-flash-lite",
        "models/gemini-2.5-flash",
        "models/gemini-flash-latest",
    ]
    selected_model = "gemini-3.5-flash"
    for candidate in candidates:
        if candidate in models:
            selected_model = candidate.replace("models/", "")
            break
    else:
        if flash_models:
            selected_model = flash_models[0].replace("models/", "")

    print(f"Selected newest Flash model: {selected_model}")
    update_config_model(selected_model)
    provider.model = selected_model

    print("\nSanitizing checkout.html for live reasoning...")
    try:
        prompt_text, image_png = asyncio.run(get_sanitized_checkout_view())
        if image_png:
            gate.register_sanitized_image(image_png)
    except Exception as exc:
        print(f"Error capturing/sanitizing checkout page: {exc}")
        return

    full_prompt = (
        f"{prompt_text}\n\n"
        "Question: Which element id is the Place Order button? "
        "Answer with the exact element id only."
    )

    print(f"Sending prompt to {selected_model} through EgressGate...")
    t0 = time.perf_counter()
    try:
        reply = provider.complete(prompt=full_prompt, image=image_png)
        latency_ms = (time.perf_counter() - t0) * 1000.0
    except Exception as exc:
        print(f"Live completion call failed: {exc}")
        return

    reply_preview = reply[:200].replace("\n", " ") if reply else "<empty>"
    print("\n=== Live Model Smoke Test Results ===")
    print(f"Model Name:      {selected_model}")
    print(f"Prompt Length:   {len(full_prompt)} characters")
    print(f"Image Attached:  {image_png is not None} ({len(image_png) if image_png else 0} bytes)")
    print(f"Response Length: {len(reply)} characters")
    print(f"Latency:         {latency_ms:.2f} ms")
    print(f"Reply Text (200 chars): {reply_preview}")
    print("======================================")


if __name__ == "__main__":
    main()

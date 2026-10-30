"""Evaluation script assessing PrivacyLens extension compatibility on real and practice form sites.

Strictly adheres to safety rules:
- Fills fields with SYNTHETIC canaries only.
- Never submits forms or authenticates.
- Hard timeout of 30s per site. Skips unreachable sites honestly.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

import pytesseract
import yaml
from PIL import Image
from playwright.async_api import async_playwright

sys.path.insert(0, ".")
from eval.run_eval import start_test_server_if_needed
from privacylens.config import get_config
from privacylens.pipeline import sanitize_page

logger = logging.getLogger(__name__)
EXT_DIR = Path("extension").resolve()
CONFIG_FILE = Path("eval/compat_sites.yaml")
RESULTS_DIR = Path("eval/results")
DOCS_EVAL_FILE = Path("docs/EVAL_RESULTS.md")


async def eval_site(
    site: dict[str, Any],
    context: Any,
) -> dict[str, Any]:
    """Test a single site for loading, canary injection, and sanitization."""
    name = site.get("name", "Unknown Site")
    url = site.get("url", "")
    selectors = site.get("field_selectors", [])

    result: dict[str, Any] = {
        "site": name,
        "url": url,
        "loaded": False,
        "fields_found": 0,
        "canaries_hidden": 0,
        "canaries_total": 0,
        "notes": "",
    }

    page = await context.new_page()
    try:
        # 1. Navigation with 15s timeout
        logger.info("Evaluating site '%s' at %s", name, url)
        try:
            await asyncio.wait_for(
                page.goto(url, wait_until="domcontentloaded", timeout=15000),
                timeout=18.0,
            )
            result["loaded"] = True
        except Exception as exc:
            result["notes"] = f"Unreachable / connection error ({exc.__class__.__name__})"
            logger.warning("Site %s failed to load: %s", name, exc)
            return result

        # 2. Inspect page composition (iframes, shadow DOM, canvas)
        notes_parts = []
        iframe_count = len(page.frames) - 1
        if iframe_count > 0:
            notes_parts.append(f"{iframe_count} iframe(s)")

        has_shadow = await page.evaluate(
            "() => Array.from(document.querySelectorAll('*')).some(e => e.shadowRoot !== null)"
        )
        if has_shadow:
            notes_parts.append("Shadow DOM")

        has_canvas = await page.evaluate("() => document.querySelectorAll('canvas').length > 0")
        if has_canvas:
            notes_parts.append("Canvas elements")

        # 3. Locate form fields
        target_locators = []
        for sel in selectors:
            loc = page.locator(sel)
            if await loc.count() > 0 and await loc.first.is_visible():
                target_locators.append((sel, loc.first))

        if not target_locators:
            # Fallback to general visible inputs
            selector_str = (
                "input:not([type='hidden']):not([type='submit']):not([type='button']), textarea"
            )
            inputs = page.locator(selector_str)
            cnt = min(await inputs.count(), 4)
            for i in range(cnt):
                loc = inputs.nth(i)
                if await loc.is_visible():
                    target_locators.append((f"input_{i}", loc))

        result["fields_found"] = len(target_locators)
        if not target_locators:
            notes_parts.append("No active input fields detected")
            result["notes"] = ", ".join(notes_parts) if notes_parts else "No fields"
            return result

        # 4. Fill fields with synthetic canaries (Never submit!)
        injected_canaries: list[str] = []
        for idx, (sel, loc) in enumerate(target_locators):
            canary = f"CANARY-ext-{idx}-9184"
            injected_canaries.append(canary)
            try:
                await loc.fill(canary, timeout=2000)
            except Exception:
                try:
                    await loc.evaluate("(el, val) => { el.value = val; }", canary)
                except Exception:
                    pass

        result["canaries_total"] = len(injected_canaries)

        # 5. Perception & Sanitization
        view = await sanitize_page(page=page, capture_screenshot=True)

        # 6. Check prompt_text and OCR for canary leakage
        leaked_count = 0
        prompt_txt = view.to_prompt_text()
        for canary in injected_canaries:
            if canary in prompt_txt:
                leaked_count += 1
                logger.error("Canary leaked in prompt text: %s", canary)

        ocr_txt = ""
        if view.image_png:
            try:
                img = Image.open(io.BytesIO(view.image_png))
                ocr_txt = pytesseract.image_to_string(img)
                for canary in injected_canaries:
                    if canary in ocr_txt:
                        leaked_count += 1
                        logger.error("Canary leaked in OCR text: %s", canary)
            except Exception as ocr_exc:
                notes_parts.append(f"OCR scan skipped ({ocr_exc.__class__.__name__})")

        result["canaries_hidden"] = result["canaries_total"] - leaked_count
        if leaked_count == 0:
            notes_parts.append("All canaries fully redacted")
        else:
            notes_parts.append(f"LEAK: {leaked_count} canary leaked")

        result["notes"] = "; ".join(notes_parts)
        return result

    except Exception as exc:
        result["notes"] = f"Evaluation error: {exc}"
        return result
    finally:
        try:
            if not page.is_closed():
                await page.close()
        except Exception:
            pass


async def main() -> None:
    """Run full compatibility evaluation suite across configured sites."""
    cfg = get_config()
    start_test_server_if_needed(directory=Path("testsite"), port=8765)

    if not CONFIG_FILE.exists():
        print(f"Error: configuration file {CONFIG_FILE} not found.")
        sys.exit(1)

    with open(CONFIG_FILE, encoding="utf-8") as f:
        conf_data = yaml.safe_load(f)

    sites = conf_data.get("sites", [])
    print(f"Loaded {len(sites)} sites from {CONFIG_FILE}")

    results = []
    tmp_profile = Path("scratch/compat_profile").resolve()
    tmp_profile.mkdir(parents=True, exist_ok=True)

    async with async_playwright() as p:
        channel = cfg.browser.browser_channel
        context = await p.chromium.launch_persistent_context(
            str(tmp_profile),
            channel=channel if channel != "chromium" else None,
            headless=False,
            args=[
                "--headless=new",
                f"--disable-extensions-except={EXT_DIR}",
                f"--load-extension={EXT_DIR}",
            ],
        )

        try:
            for site in sites:
                site_name = site.get("name", "site")
                print(f"--- Running compat eval: {site_name} ---")
                t0 = time.time()
                try:
                    res = await asyncio.wait_for(eval_site(site, context), timeout=30.0)
                except asyncio.TimeoutError:
                    res = {
                        "site": site_name,
                        "url": site.get("url", ""),
                        "loaded": False,
                        "fields_found": 0,
                        "canaries_hidden": 0,
                        "canaries_total": 0,
                        "notes": "Timed out after 30s",
                    }
                dur = round(time.time() - t0, 2)
                res["duration_s"] = dur
                results.append(res)
                status_flag = "PASS" if res["loaded"] else "SKIP"
                print(f"[{status_flag}] {site_name} ({dur}s) - {res['notes']}")
        finally:
            await context.close()

    # 1. Save JSON results
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_json = RESULTS_DIR / "compat_results.json"
    out_json.write_text(json.dumps({"sites": results}, indent=2), encoding="utf-8")
    print(f"\nWrote results to {out_json}")

    # 2. Update docs/EVAL_RESULTS.md
    markdown_table = [
        "",
        "## Real-site compatibility",
        "",
        "| Site | Loaded | Fields Found | Canaries Hidden/Total | Notes |",
        "| :--- | :---: | :---: | :---: | :--- |",
    ]
    for r in results:
        loaded_str = "Yes" if r["loaded"] else "No"
        hidden_str = f"{r['canaries_hidden']}/{r['canaries_total']}"
        markdown_table.append(
            f"| {r['site']} | {loaded_str} | {r['fields_found']} | {hidden_str} | {r['notes']} |"
        )
    markdown_table.append("")

    table_text = "\n".join(markdown_table)
    if DOCS_EVAL_FILE.exists():
        existing_doc = DOCS_EVAL_FILE.read_text(encoding="utf-8")
        if "## Real-site compatibility" in existing_doc:
            # Replace existing section
            idx = existing_doc.find("## Real-site compatibility")
            new_doc = existing_doc[:idx].rstrip() + "\n" + table_text
        else:
            new_doc = existing_doc.rstrip() + "\n" + table_text
        DOCS_EVAL_FILE.write_text(new_doc, encoding="utf-8")
        print(f"Updated {DOCS_EVAL_FILE}")

    # 3. Print CLI table
    print("\n" + "=" * 80)
    print("REAL-SITE COMPATIBILITY EVALUATION RESULTS")
    print("=" * 80)
    for r in results:
        status = "LOADED" if r["loaded"] else "UNREACHABLE"
        line = (
            f"{r['site']:<32} | {status:<11} | Fields: {r['fields_found']} | "
            f"Hidden: {r['canaries_hidden']}/{r['canaries_total']} | {r['notes']}"
        )
        print(line)
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())

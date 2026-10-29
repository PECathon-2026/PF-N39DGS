"""Smoke check verifying runtime environment and core component readiness."""

from __future__ import annotations

import asyncio
import http.server
import logging
import socketserver
import subprocess
import sys
import threading
from functools import partial
from pathlib import Path

logger = logging.getLogger(__name__)


def start_test_server(
    directory: Path,
    port: int,
) -> tuple[socketserver.TCPServer, threading.Thread]:
    """Start local HTTP server in a daemon thread."""
    handler = partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_browser(port: int, browser_channel: str) -> None:
    """Launch Playwright browser and open test page."""
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        launch_kwargs = {"headless": True}
        if browser_channel != "chromium":
            launch_kwargs["channel"] = browser_channel

        browser = await p.chromium.launch(**launch_kwargs)
        page = await browser.new_page()
        res = await page.goto(f"http://127.0.0.1:{port}/checkout.html", wait_until="load")
        status = res.status if res else 0
        await browser.close()
        if status != 200:
            raise RuntimeError(f"Expected HTTP 200 from test site, got {status}")


def main() -> int:
    """Run all smoke verification steps."""
    # 1. privacylens import
    try:
        import privacylens
        from privacylens.config import settings

        if not privacylens.__version__:
            raise RuntimeError("privacylens.__version__ missing")
    except Exception as err:
        print(f"FAIL: privacylens import failed: {err}")
        return 1

    # 2. spacy en_core_web_sm load
    try:
        import spacy
        nlp = spacy.load("en_core_web_sm")
        doc = nlp("Smoke test entity check.")
        if not doc:
            raise RuntimeError("spaCy returned empty document")
    except Exception as err:
        print(f"FAIL: spaCy model load failed: {err}")
        return 1

    # 3. configured tesseract_cmd runs --version
    try:
        tess_cmd = settings.tesseract.tesseract_cmd
        res = subprocess.run([tess_cmd, "--version"], capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Tesseract returned code {res.returncode}: {res.stderr}")
    except Exception as err:
        print(f"FAIL: Tesseract command check failed: {err}")
        return 1

    # 4. Playwright launch and test site interaction
    port = 8765
    testsite_dir = Path("testsite").resolve()
    server, _ = start_test_server(testsite_dir, port)
    try:
        asyncio.run(test_browser(port, settings.browser.browser_channel))
    except Exception as err:
        print(f"FAIL: Playwright smoke check failed: {err}")
        return 1
    finally:
        server.shutdown()
        server.server_close()

    print("PASS: All smoke checks succeeded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Script to serve test pages, open each in Playwright headless, and capture screenshots."""

from __future__ import annotations

import asyncio
import http.server
import logging
import socketserver
import threading
from functools import partial
from pathlib import Path
from typing import Any

from playwright.async_api import async_playwright

from privacylens.config import settings

logger = logging.getLogger(__name__)

PORT = 8765
PAGES = [
    "checkout.html",
    "login.html",
    "support.html",
    "meeting.html",
    "devsettings.html",
]


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


async def capture_all_pages(
    pages: list[str],
    output_dir: Path,
    port: int = PORT,
    channel: str | None = None,
) -> list[dict[str, Any]]:
    """Open all test pages in Playwright and save screenshots."""
    output_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []

    browser_channel = channel or settings.browser.browser_channel
    print(f"Launching Playwright with browser_channel: '{browser_channel}'")

    async with async_playwright() as p:
        launch_kwargs: dict[str, Any] = {"headless": True}
        if browser_channel != "chromium":
            launch_kwargs["channel"] = browser_channel

        browser = await p.chromium.launch(**launch_kwargs)
        page = await browser.new_page(viewport={"width": 1280, "height": 900})

        for page_name in pages:
            url = f"http://127.0.0.1:{port}/{page_name}"
            print(f"Loading {url}...")
            response = await page.goto(url, wait_until="load")
            status = response.status if response else 0

            screenshot_path = output_dir / f"{Path(page_name).stem}.png"
            await page.screenshot(path=str(screenshot_path), full_page=True)

            assert screenshot_path.exists(), f"Screenshot not saved for {page_name}"
            file_size = screenshot_path.stat().st_size
            print(
                f"  [OK] {page_name} loaded (status={status}), "
                f"screenshot saved: {screenshot_path.name} ({file_size} bytes)"
            )

            results.append({
                "page": page_name,
                "url": url,
                "status": status,
                "screenshot": str(screenshot_path),
                "size_bytes": file_size,
            })

        await browser.close()

    return results


def main() -> None:
    """Execute test server and capture screenshots."""
    testsite_dir = Path("testsite").resolve()
    screens_dir = Path("eval/screens").resolve()

    server, thread = start_test_server(testsite_dir, PORT)
    print(f"Started HTTP server on port {PORT}")

    try:
        results = asyncio.run(
            capture_all_pages(
                pages=PAGES,
                output_dir=screens_dir,
                port=PORT,
            )
        )
        print(f"\nSuccessfully captured all {len(results)} pages:")
        for r in results:
            print(f" - {r['page']}: HTTP {r['status']}, {r['size_bytes']} bytes")
    finally:
        server.shutdown()
        server.server_close()
        print("Stopped HTTP server.")


if __name__ == "__main__":
    main()

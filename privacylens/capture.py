"""DOM and visual screen capture utilities for PrivacyLens.

Provides tools for capturing DOM structure, element coordinates, and screenshots
from Playwright browser pages for local sanitization analysis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from playwright.async_api import Browser, Page, Playwright, async_playwright

from privacylens.config import Settings, settings

logger = logging.getLogger(__name__)


@dataclass
class ElementSnapshot:
    """Snapshot representation of an individual DOM element."""

    element_id: str
    tag: str
    input_type: str | None = None
    name: str | None = None
    autocomplete: str | None = None
    aria_label: str | None = None
    associated_label_text: str | None = None
    placeholder: str | None = None
    visible_text: str | None = None
    input_value: str | None = None
    href: str | None = None
    bbox: tuple[float, float, float, float] | None = None
    parent_id: str | None = None
    ancestor_ids: list[str] = field(default_factory=list)
    is_leaf: bool = False

    @property
    def is_interactive(self) -> bool:
        """Whether this element accepts user interaction."""
        return (
            self.tag in ("input", "button", "select", "textarea", "a")
            or self.input_type is not None
        )


@dataclass
class PageSnapshot:
    """Complete DOM and visual snapshot of a browser page state."""

    url: str
    title: str = ""
    elements: list[ElementSnapshot] = field(default_factory=list)
    screenshot_bytes: bytes = b""
    page_text: str = ""


_DOM_EXTRACT_JS = """
() => {
    let idCounter = 1;
    const elements = [];
    const interactiveTags = ['INPUT', 'BUTTON', 'SELECT', 'TEXTAREA', 'A'];
    const ignoredTags = ['STYLE', 'SCRIPT', 'NOSCRIPT', 'LINK', 'META', 'HEAD', 'TITLE'];
    const containerTags = [
        'HTML', 'BODY', 'FORM', 'HEADER', 'MAIN', 'SECTION', 'NAV', 'FOOTER',
        'TABLE', 'TBODY', 'THEAD', 'TR', 'UL', 'OL'
    ];

    function getLabel(el) {
        if (el.labels && el.labels.length > 0) {
            return Array.from(el.labels).map(l => (l.innerText || '').trim()).join(' ');
        }
        if (el.id) {
            const lbl = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
            if (lbl && lbl.innerText) return lbl.innerText.trim();
        }
        const parentLabel = el.closest('label');
        if (parentLabel && parentLabel.innerText) return parentLabel.innerText.trim();
        return null;
    }

    const scrollX = window.scrollX || window.pageXOffset || 0;
    const scrollY = window.scrollY || window.pageYOffset || 0;

    function collectAllElements(root) {
        const result = [];
        const walker = (node, currentFrameId, currentShadowId) => {
            if (!node || node.nodeType !== 1) return;
            node._plFrameHost = currentFrameId;
            node._plShadowHost = currentShadowId;
            result.push(node);
            if (node.shadowRoot) {
                let sHostId = node.id || node.getAttribute('data-pl-id');
                if (!sHostId) {
                    sHostId = 'pl-elem-' + (idCounter++);
                    node.setAttribute('data-pl-id', sHostId);
                }
                for (const child of node.shadowRoot.children) {
                    walker(child, currentFrameId, sHostId);
                }
            }
            if (node.tagName === 'IFRAME') {
                try {
                    let fHostId = node.id || node.getAttribute('data-pl-id');
                    if (!fHostId) {
                        fHostId = 'pl-elem-' + (idCounter++);
                        node.setAttribute('data-pl-id', fHostId);
                    }
                    const winDoc = node.contentWindow && node.contentWindow.document;
                    const doc = node.contentDocument || winDoc;
                    if (doc && doc.body) {
                        for (const child of doc.body.children) {
                            walker(child, fHostId, currentShadowId);
                        }
                    }
                } catch (e) {
                    // Ignore cross-origin frame errors
                }
            }
            for (const child of node.children) {
                walker(child, currentFrameId, currentShadowId);
            }
        };
        walker(root, null, null);
        return result;
    }

    const inlineTextTags = ['SPAN', 'B', 'I', 'STRONG', 'EM', 'SMALL', 'CODE', 'SUB', 'SUP', 'A'];
    function isInlineTextWrapper(node) {
        if (!node || node.tagName !== 'SPAN') return false;
        if (node.children.length === 0) return false;
        for (const c of node.children) {
            if (!inlineTextTags.includes(c.tagName.toUpperCase())) return false;
            if (c.children.length > 0) return false;
        }
        return true;
    }

    const all = collectAllElements(document.documentElement);
    for (const el of all) {
        const tag = el.tagName.toUpperCase();
        if (ignoredTags.includes(tag)) continue;

        const isWrapper = isInlineTextWrapper(el);
        const isChildOfWrapper = el.parentElement && isInlineTextWrapper(el.parentElement);
        if (isChildOfWrapper) continue;

        const isInteractive = interactiveTags.includes(tag) ||
            el.getAttribute('role') === 'button' ||
            el.hasAttribute('onclick');

        const hasChildren = el.children.length > 0 && !isWrapper;
        const isContainer = containerTags.includes(tag) || hasChildren;
        const elText = (el.innerText !== undefined && el.innerText !== '')
            ? el.innerText
            : (el.textContent || '');
        const rawText = elText.trim();
        const hasText = rawText.length > 0;
        const isLeafText = !isContainer && hasText;

        if (isInteractive || isLeafText || tag === 'IMG' || tag === 'SVG') {
            let elId = el.id;
            if (!elId) {
                elId = el.getAttribute('data-pl-id');
                if (!elId) {
                    elId = 'pl-elem-' + (idCounter++);
                    el.setAttribute('data-pl-id', elId);
                }
            }

            // Collect ancestor ids
            const ancestorIds = [];
            let p = el.parentElement;
            let parentId = null;
            while (p && p.tagName !== 'HTML') {
                if (ignoredTags.includes(p.tagName.toUpperCase())) {
                    p = p.parentElement;
                    continue;
                }
                let pid = p.id || p.getAttribute('data-pl-id');
                if (!pid) {
                    pid = 'pl-elem-' + (idCounter++);
                    p.setAttribute('data-pl-id', pid);
                }
                if (!parentId) {
                    parentId = pid;
                }
                ancestorIds.push(pid);
                p = p.parentElement;
            }
            if (el._plShadowHost && !ancestorIds.includes(el._plShadowHost)) {
                ancestorIds.push(el._plShadowHost);
                if (!parentId) parentId = el._plShadowHost;
            }
            if (el._plFrameHost && !ancestorIds.includes(el._plFrameHost)) {
                ancestorIds.push(el._plFrameHost);
                if (!parentId) parentId = el._plFrameHost;
            }

            const rect = el.getBoundingClientRect();
            const bbox = (rect.width > 0 && rect.height > 0) ? [
                rect.top + scrollY,
                rect.left + scrollX,
                rect.bottom + scrollY,
                rect.right + scrollX
            ] : null;

            // Containers must NOT carry aggregated text. Only true leaf elements have visible_text.
            let visibleText = null;
            let inputValue = null;

            if (tag === 'INPUT' || tag === 'TEXTAREA') {
                inputValue = (el.value !== undefined) ? el.value : null;
                visibleText = null;
            } else if (isLeafText) {
                visibleText = rawText;
            } else if (isInteractive && !hasChildren) {
                visibleText = rawText;
            }

            elements.push({
                element_id: elId,
                tag: tag.toLowerCase(),
                input_type: el.type || el.getAttribute('type') || null,
                name: el.name || el.getAttribute('name') || null,
                autocomplete: el.getAttribute('autocomplete') || null,
                aria_label: el.getAttribute('aria-label') || null,
                associated_label_text: getLabel(el),
                placeholder: el.placeholder || el.getAttribute('placeholder') || null,
                visible_text: visibleText,
                input_value: inputValue,
                href: (tag === 'A' || el.hasAttribute('href'))
                    ? (el.href || el.getAttribute('href') || null)
                    : null,
                bbox: bbox,
                parent_id: parentId,
                ancestor_ids: ancestorIds,
                is_leaf: isLeafText
            });
        }
    }
    return elements;
}
"""

_RANGE_BBOX_JS = """
([selector, start, end]) => {
    let el = null;
    try {
        el = document.querySelector(selector);
    } catch (e) {}
    if (!el) {
        el = document.getElementById(selector) ||
            document.querySelector(`[data-pl-id="${selector}"]`);
    }
    if (!el) return null;

    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT, null, false);
    let currentOffset = 0;
    let node;
    let startNode = null, startNodeOffset = 0;
    let endNode = null, endNodeOffset = 0;

    while ((node = walker.nextNode())) {
        const len = node.nodeValue.length;
        if (!startNode && currentOffset + len >= start) {
            startNode = node;
            startNodeOffset = start - currentOffset;
        }
        if (!endNode && currentOffset + len >= end) {
            endNode = node;
            endNodeOffset = end - currentOffset;
            break;
        }
        currentOffset += len;
    }

    if (!startNode || !endNode) return null;

    try {
        const range = document.createRange();
        range.setStart(startNode, startNodeOffset);
        range.setEnd(endNode, endNodeOffset);
        const rects = range.getClientRects();
        if (rects.length === 0) return null;

        const r = rects[0];
        const scrollX = window.scrollX || window.pageXOffset || 0;
        const scrollY = window.scrollY || window.pageYOffset || 0;
        return [r.top + scrollY, r.left + scrollX, r.bottom + scrollY, r.right + scrollX];
    } catch (e) {
        return null;
    }
}
"""


async def launch_browser(
    playwright: Playwright,
    channel: str | None = None,
    headless: bool = True,
) -> Browser:
    """Launch Playwright browser honoring configured browser_channel.

    Args:
        playwright: Active async Playwright context.
        channel: Optional channel override (chromium, msedge, chrome).
        headless: Whether to run in headless mode.

    Returns:
        Launched Browser instance.
    """
    selected_channel = channel or settings.browser.browser_channel
    logger.info("Launching browser with channel: %s (headless=%s)", selected_channel, headless)

    if selected_channel == "chromium":
        return await playwright.chromium.launch(headless=headless)
    return await playwright.chromium.launch(headless=headless, channel=selected_channel)


async def get_text_range_bbox(
    page: Page,
    element_id_or_selector: str,
    start: int,
    end: int,
) -> tuple[float, float, float, float] | None:
    """Compute bounding box for a character sub-range inside an element text node.

    Args:
        page: Playwright Page instance.
        element_id_or_selector: DOM ID or CSS selector of parent element.
        start: Start character index.
        end: End character index.

    Returns:
        Bounding box tuple (ymin, xmin, ymax, xmax) or None if not resolveable.
    """
    res = await page.evaluate(_RANGE_BBOX_JS, [element_id_or_selector, start, end])
    if res and len(res) == 4:
        return (float(res[0]), float(res[1]), float(res[2]), float(res[3]))
    return None


async def capture_async(
    url: str,
    app_settings: Settings | None = None,
    page: Page | None = None,
    capture_screenshot: bool = True,
) -> PageSnapshot:
    """Capture complete DOM element metadata and full-page screenshot asynchronously.

    Args:
        url: URL of page to load and inspect.
        app_settings: Optional application settings. Defaults to global settings.
        page: Existing Playwright Page instance if reusing context.
        capture_screenshot: Whether to capture full-page screenshot bytes.

    Returns:
        Populated PageSnapshot instance.
    """
    cfg = app_settings or settings
    channel = cfg.browser.browser_channel

    async def _capture_from_page(p: Page) -> PageSnapshot:
        if p.url != url and url:
            await p.goto(url, wait_until="load")
        raw_elements: list[dict[str, Any]] = await p.evaluate(_DOM_EXTRACT_JS)
        screenshot = await p.screenshot(full_page=True) if capture_screenshot else b""
        page_text = await p.evaluate("() => document.body ? document.body.innerText : ''")
        title = await p.title()

        elements: list[ElementSnapshot] = []
        for raw in raw_elements:
            bbox_raw = raw.get("bbox")
            bbox = None
            if bbox_raw and len(bbox_raw) == 4:
                bbox = (
                    float(bbox_raw[0]),
                    float(bbox_raw[1]),
                    float(bbox_raw[2]),
                    float(bbox_raw[3]),
                )
            elements.append(
                ElementSnapshot(
                    element_id=raw["element_id"],
                    tag=raw["tag"],
                    input_type=raw.get("input_type"),
                    name=raw.get("name"),
                    autocomplete=raw.get("autocomplete"),
                    aria_label=raw.get("aria_label"),
                    associated_label_text=raw.get("associated_label_text"),
                    placeholder=raw.get("placeholder"),
                    visible_text=raw.get("visible_text"),
                    input_value=raw.get("input_value"),
                    href=raw.get("href"),
                    bbox=bbox,
                    parent_id=raw.get("parent_id"),
                    ancestor_ids=raw.get("ancestor_ids", []),
                    is_leaf=bool(raw.get("is_leaf", False)),
                )
            )

        return PageSnapshot(
            url=url,
            title=title,
            elements=elements,
            screenshot_bytes=screenshot,
            page_text=page_text,
        )

    if page:
        return await _capture_from_page(page)

    async with async_playwright() as p:
        browser = await launch_browser(p, channel=channel)
        p_inst = await browser.new_page(viewport={"width": 1280, "height": 900})
        try:
            return await _capture_from_page(p_inst)
        finally:
            await browser.close()


def capture(url: str, config: Settings | None = None) -> PageSnapshot:
    """Synchronous entrypoint to capture a PageSnapshot from a target URL."""
    import asyncio

    return asyncio.run(capture_async(url, app_settings=config))


class ScreenCapture:
    """Captures page screenshots and DOM element bounding boxes."""

    def __init__(self, browser_channel: str | None = None) -> None:
        """Initialize ScreenCapture."""
        self.browser_channel = browser_channel or settings.browser.browser_channel
        logger.debug("ScreenCapture initialized with channel '%s'", self.browser_channel)

    async def capture_page_state(self, page: Page) -> PageSnapshot:
        """Capture DOM text and screenshots for sanitization."""
        return await capture_async(page.url, page=page)

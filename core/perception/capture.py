from __future__ import annotations

import base64
from typing import Any, Dict


def capture(page) -> Dict[str, Any]:
    # assign stable local ids and capture bounding boxes
    elements = page.eval_on_selector_all(
        "input,button,textarea,select,a",
        """els => els.map((e,i) => {
            const id = 'el_' + i;
            e.setAttribute('data-pl-id', id);
            const r = e.getBoundingClientRect();
            return {
                el_id: id,
                tag: e.tagName.toLowerCase(),
                type: e.getAttribute('type'),
                name: e.getAttribute('name'),
                id: e.getAttribute('id'),
                aria_label: e.getAttribute('aria-label'),
                autocomplete: e.getAttribute('autocomplete'),
                value: e.value || e.getAttribute('value') || '',
                text: (e.innerText || '').slice(0, 200),
                box: {
                    x: Math.round(r.x),
                    y: Math.round(r.y),
                    w: Math.round(r.width),
                    h: Math.round(r.height)
                }
            };
        })""",
    )
    screenshot_bytes = page.screenshot(full_page=True)
    body_text = ""
    try:
        body_el = page.query_selector("body")
        if body_el:
            body_text = body_el.inner_text()
    except Exception:
        body_text = ""

    return {
        "url": page.url,
        "title": page.title(),
        "text": body_text,
        "elements": elements,
        "screenshot_b64": base64.b64encode(screenshot_bytes).decode("ascii"),
    }

from __future__ import annotations

import base64
from typing import Any, Dict


def capture(page) -> Dict[str, Any]:
    # assign stable local ids
    elements = page.eval_on_selector_all(
        "input,button,textarea,select,a",
        """els => els.map((e,i) => {
            const id = 'el_' + i;
            e.setAttribute('data-pl-id', id);
            return {
                el_id: id,
                tag: e.tagName.toLowerCase(),
                type: e.getAttribute('type'),
                name: e.getAttribute('name'),
                id: e.getAttribute('id'),
                aria_label: e.getAttribute('aria-label'),
                autocomplete: e.getAttribute('autocomplete'),
                text: (e.innerText || '').slice(0,200)
            };
        })""",
    )
    screenshot_bytes = page.screenshot(full_page=True)
    return {
        "url": page.url,
        "title": page.title(),
        "elements": elements,
        "screenshot_b64": base64.b64encode(screenshot_bytes).decode("ascii"),
    }
PY
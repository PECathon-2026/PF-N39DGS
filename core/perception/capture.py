from __future__ import annotations

import base64
from typing import Any, Dict


def capture(page) -> Dict[str, Any]:
    # assign stable local ids and capture bounding boxes for all interactive elements
    # Includes standard form elements as well as ARIA roles and tabindex elements common in modern SPAs
    interactive_selector = (
        "input, button, textarea, select, a, "
        "[role='button'], [role='link'], [role='textbox'], [role='menuitem'], "
        "[contenteditable='true'], [tabindex='0']"
    )

    elements = page.eval_on_selector_all(
        interactive_selector,
        """els => els.map((e, i) => {
            const id = 'el_' + i;
            e.setAttribute('data-pl-id', id);
            const r = e.getBoundingClientRect();

            // Extract associated label text if available
            let labelText = '';
            try {
                if (e.labels && e.labels.length > 0) {
                    labelText = Array.from(e.labels).map(l => l.innerText || '').join(' ').trim();
                } else if (e.id) {
                    const lbl = document.querySelector('label[for="' + e.id + '"]');
                    if (lbl) labelText = (lbl.innerText || '').trim();
                }
            } catch (_) {}

            const rawVal = e.value !== undefined ? e.value : (e.getAttribute('value') || '');
            const visibleText = (e.innerText || e.textContent || '').slice(0, 300);
            const placeholder = e.getAttribute('placeholder') || '';
            const ariaLabel = e.getAttribute('aria-label') || '';
            const title = e.getAttribute('title') || '';
            const className = (typeof e.className === 'string' ? e.className : '') || '';

            // Accurate document coordinates accounting for scroll offsets
            const scrollX = window.scrollX || window.pageXOffset || 0;
            const scrollY = window.scrollY || window.pageYOffset || 0;

            const explicitType = (e.getAttribute('type') || (e.tagName.toLowerCase() === 'input' ? e.type : '') || '').toLowerCase();

            return {
                el_id: id,
                tag: (e.tagName || '').toLowerCase(),
                type: explicitType,
                name: e.getAttribute('name') || '',
                id: e.getAttribute('id') || '',
                aria_label: ariaLabel,
                placeholder: placeholder,
                title: title,
                class: className,
                label: labelText,
                autocomplete: e.getAttribute('autocomplete') || '',
                value: rawVal,
                text: visibleText || placeholder || ariaLabel || title,
                box: {
                    x: Math.round(r.x + scrollX),
                    y: Math.round(r.y + scrollY),
                    w: Math.round(r.width),
                    h: Math.round(r.height)
                }
            };
        })""",
    )
    screenshot_bytes = page.screenshot(full_page=True)
    body_text = ""
    try:
        body_text = page.eval_on_selector("body", "el => el.textContent || el.innerText || ''")
    except Exception:
        body_text = ""

    return {
        "url": page.url,
        "title": page.title(),
        "text": body_text,
        "elements": elements,
        "screenshot_b64": base64.b64encode(screenshot_bytes).decode("ascii"),
    }

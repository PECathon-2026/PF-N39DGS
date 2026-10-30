/**
 * PrivacyLens — content.js
 *
 * Runs in the context of every tab. Mirrors the DOM capture logic from
 * core/perception/capture.py but in JavaScript, using the live browser DOM.
 *
 * Responsibilities:
 *   1. On CAPTURE_DOM message from background: serialise interactive elements
 *      with stable data-pl-id attributes and bounding boxes, then send back.
 *   2. On EXECUTE_ACTION message: perform the action on the live DOM
 *      (click / type / select / scroll) using data-pl-id targets.
 *
 * Security: this script runs in the page context but only acts on messages
 * from the extension background (chrome.runtime). It never reads or sends
 * cookies, local storage, or credentials to any remote server.
 */

'use strict';

// ── DOM Capture ────────────────────────────────────────────────────────────

function captureDom() {
  const dpr = window.devicePixelRatio || 1;
  const INTERACTIVE_SELECTOR = (
    'input, button, textarea, select, a[href], ' +
    '[role="button"], [role="link"], [role="textbox"], [role="menuitem"], ' +
    '[contenteditable="true"], [tabindex="0"], div.btn, span.btn, button.btn'
  );

  const elements = Array.from(document.querySelectorAll(INTERACTIVE_SELECTOR))
    .map((el, i) => {
      const id = 'el_' + i;
      el.setAttribute('data-pl-id', id);
      const r = el.getBoundingClientRect();
      
      const isInput = el.tagName.toLowerCase() === 'input';
      const explicitType = (el.getAttribute('type') || (isInput ? el.type : '') || '').toLowerCase();

      // Extract associated label if present
      let labelText = '';
      try {
        if (el.labels && el.labels.length > 0) {
          labelText = Array.from(el.labels).map(l => l.innerText || '').join(' ').trim();
        } else if (el.id) {
          const lbl = document.querySelector('label[for="' + el.id + '"]');
          if (lbl) labelText = (lbl.innerText || '').trim();
        }
      } catch (_) {}

      const val = (el.value !== undefined ? el.value : null) || el.getAttribute('value') || '';
      const visibleText = (el.innerText || el.textContent || '').slice(0, 300);
      const placeholder = el.getAttribute('placeholder') || el.placeholder || '';
      const ariaLabel = el.getAttribute('aria-label') || '';
      const title = el.getAttribute('title') || '';
      const className = (typeof el.className === 'string' ? el.className : '') || '';

      return {
        el_id:       id,
        tag:         el.tagName.toLowerCase(),
        type:        explicitType || null,
        name:        el.getAttribute('name') || el.name || null,
        id:          el.getAttribute('id') || el.id || null,
        aria_label:  ariaLabel || null,
        placeholder: placeholder || null,
        class:       className || null,
        label:       labelText || null,
        autocomplete: el.getAttribute('autocomplete') || null,
        value:       val,
        text:        visibleText || placeholder || ariaLabel || title,
        box: {
          x: Math.round(r.x * dpr),
          y: Math.round(r.y * dpr),
          w: Math.round(r.width * dpr),
          h: Math.round(r.height * dpr),
        },
      };
    });

  return {
    url:      location.href,
    title:    document.title,
    dpr:      dpr,
    text:     (document.body && document.body.textContent
                ? document.body.textContent.slice(0, 10000)
                : ''),
    elements,
  };
}

// ── Action Execution ───────────────────────────────────────────────────────

function executeAction(action) {
  const { action_type, target, value } = action;

  if (action_type === 'done') {
    return { success: true, message: 'Task marked done by agent.' };
  }

  // Locate element by data-pl-id
  const el = target ? document.querySelector(`[data-pl-id="${target}"]`) : null;

  if (!el && action_type !== 'scroll' && action_type !== 'wait') {
    return { success: false, message: `Element ${target} not found.` };
  }

  try {
    switch (action_type) {
      case 'click':
        try { el.scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch (_) {}
        el.focus();
        el.click();
        return { success: true, message: `Clicked ${target}` };

      case 'type':
        try { el.scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch (_) {}
        el.focus();

        // Support React / Vue controlled inputs by invoking native prototype setter
        const valToSet = value || '';
        try {
          const isTextArea = el instanceof HTMLTextAreaElement;
          const proto = isTextArea ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
          const nativeSetter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
          if (nativeSetter) {
            nativeSetter.call(el, valToSet);
          } else {
            el.value = valToSet;
          }
        } catch (_) {
          el.value = valToSet;
        }

        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
        return { success: true, message: `Typed into ${target}` };

      case 'select':
        el.value = value || '';
        el.dispatchEvent(new Event('change', { bubbles: true }));
        return { success: true, message: `Selected ${value} in ${target}` };

      case 'scroll':
        const [sx, sy] = (value || '0,300').split(',').map(Number);
        window.scrollBy(sx || 0, sy || 300);
        return { success: true, message: 'Scrolled' };

      case 'wait':
        return { success: true, message: 'Wait acknowledged' };

      default:
        return { success: false, message: `Unknown action type: ${action_type}` };
    }
  } catch (err) {
    return { success: false, message: `Action error: ${err.message}` };
  }
}

// ── Message listener ───────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === 'CAPTURE_DOM') {
    try {
      sendResponse({ type: 'DOM_CAPTURED', payload: captureDom() });
    } catch (err) {
      sendResponse({ type: 'DOM_CAPTURE_ERROR', error: err.message });
    }
    return true;
  }

  if (msg.type === 'EXECUTE_ACTION') {
    try {
      const result = executeAction(msg.action);
      sendResponse({ type: 'ACTION_RESULT', result });
    } catch (err) {
      sendResponse({ type: 'ACTION_ERROR', error: err.message });
    }
    return true;
  }
});

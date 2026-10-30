/**
 * PrivacyLens Content Script
 * 
 * Handles local capture, action execution, visual shielding overlays (closed shadow DOM),
 * and in-page screenshot redactions. Never contacts companion API directly.
 */

(function() {
    'use strict';

    let shieldHost = null;
    let shieldShadow = null;
    let screenshotMaskNodes = [];

    // =========================================================================
    // 1. Shield Overlay (Closed Shadow DOM)
    // =========================================================================

    function removeShield() {
        if (shieldHost && shieldHost.parentNode) {
            shieldHost.parentNode.removeChild(shieldHost);
        }
        shieldHost = null;
        shieldShadow = null;
    }

    function applyShield(redactions) {
        removeShield();
        if (!redactions || redactions.length === 0) return;

        shieldHost = document.createElement('div');
        shieldHost.id = 'privacylens-shield-host';
        shieldHost.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;pointer-events:none;z-index:2147483647;';
        shieldShadow = shieldHost.attachShadow({ mode: 'closed' });

        const style = document.createElement('style');
        style.textContent = `
            :host { all: initial; }
            .pl-overlay-root { position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; }
            .pl-mask-box {
                position: absolute;
                background-color: #000000;
                border-radius: 3px;
                box-shadow: 0 0 4px rgba(0, 255, 204, 0.4);
                pointer-events: auto;
                cursor: pointer;
                transition: opacity 0.2s ease;
            }
            .pl-mask-box:hover .pl-chip {
                display: flex;
            }
            .pl-chip {
                display: none;
                position: absolute;
                bottom: 100%;
                left: 0;
                margin-bottom: 4px;
                padding: 3px 8px;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                font-size: 11px;
                font-weight: 600;
                color: #ffffff;
                border-radius: 4px;
                white-space: nowrap;
                box-shadow: 0 2px 6px rgba(0,0,0,0.6);
                z-index: 1000;
                pointer-events: none;
            }
            .pl-scan-line {
                position: absolute;
                left: 0;
                width: 100%;
                height: 2px;
                background: linear-gradient(90deg, transparent, #00ffcc, transparent);
                animation: pl-sweep 0.6s ease-out forwards;
                pointer-events: none;
            }
            @keyframes pl-sweep {
                0% { top: 0%; opacity: 1; }
                100% { top: 100%; opacity: 0; }
            }
        `;
        shieldShadow.appendChild(style);

        const rootDiv = document.createElement('div');
        rootDiv.className = 'pl-overlay-root';

        // Scan line animation
        const scanLine = document.createElement('div');
        scanLine.className = 'pl-scan-line';
        rootDiv.appendChild(scanLine);

        const typeColors = {
            CARD: '#ef4444',
            PASSWORD: '#f97316',
            API_KEY: '#f59e0b',
            TOKEN: '#eab308',
            JWT: '#d97706',
            EMAIL: '#3b82f6',
            PHONE: '#06b6d4',
            AADHAAR: '#8b5cf6',
            PAN: '#a855f7',
            NAME: '#ec4899',
            ADDRESS: '#10b981',
            OTP: '#f43f5e',
            CVV: '#e11d48',
            CANARY: '#14b8a6'
        };

        const scrollX = window.scrollX || window.pageXOffset || 0;
        const scrollY = window.scrollY || window.pageYOffset || 0;

        for (const red of redactions) {
            const bbox = red.bbox;
            if (!bbox || bbox.length < 4) continue;
            const [ymin, xmin, ymax, xmax] = bbox;
            const w = xmax - xmin;
            const h = ymax - ymin;
            if (w <= 0 || h <= 0) continue;

            const box = document.createElement('div');
            box.className = 'pl-mask-box';
            box.style.top = (ymin - scrollY) + 'px';
            box.style.left = (xmin - scrollX) + 'px';
            box.style.width = w + 'px';
            box.style.height = h + 'px';

            const chip = document.createElement('div');
            chip.className = 'pl-chip';
            const color = typeColors[red.type] || '#6366f1';
            chip.style.backgroundColor = color;
            const conf = red.confidence ? ` (${Math.round(red.confidence * 100)}%)` : '';
            chip.textContent = `${red.type} | ${red.rule_id || 'rule'}${conf}`;

            box.appendChild(chip);
            rootDiv.appendChild(box);
        }

        shieldShadow.appendChild(rootDiv);
        document.documentElement.appendChild(shieldHost);
    }

    // =========================================================================
    // 2. Action Execution
    // =========================================================================

    function resolveElement(selector) {
        if (!selector) return null;
        let el = document.getElementById(selector);
        if (el) return el;
        el = document.querySelector(`[data-pl-id="${selector}"]`);
        if (el) return el;
        try {
            el = document.querySelector(selector);
            if (el) return el;
        } catch (e) {}
        return null;
    }

    async function executeAction(payload) {
        const action = payload.action;
        const targetId = payload.element_id;

        if (action === 'wait') {
            const ms = Math.min(Math.max((payload.seconds || 1.0) * 1000, 100), 5000);
            await new Promise(r => setTimeout(r, ms));
            return { success: true, summary: `Waited ${ms / 1000}s` };
        }

        if (action === 'scroll') {
            const dir = payload.direction || 'down';
            const amount = payload.amount || 300;
            window.scrollBy({ top: dir === 'down' ? amount : -amount, behavior: 'instant' });
            return { success: true, summary: `Scrolled ${dir} by ${amount}px` };
        }

        const el = resolveElement(targetId);
        if (!el) {
            return { success: false, error: `Element '${targetId}' not found in active DOM` };
        }

        try {
            el.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });
        } catch (e) {}

        if (action === 'click') {
            try {
                el.click();
                return { success: true, summary: `Clicked [${targetId}]` };
            } catch (err) {
                return { success: false, error: `Click failed: ${err.message}` };
            }
        }

        if (action === 'type' || action === 'type_secret') {
            const textToType = payload.text || '';
            el.focus();

            if (el.isContentEditable || el.getAttribute('contenteditable') === 'true') {
                try {
                    document.execCommand('selectAll', false, null);
                    document.execCommand('insertText', false, textToType);
                } catch (e) {
                    el.innerText = textToType;
                }
                el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: textToType }));
                return { success: true, summary: `Typed into contenteditable [${targetId}]` };
            }

            // Native input / textarea value setter for React/Vue reactive tracking
            const proto = el.tagName === 'TEXTAREA'
                ? window.HTMLTextAreaElement.prototype
                : window.HTMLInputElement.prototype;
            const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
            if (setter) {
                setter.call(el, textToType);
            } else {
                el.value = textToType;
            }

            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
            el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
            return { success: true, summary: `Typed into [${targetId}]` };
        }

        if (action === 'select') {
            const val = payload.value || '';
            el.value = val;
            el.dispatchEvent(new Event('change', { bubbles: true }));
            return { success: true, summary: `Selected value '${val}' on [${targetId}]` };
        }

        return { success: false, error: `Unsupported browser action: ${action}` };
    }

    // =========================================================================
    // 3. Screenshot Masking
    // =========================================================================

    function applyScreenshotMasks(rects) {
        removeScreenshotMasks();
        const scrollX = window.scrollX || window.pageXOffset || 0;
        const scrollY = window.scrollY || window.pageYOffset || 0;

        for (const rect of (rects || [])) {
            const maskDiv = document.createElement('div');
            maskDiv.className = 'pl-screenshot-mask';
            maskDiv.style.cssText = `
                position: absolute;
                top: ${(rect.y !== undefined ? rect.y : rect.ymin) + scrollY}px;
                left: ${(rect.x !== undefined ? rect.x : rect.xmin) + scrollX}px;
                width: ${(rect.width !== undefined ? rect.width : (rect.xmax - rect.xmin))}px;
                height: ${(rect.height !== undefined ? rect.height : (rect.ymax - rect.ymin))}px;
                background-color: #000000 !important;
                z-index: 2147483646 !important;
                pointer-events: none !important;
            `;
            document.documentElement.appendChild(maskDiv);
            screenshotMaskNodes.push(maskDiv);
        }
    }

    function removeScreenshotMasks() {
        for (const node of screenshotMaskNodes) {
            if (node.parentNode) {
                node.parentNode.removeChild(node);
            }
        }
        screenshotMaskNodes = [];
    }

    // =========================================================================
    // 4. SPA Mutation & History Patches
    // =========================================================================

    let debounceTimer = null;
    function notifyPageChanged() {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            try {
                chrome.runtime.sendMessage({ kind: 'page_changed', url: window.location.href });
            } catch (e) {}
        }, 800);
    }

    const observer = new MutationObserver((mutations) => {
        // Ignore mutations within PrivacyLens shield host
        const isInternal = mutations.every(m => shieldHost && shieldHost.contains(m.target));
        if (!isInternal) {
            notifyPageChanged();
        }
    });

    if (document.body) {
        observer.observe(document.body, { childList: true, subtree: true, attributes: false });
    }

    window.addEventListener('popstate', notifyPageChanged);
    const origPushState = history.pushState;
    if (origPushState) {
        history.pushState = function() {
            const res = origPushState.apply(this, arguments);
            notifyPageChanged();
            return res;
        };
    }

    // =========================================================================
    // 5. Chrome Runtime Message Dispatcher
    // =========================================================================

    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        const cmd = request.command || request;
        const kind = cmd.kind;

        if (kind === 'capture') {
            const snap = (typeof window.__privacyLensExtractDOM === 'function')
                ? window.__privacyLensExtractDOM()
                : {
                    url: window.location.href,
                    title: document.title,
                    elements: [],
                    page_text: document.body ? document.body.innerText : ''
                };
            sendResponse({ success: true, data: snap });
            return true;
        }

        if (kind === 'execute') {
            executeAction(cmd.payload).then(res => {
                sendResponse(res);
            });
            return true;
        }

        if (kind === 'set_shield') {
            if (cmd.enabled) {
                applyShield(cmd.redactions || []);
            } else {
                removeShield();
            }
            sendResponse({ success: true, enabled: cmd.enabled });
            return true;
        }

        if (kind === 'prepare_screenshot_masks') {
            applyScreenshotMasks(cmd.rects || []);
            // Wait 2 animation frames for paint settlement
            requestAnimationFrame(() => {
                requestAnimationFrame(() => {
                    sendResponse({ success: true });
                });
            });
            return true;
        }

        if (kind === 'clear_screenshot_masks') {
            removeScreenshotMasks();
            sendResponse({ success: true });
            return true;
        }

        return false;
    });

})();

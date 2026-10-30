/**
 * PrivacyLens Single Source of Truth DOM Extraction
 * 
 * Extracts interactive and content DOM elements, bounding boxes, labels,
 * parent/ancestor relationships across open shadow roots, same-origin iframes,
 * contenteditable regions, and SVG elements.
 * 
 * Generic signals only: NO page-specific rules or selectors.
 */

(function() {
    let idCounter = 1;
    const elements = [];
    const interactiveTags = ['INPUT', 'BUTTON', 'SELECT', 'TEXTAREA', 'A'];
    const ignoredTags = ['STYLE', 'SCRIPT', 'NOSCRIPT', 'LINK', 'META', 'HEAD', 'TITLE'];
    const containerTags = [
        'HTML', 'BODY', 'FORM', 'HEADER', 'MAIN', 'SECTION', 'NAV', 'FOOTER',
        'TABLE', 'TBODY', 'THEAD', 'TR', 'UL', 'OL'
    ];
    const inlineTextTags = ['SPAN', 'B', 'I', 'STRONG', 'EM', 'SMALL', 'CODE', 'SUB', 'SUP', 'A'];

    function getLabel(el) {
        if (!el) return null;
        if (el.labels && el.labels.length > 0) {
            return Array.from(el.labels).map(l => (l.innerText || '').trim()).join(' ');
        }
        if (el.id) {
            try {
                const lbl = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
                if (lbl && lbl.innerText) return lbl.innerText.trim();
            } catch (e) {}
        }
        const parentLabel = el.closest('label');
        if (parentLabel && parentLabel.innerText) return parentLabel.innerText.trim();
        return null;
    }

    const scrollX = window.scrollX || window.pageXOffset || 0;
    const scrollY = window.scrollY || window.pageYOffset || 0;
    const dpr = window.devicePixelRatio || 1.0;

    function isInlineTextWrapper(node) {
        if (!node || node.tagName !== 'SPAN') return false;
        if (node.children.length === 0) return false;
        for (const c of node.children) {
            if (!inlineTextTags.includes(c.tagName.toUpperCase())) return false;
            if (c.children.length > 0) return false;
        }
        return true;
    }

    function collectAllElements(root) {
        const result = [];
        const walker = (node, currentFrameId, currentShadowId) => {
            if (!node || node.nodeType !== 1) return;
            node._plFrameHost = currentFrameId;
            node._plShadowHost = currentShadowId;
            result.push(node);

            // Traverse shadow root if present (open or forced-open by page_hook.js)
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

            // Traverse same-origin iframes
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
                    // Ignore cross-origin frame access restrictions
                }
            }

            for (const child of node.children) {
                walker(child, currentFrameId, currentShadowId);
            }
        };
        walker(root, null, null);
        return result;
    }

    const all = collectAllElements(document.documentElement);
    for (const el of all) {
        const tag = el.tagName.toUpperCase();
        if (ignoredTags.includes(tag)) continue;

        const isWrapper = isInlineTextWrapper(el);
        const isChildOfWrapper = el.parentElement && isInlineTextWrapper(el.parentElement);
        if (isChildOfWrapper) continue;

        const isContentEditable = el.isContentEditable || el.getAttribute('contenteditable') === 'true';
        const isInteractive = interactiveTags.includes(tag) ||
            el.getAttribute('role') === 'button' ||
            el.getAttribute('role') === 'textbox' ||
            el.hasAttribute('onclick') ||
            isContentEditable;

        const hasChildren = el.children.length > 0 && !isWrapper;
        const isContainer = containerTags.includes(tag) || hasChildren;
        
        // Text extraction handling HTML text, textContent, and SVG text nodes
        const elText = (el.innerText !== undefined && el.innerText !== '')
            ? el.innerText
            : (el.textContent || '');
        const rawText = elText.trim();
        const hasText = rawText.length > 0;
        const isLeafText = (!isContainer || isContentEditable) && hasText;

        if (isInteractive || isLeafText || tag === 'IMG' || tag === 'SVG' || tag === 'TEXT') {
            let elId = el.id;
            if (!elId) {
                elId = el.getAttribute('data-pl-id');
                if (!elId) {
                    elId = 'pl-elem-' + (idCounter++);
                    el.setAttribute('data-pl-id', elId);
                }
            }

            // Ancestor hierarchy construction
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

            // Bounding box with Range.getClientRects fallback
            let bbox = null;
            const rect = el.getBoundingClientRect();
            if (rect.width > 0 && rect.height > 0) {
                bbox = [
                    rect.top + scrollY,
                    rect.left + scrollX,
                    rect.bottom + scrollY,
                    rect.right + scrollX
                ];
            } else if (el.firstChild && el.firstChild.nodeType === 3) {
                // Text node fallback using Range
                try {
                    const range = document.createRange();
                    range.selectNodeContents(el);
                    const rangeRects = range.getClientRects();
                    if (rangeRects.length > 0) {
                        const r = rangeRects[0];
                        bbox = [
                            r.top + scrollY,
                            r.left + scrollX,
                            r.bottom + scrollY,
                            r.right + scrollX
                        ];
                    }
                } catch (e) {}
            }

            let visibleText = null;
            let inputValue = null;

            if (tag === 'INPUT' || tag === 'TEXTAREA') {
                inputValue = (el.value !== undefined) ? el.value : null;
                visibleText = null;
            } else if (isContentEditable) {
                inputValue = rawText;
                visibleText = rawText;
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
                is_leaf: isLeafText,
                dpr: dpr
            });
        }
    }

    const payload = {
        url: window.location.href,
        title: document.title,
        elements: elements,
        scroll: { x: scrollX, y: scrollY },
        dpr: dpr,
        page_text: document.body ? (document.body.innerText || '') : ''
    };

    if (typeof window !== 'undefined') {
        window.__privacyLensExtractDOM = function() {
            return payload;
        };
        window.__privacyLensExtractElements = function() {
            return elements;
        };
    }

    return elements;
})();

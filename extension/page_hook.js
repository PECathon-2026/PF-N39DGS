/**
 * PrivacyLens Page Hook
 * 
 * Runs in world MAIN at document_start across all frames.
 * Intercepts Element.prototype.attachShadow to force mode 'open',
 * ensuring closed shadow DOMs are readable by local perception.
 */

(function() {
    'use strict';
    try {
        const origAttachShadow = Element.prototype.attachShadow;
        if (origAttachShadow && !Element.prototype._plShadowHooked) {
            Element.prototype.attachShadow = function(init) {
                if (init && typeof init === 'object') {
                    init.mode = 'open';
                }
                return origAttachShadow.call(this, init);
            };
            Element.prototype._plShadowHooked = true;
        }
    } catch (e) {
        // Fail-safe: do not disrupt page execution
    }
})();

/**
 * PrivacyLens Background Service Worker (Manifest V3)
 * 
 * Manages long-polling connection with local companion API (127.0.0.1:8000),
 * routes commands to pinned browser tabs, enforces 20s fail-closed command timeouts,
 * coordinates visual shielding, and proxies sanitization requests.
 */

const COMPANION_URL = 'http://127.0.0.1:8000';
let activePinnedTabId = null;
let shieldActiveTabs = new Set();
let isPollingActive = false;

// Alarms keepalive to prevent MV3 service worker dormancy during active sessions
chrome.alarms.create('pl_keepalive', { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'pl_keepalive') {
        ensurePollingLoop();
    }
});

async function getToken() {
    const data = await chrome.storage.local.get('pl_token');
    return data.pl_token || null;
}

// =============================================================================
// 1. Long-Polling Worker Loop
// =============================================================================

async function ensurePollingLoop() {
    if (isPollingActive) return;
    isPollingActive = true;

    while (true) {
        const token = await getToken();
        if (!token) {
            await new Promise(r => setTimeout(r, 2000));
            continue;
        }

        try {
            const controller = new AbortController();
            const fetchTimeout = setTimeout(() => controller.abort(), 26000);

            const resp = await fetch(`${COMPANION_URL}/v1/ext/poll?timeout=20`, {
                method: 'GET',
                headers: {
                    'X-PL-Token': token,
                    'Host': '127.0.0.1:8000'
                },
                signal: controller.signal
            });
            clearTimeout(fetchTimeout);

            if (resp.status === 200) {
                const body = await resp.json();
                if (body && body.command) {
                    // Process command asynchronously with fail-closed timeout
                    handleCommand(body.command, token);
                }
            } else if (resp.status === 401) {
                // Invalid token
                chrome.runtime.sendMessage({ kind: 'pairing_status', connected: false, error: 'Unauthorized token' }).catch(() => {});
                await new Promise(r => setTimeout(r, 3000));
            } else {
                await new Promise(r => setTimeout(r, 2000));
            }
        } catch (err) {
            // Transient fetch abort or server restart
            await new Promise(r => setTimeout(r, 1500));
        }
    }
}

// Start polling immediately
ensurePollingLoop();

// =============================================================================
// 2. Command Dispatch & 20s Fail-Closed Execution
// =============================================================================

async function getTargetTabId() {
    if (activePinnedTabId) {
        try {
            const tab = await chrome.tabs.get(activePinnedTabId);
            if (tab && tab.id) return tab.id;
        } catch (e) {
            activePinnedTabId = null;
        }
    }
    const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return activeTab ? activeTab.id : null;
}

async function handleCommand(cmd, token) {
    const cmdId = cmd.id;
    const kind = cmd.kind;
    const tabId = await getTargetTabId();

    if (!tabId) {
        await postResult(cmdId, false, null, 'No active browser tab found', token);
        return;
    }

    // Pin tab for this agent run session
    activePinnedTabId = tabId;

    let timedOut = false;
    const timeoutHandle = setTimeout(async () => {
        timedOut = true;
        await postResult(cmdId, false, null, 'Command execution timed out after 20s (fail-closed)', token);
    }, 20000);

    try {
        if (kind === 'capture') {
            chrome.tabs.sendMessage(tabId, { command: cmd }, async (response) => {
                clearTimeout(timeoutHandle);
                if (timedOut) return;

                if (chrome.runtime.lastError || !response || !response.success) {
                    const err = chrome.runtime.lastError ? chrome.runtime.lastError.message : (response ? response.error : 'Capture failed');
                    await postResult(cmdId, false, null, err, token);
                } else {
                    await postResult(cmdId, true, response.data, null, token);
                }
            });
        } else if (kind === 'execute') {
            chrome.tabs.sendMessage(tabId, { command: cmd }, async (response) => {
                clearTimeout(timeoutHandle);
                if (timedOut) return;

                if (chrome.runtime.lastError || !response || !response.success) {
                    const err = chrome.runtime.lastError ? chrome.runtime.lastError.message : (response ? response.error : 'Execute failed');
                    await postResult(cmdId, false, null, err, token);
                } else {
                    await postResult(cmdId, true, response.summary || response.data, null, token);
                }
            });
        } else {
            clearTimeout(timeoutHandle);
            await postResult(cmdId, false, null, `Unknown command kind: ${kind}`, token);
        }
    } catch (err) {
        clearTimeout(timeoutHandle);
        if (!timedOut) {
            await postResult(cmdId, false, null, err.message, token);
        }
    }
}

async function postResult(cmdId, success, data, error, token) {
    try {
        await fetch(`${COMPANION_URL}/v1/ext/result`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-PL-Token': token,
                'Host': '127.0.0.1:8000'
            },
            body: JSON.stringify({
                id: cmdId,
                success: success,
                data: data,
                error: error
            })
        });
    } catch (e) {
        // Network delivery failed
    }
}

// =============================================================================
// 3. Shield Mode Pipeline (Tab Update & Mutation Rescan)
// =============================================================================

async function runShieldScanOnTab(tabId) {
    if (!shieldActiveTabs.has(tabId)) return;
    const token = await getToken();
    if (!token) return;

    try {
        chrome.tabs.sendMessage(tabId, { command: { kind: 'capture' } }, async (res) => {
            if (!res || !res.success || !res.data) return;

            const snap = res.data;
            try {
                const apiResp = await fetch(`${COMPANION_URL}/v1/sanitize/snapshot`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-PL-Token': token,
                        'Host': '127.0.0.1:8000'
                    },
                    body: JSON.stringify({
                        url: snap.url,
                        snapshot: snap
                    })
                });

                if (apiResp.status === 200) {
                    const data = await apiResp.json();
                    chrome.tabs.sendMessage(tabId, {
                        command: {
                            kind: 'set_shield',
                            enabled: true,
                            redactions: data.redactions || []
                        }
                    });

                    // Forward counts to side panel
                    chrome.runtime.sendMessage({
                        kind: 'shield_stats_update',
                        stats: data.stats,
                        redactions: data.redactions,
                        prompt_text: data.prompt_text,
                        url: snap.url
                    }).catch(() => {});
                }
            } catch (e) {}
        });
    } catch (e) {}
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && shieldActiveTabs.has(tabId)) {
        runShieldScanOnTab(tabId);
    }
});

// Messages from Content Script or Side Panel
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.kind === 'page_changed' && sender.tab) {
        runShieldScanOnTab(sender.tab.id);
        sendResponse({ success: true });
        return true;
    }

    if (msg.kind === 'toggle_shield') {
        const tabId = msg.tabId;
        if (msg.enabled) {
            shieldActiveTabs.add(tabId);
            runShieldScanOnTab(tabId);
        } else {
            shieldActiveTabs.delete(tabId);
            chrome.tabs.sendMessage(tabId, { command: { kind: 'set_shield', enabled: false } });
        }
        sendResponse({ success: true, enabled: msg.enabled });
        return true;
    }

    if (msg.kind === 'check_connection') {
        getToken().then(token => {
            if (!token) {
                sendResponse({ connected: false, error: 'No token configured' });
                return;
            }
            fetch(`${COMPANION_URL}/v1/health`, { headers: { 'Host': '127.0.0.1:8000' } })
                .then(r => r.json())
                .then(d => sendResponse({ connected: true, version: d.version }))
                .catch(err => sendResponse({ connected: false, error: err.message }));
        });
        return true;
    }

    if (msg.kind === 'capture_screenshot') {
        const tabId = msg.tabId;
        const rects = msg.rects || [];
        const token = msg.token;

        // 1. Prepare masks in content script
        chrome.tabs.sendMessage(tabId, { command: { kind: 'prepare_screenshot_masks', rects } }, async (prepRes) => {
            try {
                // 2. Capture visible tab
                const pngB64 = await chrome.tabs.captureVisibleTab(null, { format: 'png' });
                const pureB64 = pngB64.replace(/^data:image\/png;base64,/, '');

                // 3. Post to companion /v1/sanitize/screenshot
                const verifyResp = await fetch(`${COMPANION_URL}/v1/sanitize/screenshot`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-PL-Token': token,
                        'Host': '127.0.0.1:8000'
                    },
                    body: JSON.stringify({
                        png_b64: pureB64,
                        rects: rects,
                        dpr: window.devicePixelRatio || 1.0
                    })
                });
                const verifyData = await verifyResp.json();
                sendResponse({ success: true, data: verifyData });
            } catch (err) {
                sendResponse({ success: false, error: err.message });
            } finally {
                // 4. Always remove masks
                chrome.tabs.sendMessage(tabId, { command: { kind: 'clear_screenshot_masks' } });
            }
        });
        return true;
    }

    return false;
});

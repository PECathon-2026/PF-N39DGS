/**
 * PrivacyLens — background.js (Manifest V3 Service Worker)
 *
 * Orchestrates the full privacy pipeline by bridging the live browser tab
 * and the local PrivacyLens FastAPI backend (localhost:8000).
 */

'use strict';

const API_BASE = 'http://localhost:8000';
const POLL_INTERVAL_MS = 1000;

// ── State (in-memory, cleared on new task) ─────────────────────────────────

let _state = {
  tabId:           null,
  task:            '',
  currentStep:     0,
  maxSteps:        5,
  polling:         false,
  pollTimer:       null,
  lastStage:       'IDLE',
  pendingAction:   null,
  executingAction: false,
};

function resetState() {
  if (_state.pollTimer) clearInterval(_state.pollTimer);
  _state = {
    tabId:           _state.tabId,
    task:            '',
    currentStep:     0,
    maxSteps:        5,
    polling:         false,
    pollTimer:       null,
    lastStage:       'IDLE',
    pendingAction:   null,
    executingAction: false,
  };
}

// ── Messaging helpers ──────────────────────────────────────────────────────

async function sendToPopup(msg) {
  try {
    await chrome.runtime.sendMessage(msg);
  } catch (_) {
    if (chrome.runtime.lastError) { /* suppress Unchecked runtime.lastError */ }
  }
}

async function ensureContentScriptInjected(tabId) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content.js'],
    });
  } catch (err) {
    console.warn('[PrivacyLens] Could not inject content script:', err.message);
  }
}

async function sendToContent(tabId, msg) {
  const trySend = () => new Promise((resolve) => {
    chrome.tabs.sendMessage(tabId, msg, (resp) => {
      if (chrome.runtime.lastError) {
        resolve(null);
      } else {
        resolve(resp || null);
      }
    });
  });

  let res = await trySend();
  if (!res) {
    await ensureContentScriptInjected(tabId);
    await new Promise(r => setTimeout(r, 150));
    res = await trySend();
  }
  return res;
}

// ── Screenshot capture ─────────────────────────────────────────────────────

async function captureScreenshot(tabId) {
  return new Promise((resolve, reject) => {
    chrome.tabs.captureVisibleTab(
      null,
      { format: 'png', quality: 90 },
      (dataUrl) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        if (!dataUrl) {
          reject(new Error('captureVisibleTab returned empty dataUrl'));
          return;
        }
        const b64 = dataUrl.replace(/^data:image\/png;base64,/, '');
        resolve(b64);
      }
    );
  });
}

// ── Task execution ─────────────────────────────────────────────────────────

async function runTask(tabId, task) {
  resetState();
  _state.tabId = tabId;
  _state.task = task;
  _state.currentStep = 0;

  await triggerStep(tabId, task, 0);

  _state.polling = true;
  _state.pollTimer = setInterval(() => pollStatus(tabId), POLL_INTERVAL_MS);
}

async function triggerStep(tabId, task, stepIdx) {
  await sendToPopup({ type: 'STATUS_UPDATE', stage: 'CAPTURE', step: stepIdx });

  // 1. Capture DOM from the active tab
  const domResp = await sendToContent(tabId, { type: 'CAPTURE_DOM' });
  if (!domResp || domResp.type !== 'DOM_CAPTURED') {
    await sendToPopup({
      type: 'ERROR',
      message: 'DOM capture failed. Please refresh the page tab and try again.',
    });
    return false;
  }
  const domSnapshot = domResp.payload;

  // 2. Take screenshot
  let screenshotB64 = null;
  try {
    screenshotB64 = await captureScreenshot(tabId);
  } catch (err) {
    console.warn('[PrivacyLens] Screenshot failed:', err.message);
  }

  await sendToPopup({ type: 'STATUS_UPDATE', stage: 'DETECT', step: stepIdx });

  // 3. POST to local PrivacyLens backend
  try {
    const resp = await fetch(`${API_BASE}/task`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url:                domSnapshot.url,
        task:               task,
        max_steps:          5,
        ext_dom_snapshot:   domSnapshot,
        ext_screenshot_b64: screenshotB64,
      }),
    });
    const startResp = await resp.json();
    if (startResp.error) {
      await sendToPopup({ type: 'ERROR', message: startResp.error });
      return false;
    }
  } catch (err) {
    await sendToPopup({
      type: 'ERROR',
      message: `Backend unreachable: ${err.message}. Is the server running on localhost:8000?`,
    });
    return false;
  }

  return true;
}

// ── Status polling ─────────────────────────────────────────────────────────

async function pollStatus(tabId) {
  if (!_state.polling) return;

  let status;
  try {
    const resp = await fetch(`${API_BASE}/status`);
    status = await resp.json();
  } catch (_) {
    return;
  }

  _state.lastStage = status.stage;
  await sendToPopup({ type: 'STATUS_UPDATE', ...status });

  // Forward preview data alongside status
  try {
    const [previewResp, rawResp] = await Promise.all([
      fetch(`${API_BASE}/preview`),
      fetch(`${API_BASE}/raw_preview`),
    ]);
    const preview = await previewResp.json();
    const rawData = await rawResp.json();
    await sendToPopup({
      type: 'PREVIEW_UPDATE',
      preview,
      raw_screenshot_b64: rawData.raw_screenshot_b64 || null,
    });
  } catch (_) {
    // Non-fatal
  }

  // Handle pending human approval
  if (status.pending_action && !_state.pendingAction) {
    _state.pendingAction = status.pending_action;
    await sendToPopup({ type: 'APPROVAL_REQUIRED', action: status.pending_action });
  } else if (!status.pending_action && _state.pendingAction) {
    _state.pendingAction = null;
  }

  // Handle automated action execution on the live browser DOM
  if (status.next_action && !_state.executingAction) {
    _state.executingAction = true;
    const act = status.next_action;

    let execResult = { success: false, message: 'Action execution failed' };
    try {
      const resp = await sendToContent(tabId, {
        type: 'EXECUTE_ACTION',
        action: act,
      });
      if (resp && resp.type === 'ACTION_RESULT') {
        execResult = resp.result;
      }
    } catch (e) {
      execResult = { success: false, message: e.message };
    }

    try {
      await fetch(`${API_BASE}/action_done`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(execResult),
      });
    } catch (_) {}

    _state.executingAction = false;

    // If more steps remain, trigger next action step after short DOM settle delay
    if (act.action_type !== 'done' && _state.currentStep < _state.maxSteps) {
      _state.currentStep++;
      setTimeout(() => {
        triggerStep(tabId, _state.task, _state.currentStep);
      }, 1000);
    }
  }

  // Stop polling on terminal states
  if (['DONE', 'BLOCKED', 'ERROR'].includes(status.stage)) {
    clearInterval(_state.pollTimer);
    _state.polling = false;

    if (status.stage === 'DONE') {
      await sendToPopup({ type: 'TASK_DONE', steps: status.steps_results || [] });
    } else if (status.stage === 'BLOCKED') {
      await sendToPopup({ type: 'BLOCKED', blocked_categories: status.blocked_categories });
    }
  }
}

// ── Approval handling ──────────────────────────────────────────────────────

async function sendApproval(approved) {
  _state.pendingAction = null;
  const endpoint = approved ? '/approve' : '/reject';
  try {
    await fetch(`${API_BASE}${endpoint}`, { method: 'POST' });
  } catch (err) {
    console.error('[PrivacyLens] Approval relay failed:', err.message);
  }
}

// ── Message listener (from popup) ─────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === 'RUN_TASK') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0]) {
        runTask(tabs[0].id, msg.task);
      }
    });
    sendResponse({ status: 'ok' });
    return true;
  }

  if (msg.type === 'APPROVE') {
    sendApproval(true);
    sendResponse({ status: 'ok' });
    return true;
  }

  if (msg.type === 'REJECT') {
    sendApproval(false);
    sendResponse({ status: 'ok' });
    return true;
  }
});

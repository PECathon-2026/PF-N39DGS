/**
 * PrivacyLens – background.js (Manifest V3 Service Worker)
 *
 * Orchestrates the full privacy pipeline by bridging the live browser tab
 * and the local PrivacyLens FastAPI backend (localhost:8000).
 *
 * Flow:
 *   Step 0 → POST /task          (starts fresh task, returns next_action)
 *   Steps 1+ → POST /next_step   (continues existing task, returns next_action)
 *   After each next_action fires → POST /action_done → wait 1s → capture fresh DOM → POST /next_step
 */

'use strict';

const API_BASE = 'http://localhost:8000';
const POLL_INTERVAL_MS = 1200;   // slightly > 1s to avoid racing with next_step thread

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
  // Track the last next_action identity to avoid double-execution
  lastNextActionType:   null,
  lastNextActionTarget: null,
};

function resetState() {
  if (_state.pollTimer) clearInterval(_state.pollTimer);
  _state = {
    tabId:                _state.tabId,
    task:                 '',
    currentStep:          0,
    maxSteps:             5,
    polling:              false,
    pollTimer:            null,
    lastStage:            'IDLE',
    pendingAction:        null,
    executingAction:      false,
    lastNextActionType:   null,
    lastNextActionTarget: null,
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

// ── Capture current tab state ──────────────────────────────────────────────

async function captureCurrentState(tabId) {
  const domResp = await sendToContent(tabId, { type: 'CAPTURE_DOM' });
  if (!domResp || domResp.type !== 'DOM_CAPTURED') {
    return null;
  }
  const domSnapshot = domResp.payload;

  let screenshotB64 = null;
  try {
    screenshotB64 = await captureScreenshot(tabId);
  } catch (err) {
    console.warn('[PrivacyLens] Screenshot failed:', err.message);
  }

  return { domSnapshot, screenshotB64 };
}

// ── Task execution ──────────────────────────────────────────────────────────

async function runTask(tabId, task) {
  resetState();
  _state.tabId = tabId;
  _state.task = task;
  _state.currentStep = 0;

  await sendToPopup({ type: 'STATUS_UPDATE', stage: 'CAPTURE', step: 0 });

  const captured = await captureCurrentState(tabId);
  if (!captured) {
    await sendToPopup({ type: 'ERROR', message: 'DOM capture failed. Please refresh and try again.' });
    return;
  }

  await sendToPopup({ type: 'STATUS_UPDATE', stage: 'DETECT', step: 0 });

  // Step 0: POST /task to start the task fresh
  try {
    const resp = await fetch(`${API_BASE}/task`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url:                captured.domSnapshot.url,
        task:               task,
        max_steps:          _state.maxSteps,
        ext_dom_snapshot:   captured.domSnapshot,
        ext_screenshot_b64: captured.screenshotB64,
      }),
    });
    const startResp = await resp.json();
    if (startResp.error) {
      await sendToPopup({ type: 'ERROR', message: startResp.error });
      return;
    }
  } catch (err) {
    await sendToPopup({
      type: 'ERROR',
      message: `Backend unreachable: ${err.message}. Is the server running on localhost:8000?`,
    });
    return;
  }

  // Start polling for next_action / approval / status
  _state.polling = true;
  _state.pollTimer = setInterval(() => pollStatus(tabId), POLL_INTERVAL_MS);
}

// ── Continue task with next DOM snapshot ────────────────────────────────────

async function continueTask(tabId) {
  if (_state.executingAction) return;   // guard against re-entry
  _state.executingAction = true;

  await sendToPopup({ type: 'STATUS_UPDATE', stage: 'CAPTURE', step: _state.currentStep });

  const captured = await captureCurrentState(tabId);
  if (!captured) {
    _state.executingAction = false;
    return;
  }

  await sendToPopup({ type: 'STATUS_UPDATE', stage: 'DETECT', step: _state.currentStep });

  // Steps 1+: POST /next_step — continues existing task WITHOUT resetting state
  try {
    const resp = await fetch(`${API_BASE}/next_step`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ext_dom_snapshot:   captured.domSnapshot,
        ext_screenshot_b64: captured.screenshotB64,
      }),
    });
    const r = await resp.json();
    if (r.error) {
      await sendToPopup({ type: 'ERROR', message: r.error });
    }
  } catch (err) {
    await sendToPopup({
      type: 'ERROR',
      message: `Next step failed: ${err.message}`,
    });
  }

  _state.executingAction = false;
}

// ── Status polling ──────────────────────────────────────────────────────────

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

  // Handle next_action: execute in DOM, report done, then trigger next step
  // De-duplicate: only execute if this is a new action (not the same one we already ran)
  const act = status.next_action;
  if (act && !_state.executingAction) {
    const sameAsLast = (
      act.action_type === _state.lastNextActionType &&
      act.target      === _state.lastNextActionTarget
    );
    if (!sameAsLast) {
      _state.executingAction = true;
      _state.lastNextActionType   = act.action_type;
      _state.lastNextActionTarget = act.target;

      // 1. Execute the action in the live page DOM
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

      // 2. Report completion to backend (clears next_action in _state)
      try {
        await fetch(`${API_BASE}/action_done`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(execResult),
        });
      } catch (_) {}

      _state.executingAction = false;

      // 3. If not done and more steps remain, trigger next step after DOM settles
      if (act.action_type !== 'done' && _state.currentStep < _state.maxSteps) {
        _state.currentStep++;
        setTimeout(() => continueTask(tabId), 1200);
      }
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

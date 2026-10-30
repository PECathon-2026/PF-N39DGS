/**
 * PrivacyLens — popup.js
 * Controls popup.html, interacts with background.js via chrome.runtime messages
 * and displays before/after previews and approval UI.
 */

'use strict';

const $ = (sel) => document.querySelector(sel);

const el = {
  taskInput: $('#task-input'),
  btnRun: $('#btn-run'),
  btnDashboard: $('#btn-dashboard'),
  statusChip: $('#status-chip'),
  statusStep: $('#status-step'),
  blockedBanner: $('#blocked-banner'),
  blockedDetail: $('#blocked-detail'),
  
  // Tabs
  tabRawThreats: $('#tab-raw-threats'),
  tabRawScreenshot: $('#tab-raw-screenshot'),
  rawThreatsPane: $('#raw-threats-pane'),
  rawScreenshotPane: $('#raw-screenshot-pane'),
  rawThreatsEmpty: $('#raw-threats-empty'),
  redactionBadges: $('#redaction-badges'),
  rawImgEmpty: $('#raw-img-empty'),
  rawImg: $('#raw-img'),

  tabSanText: $('#tab-san-text'),
  tabSanImg: $('#tab-san-img'),
  sanTextPane: $('#san-text-pane'),
  sanImgPane: $('#san-img-pane'),
  sanTextEmpty: $('#san-text-empty'),
  sanTextContent: $('#san-text-content'),
  sanImgEmpty: $('#san-img-empty'),
  maskedImg: $('#masked-img'),

  // Approval
  approvalSection: $('#approval-section'),
  apActionType: $('#ap-action-type'),
  apTarget: $('#ap-target'),
  apThought: $('#ap-thought'),
  btnApprove: $('#btn-approve'),
  btnReject: $('#btn-reject'),
};

function setStatus(stage, step, maxSteps) {
  el.statusChip.className = 'chip';
  if (stage === 'IDLE') {
    el.statusChip.classList.add('chip-idle');
    el.statusChip.textContent = '● IDLE';
  } else if (stage === 'BLOCKED') {
    el.statusChip.classList.add('chip-block');
    el.statusChip.textContent = '✕ BLOCKED';
  } else if (stage === 'ERROR') {
    el.statusChip.classList.add('chip-block');
    el.statusChip.textContent = '✕ ERROR';
  } else if (stage === 'DONE') {
    el.statusChip.classList.add('chip-done');
    el.statusChip.textContent = '✓ DONE';
  } else if (stage === 'VALIDATE') {
    el.statusChip.classList.add('chip-warn');
    el.statusChip.textContent = '⚠ APPROVAL';
  } else {
    el.statusChip.classList.add('chip-run');
    el.statusChip.textContent = '◌ ' + stage;
  }

  if (step !== undefined && maxSteps !== undefined && stage !== 'IDLE') {
    el.statusStep.textContent = `Step ${step}/${maxSteps}`;
  } else {
    el.statusStep.textContent = '';
  }
}

// Tab navigation setup
function initTabs() {
  el.tabRawThreats.addEventListener('click', () => {
    el.tabRawThreats.classList.add('active');
    el.tabRawScreenshot.classList.remove('active');
    el.rawThreatsPane.classList.remove('hidden');
    el.rawScreenshotPane.classList.add('hidden');
  });

  el.tabRawScreenshot.addEventListener('click', () => {
    el.tabRawScreenshot.classList.add('active');
    el.tabRawThreats.classList.remove('active');
    el.rawScreenshotPane.classList.remove('hidden');
    el.rawThreatsPane.classList.add('hidden');
  });

  el.tabSanText.addEventListener('click', () => {
    el.tabSanText.classList.add('active');
    el.tabSanImg.classList.remove('active');
    el.sanTextPane.classList.remove('hidden');
    el.sanImgPane.classList.add('hidden');
  });

  el.tabSanImg.addEventListener('click', () => {
    el.tabSanImg.classList.add('active');
    el.tabSanText.classList.remove('active');
    el.sanImgPane.classList.remove('hidden');
    el.sanTextPane.classList.add('hidden');
  });
}

function updatePreview(preview, rawB64) {
  if (rawB64) {
    el.rawImg.src = 'data:image/png;base64,' + rawB64;
    el.rawImg.classList.remove('hidden');
    el.rawImgEmpty.classList.add('hidden');
  }

  if (preview) {
    // Redaction badges
    const redactions = preview.redactions || [];
    if (redactions.length > 0) {
      el.redactionBadges.innerHTML = redactions.map(r => {
        const cat = r.category || 'UNKNOWN';
        return `<span class="badge badge-${cat}">${cat}</span>`;
      }).join('');
      el.rawThreatsEmpty.classList.add('hidden');
    }

    // Sanitized prompt text
    if (preview.sanitized_text) {
      el.sanTextContent.textContent = preview.sanitized_text.slice(0, 500) + '...';
      el.sanTextContent.classList.remove('hidden');
      el.sanTextEmpty.classList.add('hidden');
    }

    // Masked screenshot
    if (preview.masked_image_b64) {
      el.maskedImg.src = 'data:image/png;base64,' + preview.masked_image_b64;
      el.maskedImg.classList.remove('hidden');
      el.sanImgEmpty.classList.add('hidden');
    }
  }
}

// Messaging and event listeners
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'STATUS_UPDATE') {
    setStatus(msg.stage, msg.step, msg.max_steps);
    if (msg.stage !== 'BLOCKED') {
      el.blockedBanner.classList.add('hidden');
    }
    if (msg.stage !== 'VALIDATE') {
      el.approvalSection.classList.add('hidden');
    }
  }

  if (msg.type === 'PREVIEW_UPDATE') {
    updatePreview(msg.preview, msg.raw_screenshot_b64);
  }

  if (msg.type === 'APPROVAL_REQUIRED') {
    const act = msg.action;
    el.apActionType.textContent = act.action_type || '—';
    el.apTarget.textContent = act.target || '—';
    el.apThought.textContent = act.thought || '—';
    el.approvalSection.classList.remove('hidden');
    setStatus('VALIDATE');
  }

  if (msg.type === 'BLOCKED') {
    el.blockedBanner.classList.remove('hidden');
    const cats = msg.blocked_categories || {};
    el.blockedDetail.textContent = Object.keys(cats).length ? ' (' + Object.keys(cats).join(', ') + ')' : '';
    setStatus('BLOCKED');
  }

  if (msg.type === 'ERROR') {
    setStatus('ERROR');
    alert('PrivacyLens Error: ' + msg.message);
  }
});

// User action bindings
el.btnRun.addEventListener('click', () => {
  const task = (el.taskInput.value || '').trim();
  if (!task) {
    alert('Please enter a task instruction.');
    return;
  }
  setStatus('CAPTURE', 0, 5);
  chrome.runtime.sendMessage({ type: 'RUN_TASK', task });
});

el.btnDashboard.addEventListener('click', () => {
  chrome.tabs.create({ url: 'http://localhost:8000' });
});

el.btnApprove.addEventListener('click', () => {
  el.approvalSection.classList.add('hidden');
  chrome.runtime.sendMessage({ type: 'APPROVE_ACTION' });
});

el.btnReject.addEventListener('click', () => {
  el.approvalSection.classList.add('hidden');
  chrome.runtime.sendMessage({ type: 'REJECT_ACTION' });
});

// Initialize
initTabs();


/**
 * PrivacyLens Dashboard — app.js
 * Vanilla JS (no frameworks, no WebSocket).
 * Polls /status every 2 seconds; updates all UI elements reactively.
 *
 * Security: Only sanitized metadata is displayed. Raw sensitive values
 * are NEVER present in API responses and therefore NEVER rendered here.
 */
(function () {
  'use strict';

  // ── Constants ────────────────────────────────────────────────────────────
  const POLL_INTERVAL_MS = 2000;

  const STAGES = ['CAPTURE', 'DETECT', 'SANITIZE', 'GUARD', 'MODEL', 'VALIDATE', 'EXECUTE'];

  // Maps backend STAGE values → UI stage index (for the stage bar)
  const STAGE_INDEX = {
    IDLE: -1, CAPTURE: 0, DETECT: 1, SANITIZE: 2,
    GUARD: 3, MODEL: 4, VALIDATE: 5, EXECUTE: 6,
    DONE: 7, BLOCKED: 3, ERROR: -1,
  };

  // Category → { prefix, cssClass }
  const CATEGORY_BADGE = {
    CARD:    { prefix: 'CRD', cls: 'badge-CRD' },
    PASSWORD:{ prefix: 'PWD', cls: 'badge-PWD' },
    OTP:     { prefix: 'OTP', cls: 'badge-OTP' },
    AADHAAR: { prefix: 'AAD', cls: 'badge-AAD' },
    PAN:     { prefix: 'PAN', cls: 'badge-PAN' },
    EMAIL:   { prefix: 'EML', cls: 'badge-EML' },
    PHONE:   { prefix: 'PHN', cls: 'badge-PHN' },
    API_KEY: { prefix: 'KEY', cls: 'badge-KEY' },
    FACE:    { prefix: 'FCE', cls: 'badge-FCE' },
    NAME:    { prefix: 'NAM', cls: 'badge-NAM' },
    ADDRESS: { prefix: 'ADR', cls: 'badge-ADR' },
    IP:      { prefix: 'IP_', cls: 'badge-IP_' },
  };

  // ── State ────────────────────────────────────────────────────────────────
  let _pollTimer = null;
  let _lastStatus = null;
  let _evalLoaded = false;

  // ── DOM refs ─────────────────────────────────────────────────────────────
  const $ = (sel, ctx) => (ctx || document).querySelector(sel);
  const $$ = (sel, ctx) => Array.from((ctx || document).querySelectorAll(sel));

  const el = {
    // Stage bar
    stageItems: () => $$('.stage-item'),

    // Status
    statusGuardChip: () => $('#status-guard-chip'),
    statusLastAction: () => $('#status-last-action'),

    // Metrics
    metricsBar: () => $('#metrics-bar'),
    mRecall: () => $('#m-recall'),
    mPrecision: () => $('#m-precision'),
    mLatency: () => $('#m-latency'),
    mLeakage: () => $('#m-leakage'),

    // Banners
    bannerBlocked: () => $('#banner-blocked'),
    bannerBlockedDetail: () => $('#banner-blocked-detail'),
    bannerWarn: () => $('#banner-warn'),
    bannerWarnDetail: () => $('#banner-warn-detail'),

    // Panes
    paneLocalBody: () => $('#pane-local-body'),
    paneSentBody: () => $('#pane-sent-body'),
    panesWrapper: () => $('#panes-wrapper'),

    // Empty state
    emptyState: () => $('#empty-state'),

    // Eval tab
    evalContent: () => $('#eval-content'),
    evalRunning: () => $('#eval-running'),

    // Approval modal
    modalOverlay: () => $('#modal-overlay'),
    modalActionType: () => $('#modal-action-type'),
    modalTarget: () => $('#modal-target'),
    modalThought: () => $('#modal-thought'),
    modalRisk: () => $('#modal-risk'),
    modalApproveBtn: () => $('#modal-approve-btn'),
    modalRejectBtn: () => $('#modal-reject-btn'),

    // Task form
    frmUrl: () => $('#frm-url'),
    frmTask: () => $('#frm-task'),
    frmSteps: () => $('#frm-steps'),
    btnRun: () => $('#btn-run'),
    btnStop: () => $('#btn-stop'),
  };

  // ── Helpers ──────────────────────────────────────────────────────────────

  function escHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  /**
   * Render sanitized text with [REDACTED:CATEGORY] replaced by coloured badges.
   * Never reveals raw values — only the placeholder text from the API response
   * is processed here.
   */
  function renderSanitizedText(text) {
    if (!text) return '<span class="pane-body-empty">No data yet.</span>';
    return escHtml(text).replace(
      /\[REDACTED:([A-Z_]+)\]/g,
      (_, cat) => {
        const info = CATEGORY_BADGE[cat] || { prefix: cat.slice(0, 3), cls: 'badge-DEFAULT' };
        return `<span class="badge ${info.cls}" title="${escHtml(cat)}">${info.prefix}</span>`;
      }
    );
  }

  function badgeForCategory(cat) {
    const info = CATEGORY_BADGE[cat] || { prefix: cat.slice(0, 3).toUpperCase(), cls: 'badge-DEFAULT' };
    return `<span class="badge ${info.cls}">${info.prefix}</span>`;
  }

  function fmtPercent(v) {
    if (v == null) return '—';
    return Number(v).toFixed(1) + '%';
  }

  function fmtMs(v) {
    if (v == null) return '—';
    return Math.round(Number(v)) + ' ms';
  }

  // ── Stage Bar ─────────────────────────────────────────────────────────────

  function updateStageBar(stage) {
    const activeIdx = STAGE_INDEX[stage] ?? -1;
    el.stageItems().forEach((item, i) => {
      item.classList.remove('active', 'completed');
      if (i < activeIdx) item.classList.add('completed');
      else if (i === activeIdx) item.classList.add('active');
    });
  }

  // ── Guard Chip ────────────────────────────────────────────────────────────

  function updateGuardChip(status) {
    const chip = el.statusGuardChip();
    if (!chip) return;
    chip.className = 'chip';

    if (status.stage === 'IDLE') {
      chip.className += ' chip-idle';
      chip.textContent = '● IDLE';
    } else if (status.stage === 'BLOCKED') {
      chip.className += ' chip-block';
      chip.textContent = '✕ BLOCKED';
    } else if (status.stage === 'ERROR') {
      chip.className += ' chip-block';
      chip.textContent = '✕ ERROR';
    } else if (status.stage === 'DONE') {
      chip.className += ' chip-pass';
      chip.textContent = '✓ DONE';
    } else if (status.stage === 'VALIDATE') {
      chip.className += ' chip-warn';
      chip.textContent = '⚠ AWAITING APPROVAL';
    } else {
      chip.className += ' chip-idle';
      chip.textContent = '◌ ' + status.stage;
    }
  }

  // ── Banners ───────────────────────────────────────────────────────────────

  function updateBanners(status) {
    const blockedBanner = el.bannerBlocked();
    const warnBanner = el.bannerWarn();

    // Blocked banner
    if (blockedBanner) {
      if (status.blocked) {
        blockedBanner.classList.remove('hidden');
        const cats = status.blocked_categories || {};
        const detail = Object.entries(cats)
          .map(([k, v]) => `${k}(${v})`)
          .join(', ');
        const detailEl = el.bannerBlockedDetail();
        if (detailEl) detailEl.textContent = detail ? `Categories: ${detail}` : '';
      } else {
        blockedBanner.classList.add('hidden');
      }
    }

    // Warn banner for error stage
    if (warnBanner) {
      if (status.stage === 'ERROR' && status.error) {
        warnBanner.classList.remove('hidden');
        const d = el.bannerWarnDetail();
        if (d) d.textContent = `Stage failed: ${escHtml(status.error)}`;
      } else {
        warnBanner.classList.add('hidden');
      }
    }
  }

  // ── Panes ─────────────────────────────────────────────────────────────────

  function updatePanes(status) {
    const empty = el.emptyState();
    const panesWrap = el.panesWrapper();
    const isIdle = status.stage === 'IDLE';
    const noTask = !status.url && !status.task;

    if (empty) empty.classList.toggle('hidden', !(isIdle && noTask));
    if (panesWrap) panesWrap.classList.toggle('hidden', isIdle && noTask);

    // Fetch preview data to populate panes
    if (!isIdle || !noTask) {
      fetchPreview();
      fetchRawPreview();  // populate "Raw View" tab in left pane
    }
  }

  async function fetchPreview() {
    try {
      const resp = await fetch('/preview');
      if (!resp.ok) return;
      const data = await resp.json();

      const localBody = el.paneLocalBody();
      const sentBody = el.paneSentBody();
      const imgBox = $('#img-preview-box');

      // Left pane: "LOCAL ONLY" — show threats intercepted locally
      if (localBody) {
        if (data.sanitized_text) {
          const redactions = data.redactions || [];
          let threatCardsHtml = '';
          if (redactions.length > 0) {
            threatCardsHtml = redactions.map(r => `
              <div class="threat-card">
                <div class="threat-header">
                  ${badgeForCategory(r.category)}
                  <span class="threat-source">${escHtml(r.layer.toUpperCase())}</span>
                </div>
                <div class="threat-status">✓ Neutralized Locally</div>
              </div>
            `).join('');
          } else {
            threatCardsHtml = '<div class="text-muted">No sensitive personal data identified.</div>';
          }

          localBody.innerHTML = `
            <div class="local-threats-container">
              <div class="local-threats-title">
                <span>🛡️ Intercepted Sensitive Items:</span>
                <span class="count-pill">${redactions.length} Neutralized</span>
              </div>
              <div class="threats-grid">${threatCardsHtml}</div>
              <div class="local-explainer">
                <strong>Local Trust Boundary:</strong> Raw passwords, credit card digits, biometric faces, and IDs never left this machine. Only opaque rectangles & semantic tokens were egressed.
              </div>
            </div>
          `;
        } else {
          localBody.innerHTML = '<span class="pane-body-empty">Waiting for capture…</span>';
        }
      }

      // Right pane: "SENT TO MODEL" — sanitized text with [REDACTED:X] badges
      if (sentBody) {
        if (data.sanitized_text) {
          sentBody.innerHTML = renderSanitizedText(data.sanitized_text);
        } else {
          sentBody.innerHTML = '<span class="pane-body-empty">No payload yet.</span>';
        }
      }

      // Masked Image Box
      if (imgBox) {
        if (data.masked_image_b64) {
          imgBox.innerHTML = `
            <div class="img-badge-overlay">🛡️ Solid Opaque Blackout Applied (Padding=4px) — Verified by re-OCR</div>
            <img src="data:image/png;base64,${data.masked_image_b64}" class="masked-image" alt="Sanitized Page Screenshot" />
          `;
        } else {
          imgBox.innerHTML = '<span class="pane-body-empty">No visual screenshot captured.</span>';
        }
      }
    } catch (_) {
      // Non-fatal
    }
  }

  /**
   * Fetch the raw (pre-redaction) screenshot from /raw_preview and populate
   * the "Raw View" tab in the left pane.  This image shows sensitive data
   * and must NEVER be sent to any external service — it stays local.
   */
  async function fetchRawPreview() {
    try {
      const resp = await fetch('/raw_preview');
      if (!resp.ok) return;
      const data = await resp.json();
      const rawImgBox = $('#raw-img-box');
      if (rawImgBox && data.raw_screenshot_b64) {
        rawImgBox.innerHTML = `
          <div class="img-badge-overlay" style="background:var(--color-danger-bg,#ff3b3020);color:var(--color-danger,#ff3b30);">
            ⚠️ RAW SENSITIVE DATA — Local Only · Never Sent to Model
          </div>
          <img src="data:image/png;base64,${data.raw_screenshot_b64}"
               class="masked-image" alt="Raw page screenshot (local only)" />
        `;
      }
    } catch (_) {
      // Non-fatal — raw preview is best-effort
    }
  }

  function initPresets() {
    const btns = $$('.preset-btn');
    btns.forEach(btn => {
      btn.addEventListener('click', () => {
        btns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const url = btn.getAttribute('data-url');
        const task = btn.getAttribute('data-task');
        const urlInput = el.frmUrl();
        const taskInput = el.frmTask();
        if (urlInput) urlInput.value = url;
        if (taskInput) taskInput.value = task;
      });
    });
  }

  function initViewToggle() {
    // Right pane: Prompt text ↔ Visual blackout
    const btnText = $('#btn-toggle-text');
    const btnImg = $('#btn-toggle-img');
    const sentBody = el.paneSentBody();
    const imgBody = $('#pane-sent-img-body');

    if (btnText && btnImg) {
      btnText.addEventListener('click', () => {
        btnText.classList.add('active');
        btnImg.classList.remove('active');
        if (sentBody) sentBody.classList.remove('hidden');
        if (imgBody) imgBody.classList.add('hidden');
      });
      btnImg.addEventListener('click', () => {
        btnImg.classList.add('active');
        btnText.classList.remove('active');
        if (sentBody) sentBody.classList.add('hidden');
        if (imgBody) imgBody.classList.remove('hidden');
        fetchPreview();
      });
    }

    // Left pane: Threats list ↔ Raw screenshot
    const btnLocalThreats = $('#btn-toggle-local-threats');
    const btnLocalRaw    = $('#btn-toggle-local-raw');
    const localBody    = $('#pane-local-body');
    const localRawBody = $('#pane-local-raw-body');

    if (btnLocalThreats && btnLocalRaw) {
      btnLocalThreats.addEventListener('click', () => {
        btnLocalThreats.classList.add('active');
        btnLocalRaw.classList.remove('active');
        if (localBody)    localBody.classList.remove('hidden');
        if (localRawBody) localRawBody.classList.add('hidden');
      });
      btnLocalRaw.addEventListener('click', () => {
        btnLocalRaw.classList.add('active');
        btnLocalThreats.classList.remove('active');
        if (localBody)    localBody.classList.add('hidden');
        if (localRawBody) localRawBody.classList.remove('hidden');
        // Eagerly load raw preview when user switches to this tab
        fetchRawPreview();
      });
    }
  }

  // ── Metrics Bar ───────────────────────────────────────────────────────────

  function updateMetrics(evalResults) {
    const bar = el.metricsBar();
    if (!bar || !evalResults || !evalResults.summary) return;
    bar.classList.remove('hidden');
    const s = evalResults.summary;
    const mr = el.mRecall();
    const mp = el.mPrecision();
    const ml = el.mLatency();
    const mk = el.mLeakage();
    if (mr) mr.textContent = fmtPercent(s.average_detection_recall_pct);
    if (mp) mp.textContent = fmtPercent(s.average_redaction_precision_pct);
    if (ml) ml.textContent = fmtMs(s.p50_processing_latency_ms);
    if (mk) mk.textContent = s.protected_canary_leakage ?? '—';
  }

  // ── Approval Modal ────────────────────────────────────────────────────────

  function showModal(action) {
    const overlay = el.modalOverlay();
    if (!overlay) return;

    // Populate only sanitized metadata — no raw values ever in the action dict
    const mt = el.modalActionType();
    const mtar = el.modalTarget();
    const mth = el.modalThought();
    const mrisk = el.modalRisk();

    if (mt) mt.textContent = (action.action_type || '').toUpperCase();
    if (mtar) mtar.textContent = action.target || '—';
    if (mth) mth.textContent = action.thought || '(no reasoning provided)';
    if (mrisk) mrisk.textContent = action.risk_level || 'HIGH';

    overlay.classList.add('visible');

    // Focus approve button (first focusable in modal)
    const approveBtn = el.modalApproveBtn();
    if (approveBtn) approveBtn.focus();
  }

  function hideModal() {
    const overlay = el.modalOverlay();
    if (overlay) overlay.classList.remove('visible');
  }

  function trapFocus(e) {
    const overlay = el.modalOverlay();
    if (!overlay || !overlay.classList.contains('visible')) return;

    const focusable = $$('button:not([disabled]), [tabindex]:not([tabindex="-1"])', overlay);
    if (focusable.length === 0) return;

    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    if (e.key === 'Tab') {
      if (e.shiftKey) {
        if (document.activeElement === first) { e.preventDefault(); last.focus(); }
      } else {
        if (document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    } else if (e.key === 'Escape') {
      rejectAction();
    }
  }

  async function approveAction() {
    hideModal();
    try { await fetch('/approve', { method: 'POST' }); } catch (_) {}
  }

  async function rejectAction() {
    hideModal();
    try { await fetch('/reject', { method: 'POST' }); } catch (_) {}
  }

  // ── Eval Tab ──────────────────────────────────────────────────────────────

  async function loadEvalResults() {
    const evalContent = el.evalContent();
    const runningEl = el.evalRunning();
    if (!evalContent) return;

    try {
      const resp = await fetch('/eval/results');
      if (!resp.ok) return;
      const data = await resp.json();

      if (runningEl) {
        runningEl.classList.toggle('hidden', !data.running);
      }

      if (!data.results) {
        evalContent.innerHTML = '<div class="empty-state"><div class="empty-icon">📊</div>' +
          '<div class="empty-title">No evaluation results yet</div>' +
          '<div class="empty-desc">Click "Run Evaluation" to start the full test suite.</div></div>';
        return;
      }

      const results = data.results;
      const summary = results.summary || {};
      const scenarios = results.scenarios || [];
      const adversarial = results.adversarial || [];

      let html = '';

      // Summary metrics
      html += '<div class="metrics-bar" style="margin-bottom:16px">';
      html += metricHtml('Recall', fmtPercent(summary.average_detection_recall_pct));
      html += metricHtml('Precision', fmtPercent(summary.average_redaction_precision_pct));
      html += metricHtml('Latency p50', fmtMs(summary.p50_processing_latency_ms));
      html += metricHtml('Protected Leaks', summary.protected_canary_leakage ?? '—');
      html += metricHtml('Baseline Leaks', summary.baseline_canary_leakage ?? '—');
      html += metricHtml('Zero Leakage', summary.zero_leakage_in_tested_scenarios ? '✓ YES' : '✗ NO');
      html += '</div>';

      // Scenarios table
      html += '<h3 style="font-size:1rem;font-weight:700;margin-bottom:8px">Standard Scenarios</h3>';
      html += '<div class="eval-table-wrapper"><table class="eval-table"><thead><tr>';
      for (const h of ['Scenario', 'Recall %', 'Precision %', 'Leaks (baseline)', 'Leaks (protected)', 'Latency', 'Guard', 'Task']) {
        html += `<th>${escHtml(h)}</th>`;
      }
      html += '</tr></thead><tbody>';
      for (const r of scenarios) {
        const taskCls = r.task_success ? 'eval-pass' : 'eval-fail';
        const guardCls = r.guard_passed ? 'eval-pass' : 'eval-fail';
        html += '<tr>';
        html += `<td>${escHtml(r.scenario)}</td>`;
        html += `<td>${fmtPercent(r.detection_recall_pct)}</td>`;
        html += `<td>${fmtPercent(r.redaction_precision_pct)}</td>`;
        html += `<td>${r.baseline_leak_count ?? '—'}</td>`;
        html += `<td>${r.protected_leak_count ?? '—'}</td>`;
        html += `<td>${fmtMs(r.latency_ms)}</td>`;
        html += `<td class="${guardCls}">${r.guard_passed ? 'PASSED' : 'BLOCKED'}</td>`;
        html += `<td class="${taskCls}">${r.task_success ? 'PASS' : 'FAIL'}</td>`;
        html += '</tr>';
      }
      html += '</tbody></table></div>';

      // Adversarial table
      if (adversarial.length > 0) {
        html += '<h3 style="font-size:1rem;font-weight:700;margin:16px 0 8px">Adversarial Scenarios</h3>';
        html += '<div class="eval-table-wrapper"><table class="eval-table"><thead><tr>';
        for (const h of ['Scenario', 'Baseline Leaks', 'Protected Leaks', 'Guard', 'Defense']) {
          html += `<th>${escHtml(h)}</th>`;
        }
        html += '</tr></thead><tbody>';
        for (const r of adversarial) {
          const defCls = r.protected_leak_count === 0 ? 'eval-pass' : 'eval-fail';
          const guardCls = r.guard_passed ? 'eval-pass' : 'eval-fail';
          html += '<tr>';
          html += `<td>${escHtml(r.scenario)}</td>`;
          html += `<td>${r.baseline_leak_count ?? '—'}</td>`;
          html += `<td>${r.protected_leak_count ?? '—'}</td>`;
          html += `<td class="${guardCls}">${r.guard_passed ? 'PASSED' : 'BLOCKED'}</td>`;
          html += `<td class="${defCls}">${r.protected_leak_count === 0 ? 'SUCCESS' : 'FAILED'}</td>`;
          html += '</tr>';
        }
        html += '</tbody></table></div>';
      }

      evalContent.innerHTML = html;
      updateMetrics(results);
      _evalLoaded = true;

    } catch (err) {
      if (evalContent) {
        evalContent.innerHTML = '<div class="text-muted">Failed to load evaluation results.</div>';
      }
    }
  }

  function metricHtml(label, value) {
    return `<div class="metric-item"><div class="metric-value">${escHtml(String(value))}</div>` +
           `<div class="metric-label">${escHtml(label)}</div></div>`;
  }

  // ── Polling ───────────────────────────────────────────────────────────────

  async function poll() {
    try {
      const resp = await fetch('/status');
      if (!resp.ok) return;
      const status = await resp.json();
      _lastStatus = status;

      updateStageBar(status.stage);
      updateGuardChip(status);
      updateBanners(status);
      updatePanes(status);

      // Last action text
      const la = el.statusLastAction();
      if (la) la.textContent = status.last_action || '';

      // Approval modal
      if (status.pending_action) {
        showModal(status.pending_action);
      } else {
        hideModal();
      }

      // Disable/enable run button based on stage
      const runBtn = el.btnRun();
      if (runBtn) {
        const running = !['IDLE', 'DONE', 'BLOCKED', 'ERROR'].includes(status.stage);
        runBtn.disabled = running;
      }

      // Eval running indicator
      const evRunning = el.evalRunning();
      if (evRunning) evRunning.classList.toggle('hidden', !status.eval_running);

    } catch (_) {
      // Network error — silently retry
    }
  }

  function startPolling() {
    if (_pollTimer) return;
    poll(); // immediate first poll
    _pollTimer = setInterval(poll, POLL_INTERVAL_MS);
  }

  // ── Task Form ─────────────────────────────────────────────────────────────

  async function runTask() {
    const url = (el.frmUrl()?.value || '').trim();
    const task = (el.frmTask()?.value || '').trim();
    const steps = parseInt(el.frmSteps()?.value || '5', 10);

    if (!url) { alert('Please enter a URL.'); return; }
    if (!task) { alert('Please enter a task instruction.'); return; }

    try {
      const resp = await fetch('/task', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, task, max_steps: steps }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        alert('Error: ' + (data.error || resp.statusText));
      }
    } catch (err) {
      alert('Request failed: ' + err.message);
    }
  }

  async function runEval() {
    try {
      const resp = await fetch('/eval/run', { method: 'POST' });
      const data = await resp.json();
      if (!resp.ok) {
        alert('Eval error: ' + (data.error || resp.statusText));
      } else {
        // Switch to eval tab
        switchTab('eval');
      }
    } catch (err) {
      alert('Request failed: ' + err.message);
    }
  }

  // ── Tab Switching ─────────────────────────────────────────────────────────

  function switchTab(tabId) {
    $$('.nav-tab').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.tab === tabId);
    });
    $$('.tab-pane').forEach(pane => {
      pane.classList.toggle('active', pane.id === 'tab-' + tabId);
    });
    if (tabId === 'eval' && !_evalLoaded) {
      loadEvalResults();
    }
  }

  // ── Init ──────────────────────────────────────────────────────────────────

  function init() {
    // Nav tabs
    $$('.nav-tab').forEach(btn => {
      btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });

    // Task form
    const runBtn = el.btnRun();
    if (runBtn) runBtn.addEventListener('click', runTask);

    // Eval run button
    const evalRunBtn = $('#btn-eval-run');
    if (evalRunBtn) evalRunBtn.addEventListener('click', runEval);

    // Approval modal buttons
    const approveBtn = el.modalApproveBtn();
    const rejectBtn = el.modalRejectBtn();
    if (approveBtn) approveBtn.addEventListener('click', approveAction);
    if (rejectBtn) rejectBtn.addEventListener('click', rejectAction);

    // Keyboard handler (focus trap + Escape)
    document.addEventListener('keydown', trapFocus);

    // Presets & view toggles
    initPresets();
    initViewToggle();

    // Start polling
    startPolling();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();


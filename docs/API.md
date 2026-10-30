# PrivacyLens Companion API Specification

**Version:** 0.1.0  
**Protocol:** HTTP/1.1 REST + Server-Sent Events (SSE)  
**Default Bind Address:** `127.0.0.1:8000` (Strictly loopback, never `0.0.0.0`)  
**Core Principle:** *"Compute what is sensitive locally. Reason globally only on sanitized data."*

---

## 1. Threat Model & Security Posture

PrivacyLens operates as a local background companion service powering privacy-preserving browser automation and content sanitization. Because it has access to local secret vaults and unredacted perception pipelines, the companion API enforces defense-in-depth isolation against browser-based attack vectors:

### A. Loopback Binding & Port Scanning
- The service binds strictly to `127.0.0.1`. It never listens on wildcard interfaces (`0.0.0.0`), preventing any remote or LAN access.

### B. DNS-Rebinding Defence
- Malicious websites can attempt DNS rebinding attacks by resolving an attacker-controlled domain name to `127.0.0.1` after page load.
- PrivacyLens inspects the HTTP `Host` header on every incoming request. If the `Host` is not `127.0.0.1:<port>` or `localhost:<port>`, the request is aborted immediately with `400 Bad Request`.

### C. Strict Cross-Origin Resource Sharing (CORS)
- Regular web pages (e.g., `https://evil.com` or `http://localhost:3000`) must never be permitted to query the companion API.
- PrivacyLens validates the `Origin` header against an explicit allowlist:
  - Allowed: `chrome-extension://*` and `moz-extension://*`
  - Disallowed: All `http://*`, `https://*`, null origins, and wildcard `*`.
- Unauthorized origins receive `403 Forbidden` and no CORS headers are returned.

### D. Pairing Token Authentication (`X-PL-Token`)
- Upon first initialization, PrivacyLens generates an unguessable 64-character cryptographic token and writes it to `.pl_token`.
- On POSIX systems, file permissions are restricted to `0600`; on Windows, the token file is restricted to the local user account.
- Every API endpoint (except public `/v1/health`) requires the `X-PL-Token: <token>` header.
- Token comparison is performed using constant-time string comparison (`hmac.compare_digest`) to defeat timing attacks.

### E. Universal Safety Scrub
- Before any JSON payload or SSE stream chunk is transmitted over the wire, it passes through `_safety_scrub()`.
- Canary tokens (`CANARY-*`) and known raw credentials are automatically redacted with `[REDACTED:CANARY]` or filtered, ensuring zero leakage even if an internal component raises an unhandled structure.

---

## 2. Pairing & CLI Helper

To pair a browser extension with the PrivacyLens daemon without exposing secrets to shell logs or console output:

```bash
# Copy the pairing token directly to the system clipboard (Windows/macOS/Linux)
privacylens token --copy
```

**Security Guarantee:** `privacylens token --copy` uses the OS clipboard pipeline (`clip.exe`, `pbcopy`, or `xclip`) and never echoes the raw token string to stdout, stderr, or log files.

---

## 3. BrowserDriver Architecture

PrivacyLens abstracts browser execution via the `BrowserDriver` protocol defined in `privacylens.agent.driver`. This enables the agent loop to operate identically whether running in headless automated testing or via an interactive browser extension.

```
       +------------------------------------------------+
       |             PrivacyLens Agent Loop             |
       +------------------------------------------------+
                               |
               +---------------+---------------+
               |                               |
       [PlaywrightDriver]              [ExtensionDriver]
               |                               |
    (In-Process Chromium)          (Long-Polling Command Queue)
                                               |
                                    GET /v1/ext/poll
                                   POST /v1/ext/result
                                               |
                                     [Browser Extension]
                                    (Chrome / Firefox MV3)
```

### A. PlaywrightDriver
- Controls local Chromium, Chrome, or Edge instances via Playwright async API.
- Implements `capture()` via `privacylens.capture.capture_async` and `execute()` via Playwright DOM locators.
- Used for automated regression evaluations, benchmarks, and CI.

### B. ExtensionDriver
- Connects the PrivacyLens daemon to the user's active browser session via a Manifest V3 browser extension.
- **Fail-Closed Command Queue:** Commands dispatched via `_dispatch_command()` wait for the extension to poll and reply. If the extension does not return a result within 20 seconds, the command raises `TimeoutError("...fail-closed")` and marks the driver as disconnected.
- **Fail-Closed Disconnect:** Once a driver is marked disconnected, all subsequent capture or execute calls immediately raise `ConnectionError` to prevent orphaned execution.
- **Server-Side Secret Resolution:** When the agent executes a `type_secret` action referencing a surrogate (e.g. `[SURROGATE_SECRET_1]`), the real secret is resolved server-side from `SecretStore` and injected into the payload. Secret injection is strictly gated: if the current tab origin is not present in `config/trusted_origins.json`, the driver raises `PermissionError` and halts before transmitting the secret.

---

## 4. Endpoints Reference

All endpoints are hosted on `http://127.0.0.1:8000`.

### Summary Table

| Method | Endpoint | Auth Required | Description |
|---|---|---|---|
| `GET` | `/v1/health` | No | Service status and version check |
| `POST` | `/v1/sanitize/snapshot` | Yes | DOM snapshot perception and surrogate masking |
| `POST` | `/v1/sanitize/screenshot`| Yes | Pixel-verified image redaction for screenshots |
| `POST` | `/v1/agent/runs` | Yes | Launch an autonomous agent task |
| `GET` | `/v1/agent/runs/{id}/events` | Yes | Real-time SSE event stream for a run |
| `POST` | `/v1/agent/runs/{id}/approve` | Yes | Grant or deny human approval for a pending action |
| `POST` | `/v1/agent/runs/{id}/stop` | Yes | Abort an active agent run |
| `GET` | `/v1/ext/poll` | Yes | Extension long-poll for pending browser commands |
| `POST` | `/v1/ext/result` | Yes | Extension delivers command execution result |
| `POST` | `/v1/gate/test` | Yes | Evaluate egress payload against multi-layer safety gate |
| `GET` | `/v1/results/summary` | Yes | Summary of latest detection, privacy, and canary benchmarks |
| `GET` | `/v1/receipt/{run_id}` | Yes | Cryptographic/audit receipt for a completed run |
| `POST` | `/v1/secrets/profile` | Yes | Store session secrets in memory |
| `GET` | `/v1/secrets/profile` | Yes | List registered secret names (never values) |
| `POST` | `/v1/trust` | Yes | Record origin trust approval in `trusted_origins.json` |
| `PUT` | `/v1/policy/site` | Yes | Set site-specific redaction policy |
| `GET` | `/v1/policy/site` | Yes | Retrieve policies for a specific origin |

---

### Detailed Specifications

#### `GET /v1/health`
Public healthcheck endpoint.
- **Request Headers:** None required.
- **Response `200 OK`:**
```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

---

#### `POST /v1/sanitize/snapshot`
Accepts a DOM snapshot captured from the browser extension, runs local detection and policy engines, stores values in Vault, and returns a sanitized text representation and surrogate mapping.
- **Headers:** `X-PL-Token: <token>`
- **Request Body:**
```json
{
  "url": "https://example.com/checkout",
  "snapshot": {
    "title": "Payment Checkout",
    "page_text": "Billing address for Alex Rivera...",
    "elements": [
      {
        "element_id": "card-input",
        "tag": "input",
        "input_type": "text",
        "name": "cc-number",
        "input_value": "4676336067708530",
        "bbox": [10.0, 50.0, 200.0, 30.0]
      }
    ]
  }
}
```
- **Response `200 OK`:**
```json
{
  "url": "https://example.com/checkout",
  "prompt_text": "Payment Checkout\n[card-input] input cc-number: [SURROGATE_CARD_1]",
  "redactions": [
    {
      "element_id": "card-input",
      "type": "CARD",
      "action": "mask",
      "surrogate": "[SURROGATE_CARD_1]"
    }
  ],
  "stats": {
    "total_elements": 1,
    "redacted_count": 1
  }
}
```

---

#### `POST /v1/sanitize/screenshot`
Renders solid black redaction boxes over sensitive bounding boxes on a page screenshot and performs verification.
- **Headers:** `X-PL-Token: <token>`
- **Request Body:**
```json
{
  "png_b64": "iVBORw0KGgoAAAANSUhEUgAA...",
  "rects": [
    {"x": 10, "y": 50, "width": 200, "height": 30}
  ],
  "dpr": 1.0
}
```
- **Response `200 OK`:**
```json
{
  "png_b64": "iVBORw0KGgoAAAANSUhEUgAA...",
  "verified": true,
  "withheld": false
}
```

---

#### `POST /v1/agent/runs`
Initiates an autonomous browser task.
- **Headers:** `X-PL-Token: <token>`
- **Request Body:**
```json
{
  "task": "Fill out shipping and submit order",
  "start_url": "https://store.example.com/checkout",
  "approval": "ui"
}
```
- **Response `200 OK`:**
```json
{
  "run_id": "run_01j...",
  "status": "started",
  "task": "Fill out shipping and submit order"
}
```

---

#### `GET /v1/agent/runs/{run_id}/events`
Server-Sent Events (SSE) stream emitting real-time agent execution events (`step_start`, `perception`, `action`, `llm_fallback`, `run_finish`).
- **Headers:** `X-PL-Token: <token>`
- **Response `200 OK` (`text/event-stream`):**
```
event: perception
data: {"step": 1, "kind": "perception", "summary": "Found 3 input elements"}

event: action
data: {"step": 1, "kind": "action", "action": {"action": "type", "element_id": "fname", "text": "Alex"}}
```

---

#### `GET /v1/ext/poll`
Long-polling endpoint invoked by the browser extension background worker to retrieve the next pending command.
- **Headers:** `X-PL-Token: <token>`
- **Query Parameters:** `session_id` (optional), `timeout` (float, default 20.0).
- **Response `200 OK`:**
```json
{
  "command": {
    "id": "cmd_9921",
    "kind": "execute",
    "payload": {
      "action": "click",
      "element_id": "btn-submit"
    }
  }
}
```
*(If no command arrives before timeout, returns `{"command": null}`)*.

---

#### `POST /v1/ext/result`
Delivers execution results from the browser extension back to the waiting `ExtensionDriver`.
- **Headers:** `X-PL-Token: <token>`
- **Request Body:**
```json
{
  "id": "cmd_9921",
  "success": true,
  "data": {"status": "clicked"},
  "error": null
}
```
- **Response `200 OK`:**
```json
{
  "status": "accepted"
}
```

---

#### `POST /v1/gate/test`
Evaluates an egress payload against PrivacyLens's multi-layer egress inspection gate (detecting cards, keys, base64 fragments, zero-width steganography, and image exfiltration).
- **Headers:** `X-PL-Token: <token>`
- **Request Body:**
```json
{
  "name": "leaky_card"
}
```
- **Response `200 OK`:**
```json
{
  "allowed": false,
  "violations": ["CREDIT_CARD_LEAK"],
  "reasons": ["Blocked: egress payload matches sensitive CARD pattern"]
}
```

---

#### `POST /v1/secrets/profile` & `GET /v1/secrets/profile`
Stores user secrets strictly in memory for the active session.
- **POST Request Body:**
```json
{
  "secrets": {
    "checkout_card": {"value": "4676336067708530", "type": "CARD"},
    "api_token": {"value": "sk-live-abcdef12345", "type": "KEY"}
  }
}
```
- **GET Response `200 OK`:**
```json
{
  "secret_names": ["checkout_card", "api_token"]
}
```
*(Values are never returned).*

---

#### `POST /v1/trust`
Registers or revokes explicit origin trust for secret injection.
- **Request Body:**
```json
{
  "origin": "https://store.example.com",
  "secret_name": "checkout_card",
  "allow": true
}
```
- **Response `200 OK`:**
```json
{
  "status": "ok",
  "origin": "https://store.example.com",
  "secret_name": "checkout_card",
  "trusted": true
}
```

---

## 5. Extension Implementation Guide

Browser extensions communicate with PrivacyLens via Manifest V3 background service workers and content scripts.

### Background Service Worker (`background.js`)

```javascript
const COMPANION_URL = "http://127.0.0.1:8000";
let pairingToken = ""; // Configured via options page

async function pollCompanion() {
  while (true) {
    if (!pairingToken) {
      await new Promise(r => setTimeout(r, 2000));
      continue;
    }
    try {
      const resp = await fetch(`${COMPANION_URL}/v1/ext/poll?timeout=15`, {
        headers: {
          "X-PL-Token": pairingToken,
          "Host": "127.0.0.1:8000"
        }
      });
      if (resp.status === 200) {
        const body = await resp.json();
        if (body.command) {
          await handleCommand(body.command);
        }
      } else {
        await new Promise(r => setTimeout(r, 3000));
      }
    } catch (err) {
      console.warn("Companion poll connection lost, retrying in 2s...", err);
      await new Promise(r => setTimeout(r, 2000));
    }
  }
}

async function handleCommand(cmd) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) {
    await postResult(cmd.id, false, null, "No active tab available");
    return;
  }

  try {
    const res = await chrome.tabs.sendMessage(tab.id, { command: cmd });
    await postResult(cmd.id, res.success, res.data, res.error);
  } catch (err) {
    await postResult(cmd.id, false, null, err.message);
  }
}

async function postResult(cmdId, success, data, error) {
  await fetch(`${COMPANION_URL}/v1/ext/result`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-PL-Token": pairingToken,
      "Host": "127.0.0.1:8000"
    },
    body: JSON.stringify({ id: cmdId, success, data, error })
  });
}

// Start polling
pollCompanion();
```

### Content Script (`content.js`)

```javascript
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const { command } = request;
  if (command.kind === "capture") {
    // Collect DOM elements
    const elements = Array.from(document.querySelectorAll("input, button, select, textarea, div[role]")).map(el => {
      const rect = el.getBoundingClientRect();
      return {
        element_id: el.id || el.name || `el-${Math.random().toString(36).substr(2, 9)}`,
        tag: el.tagName.toLowerCase(),
        input_type: el.type || null,
        name: el.name || null,
        visible_text: el.innerText || "",
        input_value: el.value || null,
        bbox: [rect.left, rect.top, rect.width, rect.height]
      };
    });

    sendResponse({
      success: true,
      data: {
        url: window.location.href,
        title: document.title,
        elements: elements
      }
    });
  } else if (command.kind === "execute") {
    const { action, element_id, text } = command.payload;
    const target = document.getElementById(element_id) || document.querySelector(`[name="${element_id}"]`);
    if (!target) {
      sendResponse({ success: false, error: `Element '${element_id}' not found` });
      return;
    }

    if (action === "click") {
      target.click();
      sendResponse({ success: true, data: { action: "click", element_id } });
    } else if (action === "type" || action === "type_secret") {
      target.focus();
      target.value = text;
      target.dispatchEvent(new Event("input", { bubbles: true }));
      target.dispatchEvent(new Event("change", { bubbles: true }));
      sendResponse({ success: true, data: { action: "type", element_id } });
    } else {
      sendResponse({ success: false, error: `Unknown action: ${action}` });
    }
  }
  return true;
});
```


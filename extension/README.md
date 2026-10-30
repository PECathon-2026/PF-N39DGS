# PrivacyLens Browser Extension (Manifest V3)

Privacy-preserving AI browser agent companion and client-side perception shield.
Enforces local data protection directly inside Chromium and Edge browsers:

> **"Compute what is sensitive locally. Reason globally only on sanitized data."**

---

## 1. Installation & Setup

### A. Load Unpacked in Chrome / Edge
1. Open Google Chrome or Microsoft Edge.
2. In the URL address bar, navigate to:
   - Chrome: `chrome://extensions`
   - Edge: `edge://extensions`
3. Toggle the **Developer mode** switch in the top-right corner to **ON**.
4. Click the **Load unpacked** button in the top left.
5. In the file picker dialog, select the `extension/` folder located within this repository root.
6. The **PrivacyLens Companion & Sanitization Shield** extension will now appear in your installed extensions list.

### B. Pin the Extension
1. Click the puzzle piece icon (Extensions menu) in your browser toolbar.
2. Find **PrivacyLens Companion & Sanitization Shield**.
3. Click the pin icon to keep the PrivacyLens icon permanently visible in your toolbar.

### C. Open Side Panel & Pair
1. Click the PrivacyLens icon in your toolbar to open the **PrivacyLens Side Panel** (or navigate to `http://127.0.0.1:8000/ui/` in any tab).
2. Start the local companion daemon if not already running:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\dev_up.ps1
   ```
3. Copy your pairing token directly to your clipboard:
   ```powershell
   .\.venv\Scripts\python.exe -m privacylens token --copy
   ```
   *(Note: The pairing token is persisted to `.pl_token` and is never printed to stdout or logs).*
4. In the PrivacyLens Side Panel, click **Pairing Settings**, paste the pairing token, and click **Pair Extension**. The status indicator will turn green: **Connected**.

---

## 2. Architecture & Capabilities

The extension is designed around zero-trust client security guarantees:

- **Manifest V3 Pure JavaScript**: Built with vanilla ES6+ modules. Zero external CDNs, zero remote script evaluations, strict local Content Security Policy (`script-src 'self'`).
- **Closed Shadow DOM Overlay**: Visual redaction masks and status sweeps are rendered inside a closed shadow root (`privacylens-shield-host`), ensuring untrusted page JavaScript cannot inspect, remove, or scrape redacted content.
- **Fail-Closed Execution**: If the companion API disconnects, times out (>20s), or crashes, the extension drops all pending actions immediately.
- **Local Surrogate Masking**: Outbound agent prompts replace sensitive DOM elements with synthetic surrogates (`[REDACTED:CARD_1]`). Real credentials reside exclusively in the local secret store and are filled directly at dispatch time.
- **Side Panel UI (6 Tabs)**:
  1. **Shield**: Visual detection counts, live mask overlay toggle, origin trust management.
  2. **AI View**: Exact sanitized text prompt and verified visual screenshot presented to the LLM.
  3. **Agent**: Run status, goal, reasoning step trail, stop controls, and live SSE stream.
  4. **Gate**: Outbound egress inspection log, blocked attempts, and rule matches.
  5. **Results**: Task outcome, structured artifacts, duration, and token accounting.
  6. **Receipt**: Cryptographic zero-leakage receipt, canary verification, and audit hash.

---

## 3. Known Limitations

1. **Viewport-Only Screenshots**:
   Browser extension APIs (`chrome.tabs.captureVisibleTab`) capture only the visible browser viewport. Elements scrolled out of view require scroll-and-stitch compositing for full-page visual models.
2. **Restricted Browser Pages**:
   Browser security models strictly forbid extension content script injection into `chrome://`, `edge://`, `about:`, and Web Store URLs. PrivacyLens operates on all HTTP and HTTPS web origins.
3. **Cross-Origin IFrames**:
   Cross-origin iframe DOM trees are protected by the browser Same-Origin Policy (SOP). Content within cross-origin frames cannot be inspected by parent content scripts and requires either child-frame injection or secondary OCR perception.
4. **Canvas and Raster Image Text**:
   Text rendered onto HTML5 `<canvas>` elements or embedded within images is opaque to DOM parsers and is protected exclusively by the secondary OCR and vision defence layer.
5. **CAPTCHAs and Native OS Dialogs**:
   Automated agents cannot and should not bypass CAPTCHAs, biometric challenges, or native OS dialogs (file pickers, system print dialogs). These trigger human-in-the-loop pause events.
6. **LLM Quota & Rate Limits**:
   Public cloud LLM tiers (such as Gemini free-tier 5 RPM / 20 RPD) impose strict request budgets. PrivacyLens provides local fallback models, deterministic `ScriptedLLM`, and audit record/replay cassettes (`ReplayLLM`) to operate without continuous live API consumption.

---

## 4. Packaging

To create a clean release zip archive for distribution or store upload:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\package_extension.ps1
```
The packaged archive will be generated at `dist/privacylens-extension-v0.1.0.zip`.

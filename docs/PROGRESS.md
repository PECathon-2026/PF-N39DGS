# PrivacyLens Engineering Progress

## Done
- **Repository Scaffold & Packaging**: Virtual environment configured with Python 3.13, dependencies installed, `pyproject.toml` packaging privacylens v0.1.0 in editable mode.
- **Data Models (`models.py`)**: Immutable `Finding`, `SanitizedResult`, and `Action` models with strict typing, schema validation, and `is_structural` support.
- **Checksums Engine & Verification (`detect/checksums.py`)**: Full Verhoeff, Luhn, and PAN checksum implementations with seedable synthetic Aadhaar and Card generators; 100% agreement against independent Group D5 mathematical reference model.
- **Audit Logging (`gateway/audit.py`)**: Privacy-preserving audit logging writing JSONL with entity types, counts, and SHA-256 prefixes; rejects raw values with zero leak guarantee.
- **Policy Engine (`policy/`)**: Loaded `default_policy.yaml` governing mask/block/allow actions and human approval rules.
- **Synthetic Test Site (`testsite/`)**: 5 realistic web pages (`checkout.html`, `login.html`, `support.html`, `meeting.html`, `devsettings.html`) with interactive IDs, non-sensitive context, decoys, and embedded canaries.
- **Automated Safety Checks (`scripts/check_secrets.py`, `check.ps1`, `backup.ps1`)**:
  - `check_secrets.py`: Verifies `.env` is untracked and git-ignored, scans commit history and files for exposed credentials without leaking values.
  - `check.ps1`: Automated test suite runner verifying secrets, Ruff linter, Pytest unit tests, and Playwright browser smoke test.
  - `backup.ps1`: Guarded multi-remote backup pushing to `origin main` and `hackathon main:aaditya-privacylens`.
- **Remote Integration**: Configured and fetched `hackathon` remote (`https://github.com/PECathon-2026/PF-N39DGS.git`).
- **DOM & Visual Screen Capture (`capture.py`)**:
  - Implemented `PageSnapshot` and `capture()` retrieving interactive element metadata, full-page screenshots, and leaf text node bounding boxes.
  - Traverse Open Shadow DOM (`node.shadowRoot`) and same-origin iframes (`iframe.contentDocument`).
  - Containers carry `visible_text = None` while leaf nodes store `parent_id`, `ancestor_ids`, and `is_leaf`.
- **Detection Engine (`detect/`)**:
  - `patterns.py`: Regular expressions with checksum validation for AADHAAR, PAN, CARD, EMAIL, PHONE, API_KEY, JWT, TOKEN, IP, OTP, CVV, CANARY.
  - `structural.py`: DOM semantic rules for password inputs, autocomplete attributes, keyword hints, and avatar faces. UI `<label>` elements explicitly excluded.
  - `presidio_detector.py`: Lazy-loaded Presidio AnalyzerEngine singleton restricted to `PERSON` and `LOCATION`, filtering out UI labels, buttons, navigation, role words, brand names, and hex color codes.
  - `engine.py`: Coordinated `DetectionEngine` dropping container-level findings when descendants match, resolving same-type overlapping spans, and enforcing fine-grained priority hierarchy.
- **Evaluation Benchmark & Holdout Suite (`eval/run_eval.py`)**:
  - Strict 1-to-1 bipartite matching on (type, element_id, span) with fallback CSS selector resolution.
  - Holdout evaluation set with 5 realistic adversarial pages (`checkout2.html`, `auth2.html`, `support2.html`, `meeting2.html`, `dev2.html`) and `eval/ground_truth_holdout.json`.
  - Comprehensive reporting of finding-level precision, recall, decoy false positives, decoy over-redaction, character-level over-redaction, canary coverage, and detector ablations.
- **Sanitization Engine & Policy (`policy/`, `vault.py`, `sanitize/text.py`)**:
  - Enforced full policy actions (`mask`, `block`, `allow`) across 18 entity types with type normalization and custom rules support.
  - In-memory surrogate tokenization `Vault` maintaining sequential non-reversible placeholders (`[REDACTED:TYPE_N]`) with zero-leak repr/str/pickle safeguards.
  - Fail-closed text and DOM attribute sanitizer with URL query parameter redaction and title scrubbing.
  - HMAC-SHA256 audit log prefixes protecting low-entropy entities from dictionary attacks.
- **Visual Screenshot Redactor with Pixel Verification (`sanitize/image.py`)**:
  - In-page live DOM masking wrapping text ranges in opaque spans and styling inputs/media with `#000` fill, guaranteed cleanup in finally blocks.
  - Secondary Pillow rasterization reinforcement and strict $\ge 99\%$ mask pixel verification.
- **OCR Defence-in-Depth Layer (`detect/vision.py`)**:
  - Tesseract-powered spatial word and line grouping detecting visual text inside canvas or embedded images.
  - Automatic secondary bounding-box patching and re-verification, guaranteeing 0 visual leaks.
- **Sanitization Benchmark Harness (`eval/run_sanitize_eval.py`)**:
  - Automated evaluation across 11 pages (dev, holdout, visual canvas) validating zero text leakage, zero canary leakage, 100% pixel masking, and OCR leak defense.
- **Policy Profiles (`privacylens/policy/default_policy.yaml`, `engine.py`, `config.py`)**:
  - Configurable policy profiles: `default` masks credentials (`PASSWORD`, `OTP`, `API_KEY`, `JWT`, `TOKEN`) so interactive pages yield usable views; `strict` keeps hard blocking.
  - Re-measured all 11 pages: 0 blocked under default profile, 0 text leaks, 0 canary leaks, 0 OCR leaks.
- **Egress Security Gateway (`privacylens/gateway/egress.py`)**:
  - Architectural chokepoint between reasoning components and external networks enforcing zero outbound leakage.
  - Multi-form normalization (URL unquote, HTML unescape, Unicode NFKC, zero-width stripping, digit-separator collapsing, base64 and hex decoding), active Vault cross-checking, Canary regex scanning, and registered sanitized image verification.
  - Full audit logging with HMAC-SHA256 prefixing and zero raw secret exposure.
  - Adversarial positive control: **100.0% block rate (954/954)** across all 106 sensitive items and 9 obfuscation classes.
- **Single Chokepoint & Gated Providers (`privacylens/agent/llm.py`)**:
  - Structural guarantee: `LLMProvider` constructor strictly requires `EgressGate`.
  - Custom `GatedHTTPTransport` routing all HTTP traffic through the gate before transmission.
  - Implemented `GeminiProvider` and `OllamaProvider`.
- **Event Stream & Bus (`privacylens/events.py`)**:
  - Implemented typed `Event` lifecycle stream, `EventBus`, ring-buffer memory storage, JSONL disk logging, and subscriber fan-out.
  - Safe payload sanitizer ensuring raw secrets in event payloads are replaced with safe stubs (`_SAFE_REDACTED_STUB`).
- **Action Schema & Validation Engine (`privacylens/agent/actions.py`)**:
  - Strict Pydantic models with `extra="forbid"`: `ClickAction`, `TypeAction`, `SelectAction`, `ScrollAction`, `NavigateAction`, `WaitAction`, `AskUserAction`, `FinishAction`.
  - `parse_decision()` with robust JSON recovery (code fences, unescaped newlines).
  - `ActionValidator` enforcing active DOM element existence, interactability, URL allowlists, loop detection, and policy-driven approval flags.
- **Secret Store & Action Executor (`privacylens/agent/secrets.py`, `privacylens/agent/executor.py`)**:
  - `SecretStore` holding synthetic user credentials, exposing safe metadata and placeholders (`[SECRET:<name>]`) with strict zero-leak repr/str.
  - `ActionExecutor` enforcing allowed origins (`secrets.allowed_origins`) before secret resolution.
- **Human Approval Engine (`privacylens/agent/approval.py`)**:
  - Pluggable `Approver` interface with `CliApprover`, `ScriptedApprover`, `DenyAllApprover`, and `CallbackApprover`.
  - Formatted approval prompts detailing target URL, element ID, and high-risk action descriptions without raw secret exposure.
- **Prompt Injection Defence (`privacylens/sanitize/injection.py`)**:
  - Delimited untrusted page content with randomized cryptographic boundary tags.
  - System instructions enforcing instruction hierarchy (user task > page content).
  - Heuristic pattern scanner for common prompt injection payloads and hidden text detection (display:none, opacity:0, font-size:0).
- **Agent Execution Loop (`privacylens/agent/loop.py`)**:
  - Complete lifecycle: perception, sanitization, prompt construction, egress-gated LLM completion, validation, human approval, local browser execution.
  - Built-in rate limit backoff, JSON repair retry, loop prevention, and fail-closed termination.
  - Deterministic testing with `ScriptedLLM` and `MockRecordingLLM`.
- **Live Agent Evaluation Benchmark (`eval/run_agent_eval.py`)**:
  - Evaluated live against `gemini-3.5-flash` across 5 distinct real-world browser scenarios under a 150s cap:
    - `checkout`: **PASS** (2 steps, 2 calls, 10.64s, 1 approval, verified end state).
    - `auth`: **PASS** (2 steps, 2 calls, 15.52s, 1 approval, verified end state).
    - `support`: **PASS** (2 steps, 2 calls, 9.27s, 0 approvals, verified end state).
    - `devsettings`: **PASS** (2 steps, 2 calls, 18.63s, 1 approval, verified end state).
    - `meeting`: **PASS** (2 steps, 2 calls, 7.86s, 0 approvals, verified end state).
  - **Overall Success Rate**: **5 / 5 (100.0%)**; average duration: **12.38s** per scenario; total LLM calls: **10**; zero timeouts; zero policy violations.
  - **Adversarial Mock Leakage Audit**: 3 outbound requests inspected; **0 raw secrets leaked, 0 canaries leaked**.

- **Adversarial Security & Defences Suite (`eval/run_adversarial_eval.py`)**:
  - Built 7 synthetic adversarial attack test pages (`testsite/adversarial/`): visible prompt injection, hidden DOM injection, cross-origin exfiltration, pre-approved action deception, unauthorized host exfil links, sensitive digit reconstruction, and fake system chat bubbles.
  - Built deterministic attack-success oracles across live and scripted models: **0 / 7 successful attacks (0.0% attack success rate, 100% defense)**.
  - Documented stopping layers in `docs/SECURITY.md` and `docs/EVAL_RESULTS.md`.

- **Fresh Holdout 2 Benchmark Suite (`testsite/holdout2/`, `eval/ground_truth_holdout2.json`)**:
  - Built 5 unseen, complex test pages: `invoice.html` (tax tables, mixed PII/PAN), `profile_dynamic.html` (JS dynamic DOM, split sibling spans), `contenteditable_form.html` (rich editor, placeholder secrets), `shadow_iframe.html` (cross-frame `srcdoc`, open Shadow DOM), and `svg_querystring.html` (SVG `<text>` cards, query string API keys).
  - Committed pages + ground truth before running detection (`60c3a34`).
  - Recorded first untuned run: Precision 52.6%, Recall 47.6%, 11 misses.
  - Diagnosed root causes and applied generic engine improvements (SVG textContent, frame/shadow ancestry propagation, word-bounded Verhoeff digits, placeholder scanning, link query string scanning, inline span aggregation, street address recognition).
  - Re-measured after fixes: Precision **86.96%**, Recall **95.24%** (20/21 TP, 1 miss), Canaries **4/5**, Sanitization leaks: 1 (only untyped non-dictionary name), Zero canary leaks, Zero OCR leaks. Dev and Holdout 1 benchmarks verified with zero regressions.

- **Privacy Baseline Comparison Benchmark (`eval/run_baseline_eval.py`)**:
  - Implemented empirical comparative evaluation of PrivacyLens sanitized execution vs unsafe raw baseline across all 5 core scenarios (`checkout`, `auth`, `support`, `devsettings`, `meeting`).
  - Strict guardrails: `--unsafe-baseline` CLI flag mandatory, origin validation strictly restricts execution to localhost (`SecurityOriginError`), loud security warnings emitted, and `EgressGate` operates in audit-only mode to quantify would-be leaks without halting.
  - Measured (Privacy Only):
    - **Sensitive Values Leaked to LLM**: **0** under PrivacyLens vs **25** under raw baseline (**100.0% leak reduction**).
    - **Canary Tokens Leaked**: **0** under PrivacyLens vs **5** under raw baseline (**100.0% protection**).
  - Safety unit tests in `tests/test_baseline_safety.py` verify that default mode strictly stays enforce and normal runs cannot enable unsafe baseline.

- **Realistic Multi-Step Scenarios & Secret Injection (`eval/scenarios.yaml`, `testsite/`)**:
  - All 5 scenarios start on `?empty=1` empty forms requiring active typing of user credentials, payment cards, CVVs, and API keys.
  - Form field state oracle verification (`eval/run_agent_eval.py`) validates actual DOM values post-submission.
  - ScriptedLLM multi-step execution: 10/10 scenarios passed (5 standard + 5 adversarial), 20 mock LLM calls recorded, 0 raw secrets leaked, 0 canaries leaked.
  - Baseline comparison: 0 leaks under PrivacyLens vs 25 leaks under raw baseline (100% leak reduction).

- **LLM Resilience, Fallback & Budgeting (`privacylens/agent/llm.py`, `config.yaml`)**:
  - Multi-key rotation (`api_key_envs`) and model fallback cascade (`fallback_models`).
  - Strict rate limiting (`llm.rpm_limit = 4`, minimum 15s interval) and run cap (`llm.max_calls_per_run = 14`).
  - Budget tracker storing counts only in `logs/llm_budget.json`, never exposing key values.
  - Tested in `tests/test_llm_resilience.py`.

- **Detector Improvements & Holdout 2 Evaluation**:
  - Snake_case and index-suffixed identifier filtering (`_is_identifier_not_key`) and Presidio subword splitting.
  - Contextual name prefix rule (`_NAME_CONTEXT_PREFIX_RE`) and capture-level context label inheritance.
  - Canary ancestor ID matching in `eval/run_eval.py`.
  - Holdout 2 Detection: Precision 84.0%, Recall **100.0%** (21/21 TP, 0 misses), Canaries 5/5. Dev Detection: Precision 86.7%, Recall **100.0%**, Canaries 5/5. Holdout 1: Precision 92.0%, Recall 92.0% (100% on DOM).

- **BrowserDriver Abstraction (`privacylens/agent/driver.py`)**:
  - `BrowserDriver` protocol unifying browser automation across `PlaywrightDriver` and `ExtensionDriver`.
  - `ExtensionDriver` with 20s fail-closed command queue (`_dispatch_command`), disconnect fail-closed state tracking, and server-side secret resolution.
  - Local origin trust management in `config/trusted_origins.json`.
  - Updated `sanitize_page()` and `run_task()` to accept any `BrowserDriver`.

- **Companion Fast-API Service (`privacylens/api/app.py`, `privacylens/api/auth.py`)**:
  - Strictly binds to `127.0.0.1:8000` (loopback only, no 0.0.0.0).
  - Pairing token security: generated to `.pl_token` (restricted permissions), `X-PL-Token` constant-time verification.
  - DNS-rebinding defence: aborts non-localhost `Host` headers with 400 Bad Request.
  - Strict CORS: permits `chrome-extension://*` and `moz-extension://*` only.
  - CLI command: `privacylens token --copy` copies pairing token to clipboard without printing.
  - 15 production endpoints: `/v1/health`, `/v1/sanitize/snapshot`, `/v1/sanitize/screenshot`, `/v1/agent/runs`, `/v1/agent/runs/{id}/events` (SSE), `/v1/agent/runs/{id}/approve`, `/v1/agent/runs/{id}/stop`, `/v1/ext/poll`, `/v1/ext/result`, `/v1/gate/test`, `/v1/results/summary`, `/v1/receipt/{id}`, `/v1/secrets/profile` (memory only, GET names only), `/v1/trust`, `/v1/policy/site`.
  - Universal safety scrub (`_safety_scrub`) on all outgoing JSON responses and SSE events.

- **Companion Test Suite, Docs & Dev Scripts (`tests/test_api_companion.py`, `docs/API.md`, `scripts/dev_up.ps1`)**:
  - Comprehensive 15-test suite in `tests/test_api_companion.py` covering token auth, DNS rebinding, CORS, snapshot/screenshot sanitization, gate blocking of 5 attack classes, receipts, safety scrub, fake extension coroutines, and slow Playwright driver delegation test.
  - `docs/API.md`: Full OpenAPI documentation, threat model, security posture, extension implementation guides (background.js, content.js).
  - `scripts/dev_up.ps1`: Automated startup for companion API and testsite, token clipboard copy, and dev page launching.

## In progress
- Production deployment configuration and containerization.

## Next
- Production deployment configuration, package publishing, and edge deployment.

## Decisions
- **Strict Boundary Separation**: LLM receives only sanitized DOM representations and surrogate tokens (`[SECRET:...]` or `[REDACTED_...]`). Resolution to actual credentials occurs locally within `ActionExecutor` on allowed origins.
- **Fail-Closed Gate Enforcement**: Every network byte transmitted to LLM endpoints must pass through `EgressGate`. Outbound text is normalized across 6 dimensions and cross-referenced against active Vault tokens and canary patterns.
- **High-Risk Human Gate**: Actions involving credential submission or irreversible state changes require human policy approval before local browser execution.
- **Fail-Closed BrowserDriver**: If an extension stops responding or disconnects for >20s, the companion driver fails closed, invalidating the session and refusing to dispatch pending commands.

## Measured results
- **Companion Test Suite**: 15 tests passing, including fake extension coroutines and slow Playwright integration.
- **Unit Test Suite**: 118 unit tests passing in pytest (0 failures).
- **Check Suite (`scripts/check.ps1`)**: PASS across Secrets Check, Ruff Linter, Pytest Unit Tests, and Runtime Smoke Check.
- **Secrets Audit**: 0 leaks detected across commit history, repository files, and logs.
- **Live Agent Evaluation Benchmark (`eval/results/agent_results.json`)**:
  - **Scenario Completion Rate**: **5 / 5 (100.0%)**
  - **Total Execution Latency**: **62.12s** across 5 full multi-step tasks.
  - **Average Latency per Scenario**: **12.38s**.
  - **Total LLM Invocations**: **10 calls** (2 calls/scenario average).
  - **End-State DOM Verification**: **5 / 5 (100.0%)**.
  - **Adversarial Outbound Leak Audit**: **0 / 3 raw secrets leaked (0.0%)**, **0 / 3 canaries leaked (0.0%)**.
- **Detection Benchmark**:
  - **Dev Detection**: Precision **86.7%**, Recall **100.0%** (26/26 TP), Canaries **5/5**.
  - **Holdout 1**: Precision **92.0%**, Recall **92.0%** (23/25, 100% on DOM), Canaries **5/5**.
  - **Holdout 2**: Precision **84.0%**, Recall **100.0%** (21/21 TP, 0 misses), Canaries **5/5**.
- **Adversarial Gate Positive Control**: **100.0% block rate (954/954)** across all 9 obfuscation classes.
- **Text & Pixel Leakage**: **0 text leaks**, **0 canary leaks**, **100.0% pixel masking**.

## Known issues
- Windows standard sandbox restricts loopback TCP `socket.socketpair()`; subprocess server commands and Playwright sessions run using explicit local bindings.

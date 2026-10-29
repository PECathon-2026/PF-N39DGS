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
  - `patterns.py`: Regular expressions with checksum validation for AADHAAR (with spaced support), PAN (with lowercase support), CARD, EMAIL, PHONE, API_KEY, JWT, TOKEN, IP (excluding versions), OTP (with refined keywords), CVV, CANARY.
  - `structural.py`: DOM semantic rules for password inputs, autocomplete attributes, keyword hints, and avatar faces. UI `<label>` elements explicitly excluded.
  - `presidio_detector.py`: Lazy-loaded Presidio AnalyzerEngine singleton restricted to `PERSON` and `LOCATION`, filtering out UI labels, buttons, navigation, role words, and hex color codes.
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
  - Added configurable policy profiles: `default` masks credentials (`PASSWORD`, `OTP`, `API_KEY`, `JWT`, `TOKEN`) so interactive pages yield usable views; `strict` keeps hard blocking.
  - Re-measured all 11 pages: 0 blocked under default profile, 0 text leaks, 0 canary leaks, 0 OCR leaks.
  - Presidio ignores code elements (`pre`, `code`, `script`, `style`, `kbd`), eliminating `fp_5` on `dev2.html` and improving holdout precision to 88.5%.
- **Egress Security Gateway (`privacylens/gateway/egress.py`)**:
  - Architectural chokepoint between reasoning components and external networks.
  - Implemented `EgressRequest`, `Decision`, `EgressBlocked`, and `EgressGate`.
  - Comprehensive inspection: host allowlisting (`egress.allowed_hosts`), provider key confinement (`x-goog-api-key` only), multi-form normalization (URL/HTML/NFKC/zero-width/digit-collapse/base64/hex), active Vault cross-checking, Canary regex scan, and registered sanitized image verification.
  - Full audit logging via `AuditLogger` with zero raw secrets.
- **Single Chokepoint & Gated Providers (`privacylens/agent/llm.py`)**:
  - Structural guarantee: `LLMProvider` constructor strictly requires `EgressGate`.
  - Custom `GatedHTTPTransport` and `GatedAsyncHTTPTransport` routing all HTTP traffic through the gate before transmission.
  - Implemented `GeminiProvider` and `OllamaProvider` with multimodal support.
  - Live model smoke test (`scripts/llm_smoke.py`) queried Gemini API, selected `gemini-3.5-flash`, and executed a live completion on sanitized `checkout.html` answering `btn-place-order` with gate enforced.
- **Leakage Evaluation Benchmark (`eval/run_leakage_eval.py`)**:
  - Mock LLM server recording raw request bytes.
  - Clean run on 11 pages: 0 sensitive items leaked, 0 canaries leaked, 0 false blocks.
  - Adversarial positive control across 106 items * 9 classes: 97.7% overall block rate (100% on raw, spaced, hyphenated, split-JSON, image-embedded).
  - Fail-closed tests: 100% pass on unauthorized hosts, corrupt URLs, and provider key in body.
- **Security Architecture Documentation (`docs/SECURITY.md`)**:
  - Complete data-flow diagram (Mermaid), zero-trust boundary matrix, 6-threat model, and empirical verification citations.

## In progress
- Agent execution loop and action approval gate.

## Next
- Interactive agent action execution with policy approval gates.
- Multi-step task execution on sanitized web applications.

## Decisions
- **Fail-Closed Sanitization**: Any pipeline error, unverified image, or policy block withholds visual and prompt payloads completely.
- **Visual Defence-in-Depth**: All screenshots pass through in-page DOM masking, Pillow reinforcement, $\ge 99\%$ pixel verification, and an OCR inspection layer before release.
- **Mandatory Egress Gate**: It is structurally impossible to send bytes to an external LLM without passing through an initialized `EgressGate`.
- **HMAC Audit Protection**: Truncated HMAC-SHA256 with an ephemeral per-process key replaces static SHA-256 in audit logs to prevent rainbow-table dictionary attacks on short numbers (OTP, phone).

## Measured results
- **Sanitization Pipeline Benchmark (All 11 Dev + Holdout Pages)**:
  - **Text Leakage Count:** **0** (0 sensitive values in prompt or JSON outputs across all 11 pages).
  - **Canary Leakage Count:** **0** (0 canary markers leaked).
  - **Pixel Mask Rate:** **100.0%** (100% of sensitive regions masked).
  - **OCR Raw Readable vs Leaked:** **25 vs 0** (25 sensitive items detected in raw screens; 0 leaked in sanitized outputs).
  - **Blocked Pages under Default Profile:** **0 / 11** (100% usable views).
- **Detection Benchmark (Dev & Holdout)**:
  - **Dev Set Detection**: Precision **96.3%**, Recall **100.0%**, Canaries **5/5**.
  - **Holdout Set Detection**: Precision **88.5%**, Recall **92.0%**, Canaries **5/5**, Decoy FP = **0**.
- **Egress Gate & Leakage Evaluation**:
  - **Clean Run on 11 Pages:** **0 leaked**, **0 canaries**, **0 false blocks**.
  - **Adversarial Block Rate (Positive Control):** **97.7%** (931 / 954 blocked across 106 sensitive items and 9 obfuscation classes).
  - **Raw / Spaced / Hyphenated / Split-JSON / Image-Embedded Block Rate:** **100.0%**.
  - **Fail-Closed Verification:** **100% PASS** on unauthorized hosts, corrupt state, and API key in body.
- **Unit Test Coverage**: 60 fast unit tests passing in < 6s.
- **Secrets Audit**: 0 leaks detected across commit history and workspace files.

## Known issues
- Windows standard sandbox restricts loopback TCP `socket.socketpair()`; subprocess server commands and Playwright sessions run using explicit local bindings.

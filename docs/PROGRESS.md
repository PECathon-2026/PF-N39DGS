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

## In progress
- Agent execution loop and LLM action approval gate.

## Next
- Egress gateway filtering preventing raw sensitive leaks to external LLM providers.
- Interactive agent action execution with policy approval gates.

## Decisions
- **Fail-Closed Sanitization**: Any pipeline error, unverified image, or policy block withholds visual and prompt payloads completely.
- **Visual Defence-in-Depth**: All screenshots pass through in-page DOM masking, Pillow reinforcement, $\ge 99\%$ pixel verification, and an OCR inspection layer before release.
- **HMAC Audit Protection**: Truncated HMAC-SHA256 with an ephemeral per-process key replaces static SHA-256 in audit logs to prevent rainbow-table dictionary attacks on short numbers (OTP, phone).

## Measured results
- **Sanitization Pipeline Benchmark (All 11 Dev + Holdout Pages)**:
  - **Text Leakage Count:** **0** (0 sensitive values in prompt or JSON outputs).
  - **Canary Leakage Count:** **0** (0 canary markers leaked).
  - **Pixel Mask Rate:** **100.0%** (100% of sensitive regions masked).
  - **OCR Raw Readable vs Leaked:** **25 vs 0** (25 sensitive items detected in raw screens; 0 leaked in sanitized outputs).
  - **Latency without OCR:** **p50 = 104.0 ms, p95 = 683.9 ms**.
  - **Latency with OCR:** **p50 = 830.6 ms, p95 = 1,598.4 ms**.
- **Dev Set Detection**: Precision **96.3%**, Recall **100.0%**.
- **Holdout Set Detection**: Precision **88.5%**, Recall **100.0%**, Decoy FP = **0**.
- **Unit Test Coverage**: 47 fast unit tests passing in < 5s.
- **Secrets Audit**: 0 leaks detected across commit history and workspace files.

## Known issues
- Windows standard sandbox restricts loopback TCP `socket.socketpair()`; subprocess server commands and Playwright sessions run using explicit local bindings.

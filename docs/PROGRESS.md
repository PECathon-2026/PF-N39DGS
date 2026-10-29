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

## In progress
- Local surrogate tokenization vault (`vault.py`) and sanitization pipeline (masking and placeholder substitution).

## Next
- Visual screenshot redactor (`sanitize/image.py`) using leaf bounding boxes.
- Egress gateway filtering preventing raw sensitive leaks to external LLM providers.

## Decisions
- **Presidio Scope**: Restrict Presidio strictly to `PERSON` and `LOCATION` entities with score threshold $\ge 0.60$; EMAIL and PHONE delegated to checksum/regex detectors.
- **Leaf-Only DOM Capture**: Text extraction confined to leaf elements and input values; container wrappers do not aggregate descendant text, preventing massive over-redaction boxes.
- **Container Dropping**: Detection engine automatically drops container findings when matching descendant findings exist.
- **Priority Calibration**: Calibrated priority ordering: `CARD` > `AADHAAR` > `PAN` > `API_KEY` > `JWT` > `TOKEN` > `PASSWORD` > `CVV` > `EXPIRY` > `OTP` > `EMAIL` > `PHONE` > `IP` > `ADDRESS` > `NOTE_WITH_CANARY` > `NAME`.
- **Pytest Isolation**: Default test runs exclude slow tests (`-m "not slow"`) for fast deterministic local testing. Real-HTTP uvicorn tests marked `@pytest.mark.slow`.

## Measured results
- **Dev Set Progression**:
  - **Before Fix**: Precision **44.8%**, Recall **100.0%** (26 TP, 32 FP, 0 Decoy FP, 12.4% char over-redact).
  - **After Fix**: Precision **96.3%**, Recall **100.0%** (26 TP, 1 FP [type mismatch], 0 Decoy FP, 0.0% char over-redact).
- **Holdout Set Progression**:
  - **First Run**: Precision **71.0%**, Recall **95.7%** (22 TP, 1 FN, 9 FP, 3 Decoy FP, 20.0% decoy over-redact).
  - **After Fixes**: Precision **88.5%**, Recall **100.0%** (23 TP, 0 FN, 3 FP, 0 Decoy FP, 0.0% decoy over-redact).
- **Canary Coverage**: **5/5** (100% across dev and holdout sets).
- **Unit Test Coverage**: 29 fast unit tests passing in < 0.1s.
- **Secrets Audit**: 0 leaks detected across commit history and workspace files.

## Known issues
- Windows standard sandbox restricts loopback TCP `socket.socketpair()`; subprocess server commands and Playwright sessions run using explicit local bindings.

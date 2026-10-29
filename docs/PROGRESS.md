# PrivacyLens Engineering Progress

## Done
- **Repository Scaffold & Packaging**: Virtual environment configured with Python 3.13, dependencies installed, `pyproject.toml` packaging privacylens v0.1.0 in editable mode.
- **Data Models (`models.py`)**: Immutable `Finding`, `SanitizedResult`, and `Action` models with strict typing and schema validation.
- **Checksums Engine & Verification (`detect/checksums.py`)**: Full Verhoeff, Luhn, and PAN checksum implementations with seedable synthetic Aadhaar and Card generators; 100% agreement against independent Group D5 mathematical reference model.
- **Audit Logging (`gateway/audit.py`)**: Privacy-preserving audit logging writing JSONL with entity types, counts, and SHA-256 prefixes; rejects raw values with zero leak guarantee.
- **Policy Engine (`policy/`)**: Loaded `default_policy.yaml` governing mask/block/allow actions and human approval rules.
- **Synthetic Test Site (`testsite/`)**: 5 realistic web pages (`checkout.html`, `login.html`, `support.html`, `meeting.html`, `devsettings.html`) with interactive IDs, non-sensitive context, decoys, and embedded canaries.
- **Automated Safety Checks (`scripts/check_secrets.py`, `check.ps1`, `backup.ps1`)**:
  - `check_secrets.py`: Verifies `.env` is untracked and git-ignored, scans commit history and files for exposed credentials without leaking values.
  - `check.ps1`: Automated test suite runner verifying secrets, Ruff linter, Pytest unit tests, and Playwright browser smoke test.
  - `backup.ps1`: Guarded multi-remote backup pushing to `origin main` and `hackathon main:aaditya-privacylens`.
- **Remote Integration**: Configured and fetched `hackathon` remote (`https://github.com/PECathon-2026/PF-N39DGS.git`).
- **DOM & Visual Screen Capture (`capture.py`)**: Implemented `PageSnapshot` and `capture()` retrieving interactive element metadata, full-page screenshots, and text node range bounding boxes.
- **Detection Engine (`detect/`)**:
  - `patterns.py`: Regular expressions with checksum validation for AADHAAR, PAN, CARD, EMAIL, PHONE, API_KEY, JWT, TOKEN, IP, OTP, CVV, CANARY.
  - `structural.py`: DOM semantic rules for password inputs, autocomplete attributes, keyword hints, and avatar faces.
  - `presidio_detector.py`: Lazy-loaded Presidio AnalyzerEngine singleton initialized with `en_core_web_sm` for PERSON and LOCATION detection.
  - `engine.py`: Coordinated `DetectionEngine` resolving same-type overlapping spans and cross-type conflicts via priority hierarchy.
- **Evaluation Benchmark (`eval/run_eval.py`)**:
  - Automated evaluation harness computing precision, recall, decoy false-positive count, canary coverage, latency, and full detector ablations.
  - Generates `eval/results/latest.json` and `docs/EVAL_RESULTS.md`.

## In progress
- Preparation for local tokenization vault and sanitization pipeline (masking and placeholder substitution).

## Next
- Local surrogate vault (`vault.py`) integration and token substitution in text and visual screenshots.
- Egress gateway filtering preventing raw sensitive leaks to external LLM providers.

## Decisions
- **Presidio Configuration**: Presidio `AnalyzerEngine` initialized explicitly with `NlpEngineProvider` specifying `en_core_web_sm` to avoid large background model downloads.
- **OCR Engine**: Tesseract executable bound dynamically via `pytesseract.pytesseract.tesseract_cmd` from `config.yaml` (`C:\Program Files\Tesseract-OCR\tesseract.exe`).
- **Browser Channel**: Configurable `browser_channel` (`chromium`, `msedge`, `chrome`; default: `chromium`) utilized across all Playwright sessions.
- **Pytest Isolation**: Default test runs exclude slow tests (`-m "not slow"`) to guarantee instantaneous, deterministic, network-free local testing. Real-HTTP uvicorn tests are marked `@pytest.mark.slow`.

## Measured results
- **Detection Accuracy**:
  - **Overall Recall:** **100.0%** (26/26 sensitive items detected).
  - **Canary Coverage:** **5/5** (100% of canary markers detected).
  - **Decoy False Positives:** **0** (Zero decoys incorrectly flagged).
  - **Overall Precision:** **44.8%** across multi-modal combinations.
- **Unit Test Coverage**: 24 fast unit tests passing in < 0.1s.
- **Checksum Integrity**: 100% agreement on 10,000 random strings, 1,000 Aadhaar numbers, and group D5 perturbation vectors.
- **Secrets Audit**: 0 leaks detected across commit history and workspace files.

## Known issues
- Windows standard sandbox restricts loopback TCP `socket.socketpair()`; subprocess server commands and Playwright sessions run using explicit local bindings.

# PrivacyLens Engineering Progress

## Done
- **Repository Scaffold & Packaging**: Virtual environment configured with Python 3.13, dependencies installed, `pyproject.toml` packaging privacylens v0.1.0 in editable mode.
- **Data Models (`models.py`)**: Defined immutable `Finding`, `SanitizedResult`, and `Action` models with strict typing and schema validation.
- **Checksums Engine (`detect/checksums.py`)**: Full Verhoeff, Luhn, and PAN checksum implementations with seedable synthetic Aadhaar and Card generators; mathematically validated against Group D5 spec.
- **Audit Logging (`gateway/audit.py`)**: Privacy-preserving audit logging writing JSONL with entity types, counts, and SHA-256 prefixes; rejects raw values with zero leak guarantee.
- **Policy Engine (`policy/`)**: Loaded `default_policy.yaml` governing mask/block/allow actions and human approval rules.
- **Synthetic Test Site (`testsite/`)**: 5 realistic web pages (`checkout.html`, `login.html`, `support.html`, `meeting.html`, `devsettings.html`) with interactive IDs, non-sensitive context, decoys, and embedded canaries.
- **Evaluation Dataset (`eval/ground_truth.json`)**: Ground truth map detailing 26 sensitive items and 18 decoys across 5 pages with 5 unique canaries.
- **Screen Capture Verification**: Playwright headless captured full screenshots for all 5 pages to `eval/screens/`.
- **Automated Safety Checks (`scripts/check_secrets.py`, `check.ps1`, `backup.ps1`)**: Integrated git-ignore checks, in-process secret leak detection, Ruff linting, Pytest, and smoke testing.
- **Remote Integration**: Added team remote `hackathon` (`https://github.com/PECathon-2026/PF-N39DGS.git`).

## In progress
- **Part B: Local Detection Engine**: Implementing `PageSnapshot` in `capture.py`, comprehensive regex patterns in `detect/patterns.py`, DOM heuristic rules in `detect/structural.py`, Presidio NLP integration in `detect/presidio_detector.py`, and multi-detector orchestration in `detect/engine.py`.

## Next
- Complete ablation and evaluation benchmark run via `eval/run_eval.py` writing `eval/results/latest.json` and `docs/EVAL_RESULTS.md`.
- Run `check.ps1` and `backup.ps1`.

## Decisions
- **OCR Engine**: Tesseract executable bound dynamically via `pytesseract.pytesseract.tesseract_cmd` from `config.yaml` (`C:\Program Files\Tesseract-OCR\tesseract.exe`).
- **Browser Channel**: Configurable `browser_channel` (`chromium`, `msedge`, `chrome`; default: `chromium`) utilized across all Playwright sessions.
- **Pytest Isolation**: Default test runs exclude slow tests (`-m "not slow"`) to guarantee instantaneous, deterministic, network-free local testing. Real-HTTP uvicorn tests are marked `@pytest.mark.slow`.

## Measured results
- **Unit Test Coverage**: 10 fast unit tests passing in < 0.1s.
- **Checksum Integrity**: 100% agreement on 10,000 random strings, 1,000 Aadhaar numbers, and group D5 perturbation vectors.
- **Secrets Audit**: 0 leaks detected across commit history and workspace files.

## Known issues
- Windows standard sandbox restricts loopback TCP `socket.socketpair()`; subprocess server commands and Playwright sessions run using explicit local bindings.

"""Unit tests verifying single source of truth for DOM capture JS."""

from pathlib import Path


def test_capture_dom_js_files_identical() -> None:
    """Verify privacylens/js/capture_dom.js and extension/capture_dom.js are byte-identical."""
    src = Path("privacylens/js/capture_dom.js")
    dst = Path("extension/capture_dom.js")

    assert src.exists(), "Source JS file privacylens/js/capture_dom.js must exist"
    assert dst.exists(), "Extension JS file extension/capture_dom.js must exist"

    src_content = src.read_text(encoding="utf-8").strip()
    dst_content = dst.read_text(encoding="utf-8").strip()

    assert src_content == dst_content, (
        "extension/capture_dom.js is out of sync with privacylens/js/capture_dom.js! "
        "Run scripts/sync_extension.ps1 to synchronize."
    )

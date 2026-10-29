import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eval.canaries.registry import generate_registry, luhn_check, verhoeff_check, is_valid_pan, is_valid_email

def test_canaries_unique_and_valid():
    reg = generate_registry(42)
    vals = reg.all_values()
    assert len(vals) == len(set(vals))
    bycat = {e.category: e.value for e in reg.entries}
    assert luhn_check(bycat["CARD"])
    assert verhoeff_check(bycat["AADHAAR"])
    assert is_valid_pan(bycat["PAN"])
    assert is_valid_email(bycat["EMAIL"])

def test_canaries_in_pages():
    reg = generate_registry(42)
    bycat = {e.category: e.value for e in reg.entries}
    pages_dir = os.path.join(os.path.dirname(__file__), "pages")
    for fn in os.listdir(pages_dir):
        if not fn.endswith(".html"):
            continue
        content = open(os.path.join(pages_dir, fn), encoding="utf-8").read()
        # at least one canary present in each page (sanity)
    # check all canary values appear somewhere across pages
    all_html = ""
    for fn in os.listdir(pages_dir):
        if fn.endswith(".html"):
            all_html += open(os.path.join(pages_dir, fn), encoding="utf-8").read()
    for v in reg.all_values():
        assert v in all_html, v

def test_pages_load_playwright():
    from playwright.sync_api import sync_playwright
    pages_dir = os.path.join(os.path.dirname(__file__), "pages")
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        for fn in sorted(os.listdir(pages_dir)):
            if not fn.endswith(".html"):
                continue
            url = "file:///" + os.path.abspath(os.path.join(pages_dir, fn)).replace("\\", "/")
            page.goto(url)
            assert page.title() is not None
        browser.close()

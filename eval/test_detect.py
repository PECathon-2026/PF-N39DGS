import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.detect.regex_layer import scan_text
from eval.canaries.registry import generate_registry

def test_negative_invalid_checksum():
    from eval.canaries.registry import verhoeff_check, luhn_check
    assert not verhoeff_check("123456789012")
    assert not luhn_check("4111111111111112")

def test_recall_per_category():
    reg = generate_registry(42)
    bycat = {e.category: e.value for e in reg.entries}
    # build a text blob of all canaries
    text = " ".join(bycat.values())
    findings = scan_text(text)
    cats = {f.category for f in findings}
    # print table
    print("\nCategory | detected")
    for c in bycat:
        print(c, c in cats)
    assert "CARD" in cats and "EMAIL" in cats and "IP" in cats

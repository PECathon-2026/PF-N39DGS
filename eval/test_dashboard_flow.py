import os
import sys
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from dashboard.main import app, _state

def test_full_dashboard_flow():
    client = TestClient(app)

    pages_dir = os.path.join(os.path.abspath("."), "eval", "pages")
    scen_1_path = os.path.abspath(os.path.join(pages_dir, "scenario_1_ecommerce.html")).replace("\\", "/")
    url = f"file:///{scen_1_path}"

    print(f"Starting task on {url}...")
    res = client.post("/task", json={"url": url, "task": "Add item to cart and proceed to checkout", "max_steps": 5})
    assert res.status_code == 200

    pending_found = False
    for i in range(80):
        time.sleep(0.5)
        s = client.get("/status").json()
        stage = s.get("stage")
        if s.get("pending_action"):
            print(f"[{i*0.5}s] Pending action found: {s['pending_action']}")
            pending_found = True
            
            # Check preview during validation
            prev = client.get("/preview").json()
            assert prev.get("sanitized_text") is not None
            print(f"Preview during validation: {len(prev['sanitized_text'])} chars, {len(prev.get('redactions', []))} redactions")

            # Approve
            app_res = client.post("/approve").json()
            print("Approve response:", app_res)
            break

    assert pending_found, "Expected pending action to be triggered"

    # Wait for completion
    completed = False
    for i in range(120):
        time.sleep(0.5)
        s = client.get("/status").json()
        stage = s.get("stage")
        if i % 5 == 0:
            print(f"[{i*0.5}s after approval] stage={stage}, pending={s.get('pending_action') is not None}, error={s.get('error')}")
        if stage in ("DONE", "ERROR", "BLOCKED"):
            print(f"[{i*0.5}s after approval] Final stage: {stage}")
            print("Steps count:", s.get("step"))
            print("Last action:", s.get("last_action"))
            print("Error:", s.get("error"))
            assert stage == "DONE", f"Task failed with stage {stage}: {s.get('error')}"
            completed = True
            break

    assert completed, "Task did not complete within timeout"

    # Verify preview is accessible and sanitized
    final_prev = client.get("/preview").json()
    assert final_prev.get("sanitized_text") is not None
    assert len(final_prev.get("redactions", [])) > 0
    print(f"Final preview verified with {len(final_prev['redactions'])} redactions")

    # Verify blocked payload banner trigger
    from dashboard.main import _safe_state_update
    _safe_state_update({
        "stage": "BLOCKED",
        "last_guard_categories": {"CARD": 1, "EMAIL": 1},
        "blocked_events": [{"event_id": "blk_999", "reason": "Sensitive data detected: CARD(1), EMAIL(1)", "category_counts": {"CARD": 1, "EMAIL": 1}}],
    })
    s_blocked = client.get("/status").json()
    assert s_blocked["blocked"] is True
    assert "CARD" in s_blocked["blocked_categories"]
    print("Blocked banner trigger verified in /status response")
    print("ALL GATE TESTS PASSED!")

if __name__ == "__main__":
    test_full_dashboard_flow()

"""Smoke test for the new /next_step multi-step extension flow.

Tests:
1. /next_step rejects when no task is running (stage=IDLE)
2. /next_step rejects when ext_dom_snapshot is missing
3. /next_step returns done immediately when max_steps reached
4. step counter advances correctly across /task → /next_step
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from dashboard.main import app, _safe_state_update, _state


def _make_minimal_snapshot(url="http://localhost/test", elements=None):
    """Build a minimal ext_dom_snapshot for testing."""
    return {
        "url": url,
        "title": "Test Page",
        "text": "Username: Enter your email. Password: Enter your password. Login button.",
        "elements": elements or [
            {
                "el_id": "el_0",
                "tag": "input",
                "type": "email",
                "name": "username",
                "id": "username",
                "placeholder": "Email address",
                "value": "",
                "text": "",
                "aria_label": None,
                "autocomplete": "email",
                "box": {"x": 10, "y": 10, "w": 200, "h": 40},
            },
            {
                "el_id": "el_1",
                "tag": "input",
                "type": "password",
                "name": "password",
                "id": "password",
                "placeholder": "Password",
                "value": "",
                "text": "",
                "aria_label": None,
                "autocomplete": "current-password",
                "box": {"x": 10, "y": 60, "w": 200, "h": 40},
            },
            {
                "el_id": "el_2",
                "tag": "button",
                "type": "submit",
                "name": None,
                "id": "login-btn",
                "placeholder": None,
                "value": "",
                "text": "Login",
                "aria_label": None,
                "autocomplete": None,
                "box": {"x": 10, "y": 110, "w": 100, "h": 40},
            },
        ],
        "dpr": 1,
    }


# Minimal 1x1 transparent PNG in base64
_BLANK_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
    "YPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)


def test_next_step_rejected_when_idle():
    """POST /next_step must be rejected if no task is running."""
    client = TestClient(app)
    _safe_state_update({"stage": "IDLE", "task": "", "step": 0, "next_action": None})

    resp = client.post("/next_step", json={
        "ext_dom_snapshot": _make_minimal_snapshot(),
        "ext_screenshot_b64": _BLANK_PNG_B64,
    })
    assert resp.status_code == 409, f"Expected 409 but got {resp.status_code}: {resp.json()}"
    assert "No active task" in resp.json()["error"]


def test_next_step_requires_snapshot():
    """POST /next_step must return 422 if snapshot fields are missing."""
    _safe_state_update({"stage": "EXECUTE", "task": "login", "step": 1, "max_steps": 5})
    client = TestClient(app)
    resp = client.post("/next_step", json={"ext_dom_snapshot": None, "ext_screenshot_b64": None})
    assert resp.status_code == 422


def test_next_step_done_when_max_steps_reached():
    """POST /next_step returns done immediately if step >= max_steps."""
    _safe_state_update({
        "stage": "EXECUTE",
        "task": "login",
        "step": 5,
        "max_steps": 5,
        "next_action": None,
    })
    client = TestClient(app)
    resp = client.post("/next_step", json={
        "ext_dom_snapshot": _make_minimal_snapshot(),
        "ext_screenshot_b64": _BLANK_PNG_B64,
    })
    data = resp.json()
    assert resp.status_code == 200
    assert data.get("status") == "done"


def test_next_step_continues_step_counter():
    """step counter in _state increments across /task and /next_step calls."""
    client = TestClient(app)

    pages_dir = os.path.join(os.path.abspath("."), "eval", "pages")
    auth_path = os.path.abspath(os.path.join(pages_dir, "scenario_2_auth.html")).replace("\\", "/")
    url = f"file:///{auth_path}"
    snap = _make_minimal_snapshot(url=url)

    # Reset state fully to IDLE before starting (previous tests may leave it in BLOCKED/DONE)
    _safe_state_update({
        "stage": "IDLE", "task": "", "url": "", "step": 0, "max_steps": 5,
        "steps_results": [], "preview": None, "error": None,
        "blocked_events": [], "last_guard_passed": None, "last_guard_categories": {},
        "pending_action": None, "next_action": None, "approval_event": None, "approval_result": None,
    })

    # Step 0: start via /task with extension snapshot
    res = client.post("/task", json={
        "url": url,
        "task": "Login with auth credentials",
        "max_steps": 5,
        "ext_dom_snapshot": snap,
        "ext_screenshot_b64": _BLANK_PNG_B64,
    })
    assert res.status_code == 200, f"Task start failed: {res.json()}"

    # Wait for pipeline to produce step 0 result (extended timeout for OCR/model)
    terminal = False
    for _ in range(60):
        time.sleep(0.5)
        s = client.get("/status").json()
        if s.get("stage") in ("EXECUTE", "DONE", "ERROR", "BLOCKED"):
            terminal = True
            break

    assert terminal, f"Pipeline did not reach a terminal stage: {client.get('/status').json()}"

    step_after_0 = client.get("/status").json().get("step", 0)
    assert step_after_0 >= 1, f"Step should be >= 1 after /task, got {step_after_0}"

    # Simulate approved action from extension
    client.post("/action_done", json={"success": True, "message": "Typed email"})

    # Force stage to EXECUTE so /next_step is accepted
    _safe_state_update({"stage": "EXECUTE"})

    # Step 1: continue via /next_step
    res2 = client.post("/next_step", json={
        "ext_dom_snapshot": snap,
        "ext_screenshot_b64": _BLANK_PNG_B64,
    })
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2.get("status") == "processing", f"Expected 'processing', got: {data2}"

    # Wait for pipeline step 1 to complete
    terminal2 = False
    for _ in range(60):
        time.sleep(0.5)
        s2 = client.get("/status").json()
        if s2.get("stage") in ("EXECUTE", "DONE", "ERROR", "BLOCKED"):
            terminal2 = True
            break

    assert terminal2, f"Pipeline step 1 did not reach terminal stage: {client.get('/status').json()}"

    step_after_1 = client.get("/status").json().get("step", 0)
    assert step_after_1 >= 2, f"Step should be >= 2 after /next_step, got {step_after_1}"


if __name__ == "__main__":
    test_next_step_rejected_when_idle()
    print("test_next_step_rejected_when_idle PASSED")
    test_next_step_requires_snapshot()
    print("test_next_step_requires_snapshot PASSED")
    test_next_step_done_when_max_steps_reached()
    print("test_next_step_done_when_max_steps_reached PASSED")
    test_next_step_continues_step_counter()
    print("test_next_step_continues_step_counter PASSED")
    print("\nAll /next_step tests passed!")

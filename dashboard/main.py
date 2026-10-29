"""PrivacyLens Dashboard — FastAPI + Jinja2 app (Stage 9).

Security invariants (non-negotiable):
  - No endpoint returns raw sensitive values.
  - /preview returns ONLY sanitized text + metadata (category, layer, confidence).
  - Blocked events contain only category_counts and reason — never raw values.
  - Approval modal exposes only sanitized action metadata (action_type, target, thought).
  - The only path to the external model is core.agent.client.send_to_model().
"""
from __future__ import annotations

import base64
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure repo root is on sys.path so core.* imports work when uvicorn is run
# from the project root directory.
_REPO_ROOT = Path(__file__).parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader

# ---------------------------------------------------------------------------
# App init
# ---------------------------------------------------------------------------
app = FastAPI(title="PrivacyLens Dashboard", version="1.0.0")

_DASHBOARD_DIR = Path(__file__).parent
_STATIC_DIR = _DASHBOARD_DIR / "static"
_TEMPLATES_DIR = _DASHBOARD_DIR / "templates"

app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

# Workaround: Jinja2 3.1.6 + Starlette 1.3.1 LRUCache compat issue — use raw Jinja2 env
_jinja_env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=True)

# ---------------------------------------------------------------------------
# In-memory state — single source of truth for the running agent task.
# INVARIANT: This dict MUST NOT contain raw sensitive values at any time.
# ---------------------------------------------------------------------------
_state: Dict[str, Any] = {
    "stage": "IDLE",            # IDLE|CAPTURE|DETECT|SANITIZE|GUARD|MODEL|VALIDATE|EXECUTE|DONE|BLOCKED|ERROR
    "task": "",
    "url": "",
    "step": 0,
    "max_steps": 5,
    "steps_results": [],        # list of step result dicts (sanitized metadata only)
    "preview": None,            # dict: sanitized_text, masked_image_b64, redactions[]
    "last_guard_passed": None,  # bool
    "last_guard_categories": {},
    "blocked_events": [],       # from guard (category_counts + reason only)
    "pending_action": None,     # sanitized Action dict awaiting human approval
    "approval_event": None,     # threading.Event
    "approval_result": None,    # bool
    "eval_running": False,
    "eval_results": None,       # last eval JSON report
    "error": None,
}

_state_lock = threading.Lock()


def _safe_state_update(updates: Dict[str, Any]) -> None:
    """Thread-safe update of _state."""
    with _state_lock:
        _state.update(updates)


# ---------------------------------------------------------------------------
# Background task: run agent loop
# ---------------------------------------------------------------------------

def _render_snap(san_snap: Dict[str, Any]) -> str:
    """Render sanitized snapshot to string for preview. Never includes raw values."""
    try:
        from core.sanitize import render_sanitized_view
        return render_sanitized_view(san_snap)
    except Exception:
        parts = []
        for el in san_snap.get("elements", []):
            txt = el.get("text", "")
            if txt:
                parts.append(str(txt))
        pg_text = san_snap.get("text", "")
        if pg_text:
            parts.append(str(pg_text))
        return "\n".join(parts)


def _extract_redactions_from_text(sanitized_text: str) -> List[Dict[str, Any]]:
    """Extract redaction metadata from sanitized text placeholders.
    Returns list of {category, layer, confidence} — NEVER raw values.
    """
    import re
    redactions = []
    for m in re.finditer(r"\[REDACTED:([A-Z_]+)\]", sanitized_text):
        redactions.append({
            "category": m.group(1),
            "layer": "fusion",
            "confidence": 0.95,
        })
    return redactions


def _run_task_background(url: str, task: str, max_steps: int) -> None:
    """Background thread: runs the full agent loop and updates _state."""
    _safe_state_update({
        "stage": "CAPTURE",
        "url": url,
        "task": task,
        "max_steps": max_steps,
        "step": 0,
        "steps_results": [],
        "preview": None,
        "error": None,
        "blocked_events": [],
        "last_guard_passed": None,
        "last_guard_categories": {},
        "pending_action": None,
        "approval_event": None,
        "approval_result": None,
    })

    preview_store: Dict[str, Any] = {}

    def approval_cb(action: Any, san_snap: Dict[str, Any]) -> bool:
        """Called by run_agent_loop when a high-risk action needs human approval.

        INVARIANT: Only sanitized metadata is stored — action.thought may
        reference [REDACTED:X] placeholders but never raw values, as the
        sanitized snapshot has already been processed by this point.
        """
        # Store sanitized preview snapshot at this point
        san_text = _render_snap(san_snap)
        redactions = _extract_redactions_from_text(san_text)

        # Extract masked image b64 if present (already masked by pipeline)
        masked_b64: Optional[str] = None
        raw_b64 = san_snap.get("screenshot_b64")
        if raw_b64:
            # The screenshot in san_snap is still the original; we cannot
            # access masked bytes here without storing them separately.
            # We omit image in approval callback preview — the full preview
            # is populated after loop completion.
            masked_b64 = None

        preview_store.update({
            "sanitized_text": san_text,
            "masked_image_b64": masked_b64,
            "redactions": redactions,
        })

        # Sanitized action dict for the UI (NEVER includes raw values)
        safe_action = {
            "action_type": action.action_type,
            "target": action.target,
            "thought": action.thought,   # Already sanitized by pipeline
            "risk_level": action.risk_level,
        }

        ev = threading.Event()
        _safe_state_update({
            "stage": "VALIDATE",
            "pending_action": safe_action,
            "approval_event": ev,
            "approval_result": None,
            "preview": dict(preview_store),
        })

        # Wait up to 5 minutes for human response
        ev.wait(timeout=300)

        result = _state.get("approval_result", False)
        _safe_state_update({
            "pending_action": None,
            "approval_event": None,
        })
        return bool(result)

    def on_step(step_idx: int, san_snap: Dict[str, Any], masked_bytes: bytes) -> None:
        san_text = _render_snap(san_snap)
        redactions = _extract_redactions_from_text(san_text)
        masked_b64 = base64.b64encode(masked_bytes).decode("ascii") if masked_bytes else None

        preview_store.update({
            "sanitized_text": san_text,
            "masked_image_b64": masked_b64,
            "redactions": redactions,
        })
        _safe_state_update({
            "step": step_idx + 1,
            "preview": dict(preview_store),
        })

    try:
        from core.agent.client import EgressBlockedError, run_agent_loop
        from core.egress.guard import get_blocked_events

        _safe_state_update({"stage": "EXECUTE"})
        exec_results = run_agent_loop(
            url, task, max_steps=max_steps, approval_callback=approval_cb, on_step_callback=on_step
        )

        # Convert results to safe dicts (no raw values)
        steps_dicts = [r.to_dict() for r in exec_results]

        # Build last-action description from final result
        last_step = steps_dicts[-1] if steps_dicts else {}
        last_action = last_step.get("message", "")

        _safe_state_update({
            "stage": "DONE",
            "steps_results": steps_dicts,
            "step": len(steps_dicts),
            "last_guard_passed": True,
            "preview": preview_store if preview_store else _state.get("preview"),
        })

    except Exception as exc:
        from core.agent.client import EgressBlockedError
        from core.egress.guard import get_blocked_events

        if isinstance(exc, EgressBlockedError):
            blocked_evts = get_blocked_events()
            _safe_state_update({
                "stage": "BLOCKED",
                "blocked_events": blocked_evts,          # category_counts + reason only
                "last_guard_passed": False,
                "last_guard_categories": exc.category_counts,
                "error": None,
            })
        else:
            _safe_state_update({
                "stage": "ERROR",
                "error": type(exc).__name__,
                "last_guard_passed": None,
            })


def _run_eval_background() -> None:
    """Background thread: runs the full evaluation harness."""
    _safe_state_update({"eval_running": True})
    try:
        from eval.run_eval import run_full_evaluation
        report = run_full_evaluation()
        _safe_state_update({"eval_results": report, "eval_running": False})
    except Exception as exc:
        _safe_state_update({
            "eval_running": False,
            "eval_results": {"error": type(exc).__name__, "message": str(exc)},
        })


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Serve the single-page dashboard."""
    tmpl = _jinja_env.get_template("index.html")
    pages_dir = str((_REPO_ROOT / "eval" / "pages").resolve()).replace("\\", "/")
    html = tmpl.render(request=request, pages_dir=pages_dir)
    return HTMLResponse(content=html)


@app.get("/scenarios")
async def list_scenarios() -> JSONResponse:
    """Return list of benchmark scenarios with file URLs for easy 1-click loading."""
    pages_dir = str((_REPO_ROOT / "eval" / "pages").resolve()).replace("\\", "/")
    return JSONResponse([
        {"id": "scenario_1", "name": "🛒 E-Commerce Checkout", "url": f"file:///{pages_dir}/scenario_1_ecommerce.html", "task": "Add item to cart and proceed to checkout"},
        {"id": "scenario_2", "name": "🔐 Auth & Credentials", "url": f"file:///{pages_dir}/scenario_2_auth.html", "task": "Login with auth credentials"},
        {"id": "scenario_3", "name": "🎧 Support Ticket", "url": f"file:///{pages_dir}/scenario_3_support.html", "task": "Submit support ticket message"},
        {"id": "scenario_4", "name": "📹 Face & Video Call", "url": f"file:///{pages_dir}/scenario_4_video.html", "task": "Join video call conference"},
        {"id": "scenario_5", "name": "⚙️ Dev Settings & IP", "url": f"file:///{pages_dir}/scenario_5_devtools.html", "task": "Save dev settings and network config"},
        {"id": "adv_1", "name": "🕵️ Adversarial 1 (Hidden Text)", "url": f"file:///{pages_dir}/adversarial_1_hidden_text.html", "task": "Handle dialog with hidden text"},
        {"id": "adv_2", "name": "🛡️ Adversarial 2 (Prompt Injection)", "url": f"file:///{pages_dir}/adversarial_2_prompt_injection.html", "task": "Process form while resisting prompt injection"},
    ])


@app.post("/task")
async def start_task(
    request: Request,
    url: Optional[str] = Form(default=None),
    task: Optional[str] = Form(default=None),
    max_steps: Optional[int] = Form(default=None),
) -> JSONResponse:
    """Start a new agent task.

    Accepts either JSON body or HTML form data.
    """
    # If form data is empty, try JSON body
    if url is None and task is None:
        try:
            body = await request.json()
            url = body.get("url", "")
            task = body.get("task", "")
            max_steps = body.get("max_steps", 5)
        except Exception:
            return JSONResponse({"error": "Could not parse request body"}, status_code=400)

    url = (url or "").strip()
    task = (task or "").strip()
    if not url:
        return JSONResponse({"error": "url is required"}, status_code=422)
    if not task:
        return JSONResponse({"error": "task is required"}, status_code=422)

    max_steps = int(max_steps or 5)

    current_stage = _state.get("stage", "IDLE")
    if current_stage not in ("IDLE", "DONE", "BLOCKED", "ERROR"):
        return JSONResponse(
            {"error": f"Task already running (stage={current_stage})"},
            status_code=409,
        )

    t = threading.Thread(
        target=_run_task_background,
        args=(url, task, max_steps),
        daemon=True,
    )
    t.start()
    return JSONResponse({"status": "started", "url": url, "task": task})


@app.get("/status")
async def get_status() -> JSONResponse:
    """Poll current pipeline stage and latest metrics.

    INVARIANT: Response MUST NOT contain raw sensitive values.
    """
    with _state_lock:
        s = dict(_state)

    steps = s.get("steps_results", [])
    last_action = ""
    if steps:
        last_action = steps[-1].get("message", "")

    blocked_evts = s.get("blocked_events", [])
    # Strip any raw-value fields if somehow present (defence in depth)
    safe_blocked = [
        {
            "event_id": e.get("event_id", ""),
            "timestamp": e.get("timestamp", ""),
            "stage": e.get("stage", "EGRESS_GUARD"),
            "status": e.get("status", "BLOCKED"),
            "category_counts": e.get("category_counts", {}),
            "reason": e.get("reason", ""),
        }
        for e in blocked_evts
    ]

    return JSONResponse({
        "stage": s.get("stage", "IDLE"),
        "task": s.get("task", ""),
        "url": s.get("url", ""),
        "step": s.get("step", 0),
        "max_steps": s.get("max_steps", 5),
        "blocked": s.get("stage") == "BLOCKED",
        "blocked_categories": s.get("last_guard_categories", {}),
        "blocked_events": safe_blocked,
        "pending_action": s.get("pending_action"),   # sanitized metadata only
        "last_action": last_action,
        "guard_passed": s.get("last_guard_passed"),
        "eval_running": s.get("eval_running", False),
        "error": s.get("error"),
    })


@app.get("/preview")
async def get_preview() -> JSONResponse:
    """Return sanitized before/after payload for the dashboard.

    INVARIANT: Returns ONLY sanitized text/image + per-redaction metadata
    (category, layer, confidence). Raw original content is NEVER returned.
    """
    with _state_lock:
        preview = _state.get("preview")

    if preview is None:
        return JSONResponse({"sanitized_text": None, "masked_image_b64": None, "redactions": []})

    # Ensure we only return safe fields — strip any raw content defensively
    safe_preview = {
        "sanitized_text": preview.get("sanitized_text"),
        "masked_image_b64": preview.get("masked_image_b64"),  # Already masked by pipeline
        "redactions": [
            {
                "category": r.get("category", "UNKNOWN"),
                "layer": r.get("layer", "fusion"),
                "confidence": r.get("confidence", 0.9),
            }
            for r in (preview.get("redactions") or [])
        ],
    }
    return JSONResponse(safe_preview)


@app.post("/approve")
async def approve_action() -> JSONResponse:
    """Human approves a pending high-risk action."""
    with _state_lock:
        ev: Optional[threading.Event] = _state.get("approval_event")
        if ev is None:
            return JSONResponse({"error": "No pending action"}, status_code=400)
        _state["approval_result"] = True

    ev.set()
    return JSONResponse({"status": "approved"})


@app.post("/reject")
async def reject_action() -> JSONResponse:
    """Human rejects a pending high-risk action."""
    with _state_lock:
        ev: Optional[threading.Event] = _state.get("approval_event")
        if ev is None:
            return JSONResponse({"error": "No pending action"}, status_code=400)
        _state["approval_result"] = False

    ev.set()
    return JSONResponse({"status": "rejected"})


@app.post("/eval/run")
async def trigger_eval() -> JSONResponse:
    """Trigger the full evaluation harness in a background thread."""
    with _state_lock:
        if _state.get("eval_running"):
            return JSONResponse({"error": "Evaluation already running"}, status_code=409)

    t = threading.Thread(target=_run_eval_background, daemon=True)
    t.start()
    return JSONResponse({"status": "eval_started"})


@app.get("/eval/results")
async def eval_results() -> JSONResponse:
    """Fetch the last evaluation report (JSON)."""
    with _state_lock:
        results = _state.get("eval_results")
        running = _state.get("eval_running", False)

    if results is None:
        # Try to load from disk if available
        try:
            results_path = _REPO_ROOT / "eval" / "results.json"
            if results_path.exists():
                with open(results_path, encoding="utf-8") as f:
                    results = json.load(f)
        except Exception:
            results = None

    return JSONResponse({
        "running": running,
        "results": results,
    })

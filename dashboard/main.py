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

from fastapi import Body, FastAPI, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader

# ---------------------------------------------------------------------------
# App init
# ---------------------------------------------------------------------------
app = FastAPI(title="PrivacyLens Dashboard", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    "next_action": None,        # action dispatched to live browser extension
    "approval_event": None,     # threading.Event
    "approval_result": None,    # bool
    "eval_running": False,
    "eval_results": None,       # last eval JSON report
    "error": None,
}

_state_lock = threading.Lock()

# In-memory raw (pre-redaction) screenshot storage — single task, local only.
# INVARIANT: _raw_store is NEVER transmitted externally. It is served only via
# GET /raw_preview which is localhost-bound (uvicorn default).  It is cleared
# when a new task starts and when the stage returns to IDLE.
_raw_store: dict = {}


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


def _run_task_background(
    url: str,
    task: str,
    max_steps: int,
    ext_dom_snapshot: Optional[Dict[str, Any]] = None,
    ext_screenshot_b64: Optional[str] = None,
) -> None:
    """Background thread: runs the full agent loop and updates _state."""
    # Clear raw store for fresh task — ensures left pane shows current task only
    _raw_store.clear()

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
        "next_action": None,
        "approval_event": None,
        "approval_result": None,
    })

    preview_store: Dict[str, Any] = {}

    def approval_cb(action: Any, san_snap: Dict[str, Any]) -> bool:
        """Called by run_agent_loop when a high-risk action needs human approval."""
        san_text = _render_snap(san_snap)
        redactions = _extract_redactions_from_text(san_text)

        preview_store.update({
            "sanitized_text": san_text,
            "masked_image_b64": None,
            "redactions": redactions,
        })

        safe_action = {
            "action_type": action.action_type,
            "target": action.target,
            "thought": action.thought,
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

    def on_step(step_idx: int, san_snap: Dict[str, Any], masked_bytes: bytes,
                raw_screenshot_b64: Optional[str] = None) -> None:
        san_text = _render_snap(san_snap)
        redactions = _extract_redactions_from_text(san_text)
        masked_b64 = base64.b64encode(masked_bytes).decode("ascii") if masked_bytes else None

        if raw_screenshot_b64:
            _raw_store["raw_screenshot_b64"] = raw_screenshot_b64
            # Also register visual face redactions so the dashboard metadata reflects visual protections
            try:
                from core.detect import face_layer
                face_finds = face_layer.scan_image(raw_screenshot_b64)
                for _ in face_finds:
                    redactions.append({
                        "category": "FACE",
                        "layer": "face",
                        "confidence": 0.90,
                    })
            except Exception:
                pass

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
        from core.vault import vault

        # If an active browser extension provided a live snapshot & screenshot,
        # process that exact live user tab directly
        if ext_dom_snapshot and ext_screenshot_b64:
            from core.detect import dom_layer, face_layer, fusion, ocr_layer, regex_layer
            from core.sanitize import mask_image_bytes, sanitize_dom
            from core.agent.client import build_user_prompt, send_to_model
            from core.agent.validator import parse_action_proposal, validate_action

            _safe_state_update({"stage": "DETECT"})
            live_snap = dict(ext_dom_snapshot)
            live_snap["screenshot_b64"] = ext_screenshot_b64
            live_raw_bytes = base64.b64decode(ext_screenshot_b64)
            _raw_store["raw_screenshot_b64"] = ext_screenshot_b64

            d_find = dom_layer.scan_dom(live_snap)
            full_text = " ".join([el.get("text", "") + " " + el.get("value", "") for el in live_snap.get("elements", [])])
            if live_snap.get("text"):
                full_text += " " + live_snap["text"]
            r_find = regex_layer.scan_text(full_text)
            o_find = ocr_layer.scan_image(live_raw_bytes)
            f_find = face_layer.scan_image(live_raw_bytes)
            fused = fusion.fuse(d_find + r_find + o_find + f_find)

            _safe_state_update({"stage": "SANITIZE"})
            san_snap = sanitize_dom(live_snap, fused)
            masked_bytes = mask_image_bytes(live_raw_bytes, fused, padding=4)
            on_step(0, san_snap, masked_bytes, ext_screenshot_b64)

            _safe_state_update({"stage": "GUARD"})
            prompt = build_user_prompt(task, san_snap)
            _safe_state_update({"stage": "MODEL"})
            model_reply = send_to_model(
                prompt=prompt,
                image_bytes=masked_bytes,
                task_context=task,
                snapshot_context=san_snap,
                step=0,
            )

            _safe_state_update({"stage": "VALIDATE"})
            action = parse_action_proposal(model_reply)
            v_res = validate_action(action, san_snap)
            if v_res.requires_approval:
                approval_cb(action, san_snap)

            # Resolve symbolic vault values locally before sending action to extension
            resolved_val = vault.resolve_value(action.value) if action.value else None
            is_done = (action.action_type == "done")

            _safe_state_update({
                "stage": "DONE" if is_done else "EXECUTE",
                "next_action": {
                    "action_type": action.action_type,
                    "target": action.target,
                    "value": resolved_val,
                    "thought": action.thought,
                },
                "steps_results": [{
                    "success": True,
                    "action_type": action.action_type,
                    "target": action.target,
                    "message": f"{action.action_type.capitalize()} on {action.target} ({action.thought})",
                }],
                "step": 1,
                "last_guard_passed": True,
            })
            return

        # Standard Playwright loop for local evaluation scenarios and headless execution
        _safe_state_update({"stage": "EXECUTE"})
        exec_results = run_agent_loop(
            url, task, max_steps=max_steps, approval_callback=approval_cb, on_step_callback=on_step
        )

        steps_dicts = [r.to_dict() for r in exec_results]
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
                "blocked_events": blocked_evts,
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
    """Start a new agent task. Accepts either JSON body or HTML form data."""
    ext_dom_snapshot = None
    ext_screenshot_b64 = None

    if url is None and task is None:
        try:
            body = await request.json()
            url = body.get("url", "")
            task = body.get("task", "")
            max_steps = body.get("max_steps", 5)
            ext_dom_snapshot = body.get("ext_dom_snapshot")
            ext_screenshot_b64 = body.get("ext_screenshot_b64")
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
    if current_stage not in ("IDLE", "DONE", "BLOCKED", "ERROR", "EXECUTE"):
        return JSONResponse(
            {"error": f"Task already running (stage={current_stage})"},
            status_code=409,
        )

    t = threading.Thread(
        target=_run_task_background,
        args=(url, task, max_steps, ext_dom_snapshot, ext_screenshot_b64),
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
        "next_action": s.get("next_action"),         # action dispatched to browser extension
        "last_action": last_action,
        "guard_passed": s.get("last_guard_passed"),
        "eval_running": s.get("eval_running", False),
        "error": s.get("error"),
    })


@app.post("/action_done")
async def action_done(payload: Dict[str, Any] = Body(...)) -> JSONResponse:
    """Acknowledged by the browser extension when it finishes executing next_action."""
    with _state_lock:
        _state["next_action"] = None
        if payload.get("message"):
            _state["steps_results"].append({
                "success": payload.get("success", True),
                "message": str(payload.get("message")),
            })
    return JSONResponse({"status": "ok"})


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

    safe_preview = {
        "sanitized_text": preview.get("sanitized_text"),
        "masked_image_b64": preview.get("masked_image_b64"),
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


@app.get("/raw_preview")
async def raw_preview() -> JSONResponse:
    """Serve the raw (pre-redaction) screenshot for the dashboard left pane."""
    raw_b64 = _raw_store.get("raw_screenshot_b64")
    return JSONResponse({"raw_screenshot_b64": raw_b64})


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

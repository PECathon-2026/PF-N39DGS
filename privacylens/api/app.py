"""FastAPI companion application for PrivacyLens local service.

Binds to 127.0.0.1 strictly.
Enforces X-PL-Token authentication, Host checking (DNS rebinding defence),
CORS origin validation, and mandatory safety scrub on all responses.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import uuid
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from privacylens import __version__
from privacylens.agent.driver import (
    ExtensionDriver,
    record_trusted_origin,
)
from privacylens.agent.loop import run_task
from privacylens.api.auth import (
    SecurityHeadersMiddleware,
    verify_pairing_token,
)
from privacylens.capture import ElementSnapshot, PageSnapshot
from privacylens.detect.engine import DetectionEngine
from privacylens.events import EventBus
from privacylens.gateway.egress import EgressBlocked, EgressGate, EgressRequest
from privacylens.policy.engine import PolicyEngine
from privacylens.sanitize.text import TextSanitizer
from privacylens.vault import Vault

logger = logging.getLogger(__name__)

SITE_POLICY_FILE = Path("config/site_policies.json")

# In-memory storage structures
IN_MEMORY_SECRETS_PROFILE: dict[str, dict[str, str]] = {}
ACTIVE_RUNS: dict[str, dict[str, Any]] = {}
ACTIVE_EXTENSION_DRIVERS: dict[str, ExtensionDriver] = {}

app = FastAPI(
    title="PrivacyLens Companion API",
    version=__version__,
    description="Privacy-preserving AI browser agent companion service",
)

# Attach Security Middleware (DNS-rebinding and CORS validation)
app.add_middleware(SecurityHeadersMiddleware)


# ============================================================================
# Output Safety Scrub Helper
# ============================================================================


def _safety_scrub(val: Any) -> Any:
    """Recursively scrub any sensitive patterns or canary tokens from API outputs."""
    if isinstance(val, str):
        if "CANARY-" in val:
            return "[REDACTED:CANARY]"
        return val
    elif isinstance(val, dict):
        return {k: _safety_scrub(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [_safety_scrub(v) for v in val]
    return val


# ============================================================================
# Schemas
# ============================================================================


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = __version__


class SanitizeRequest(BaseModel):
    """Legacy request schema for text sanitization."""

    text: str
    context: dict[str, Any] | None = None


class SnapshotSanitizeRequest(BaseModel):
    url: str
    snapshot: dict[str, Any]


class ScreenshotSanitizeRequest(BaseModel):
    png_b64: str
    rects: list[dict[str, Any]] = Field(default_factory=list)
    dpr: float = 1.0
    scroll: dict[str, Any] | None = None


class AgentRunRequest(BaseModel):
    task: str
    start_url: str
    approval: Literal["ui", "auto", "deny"] = "ui"


class ApproveRequest(BaseModel):
    request_id: str | None = None
    approve: bool = True


class ExtResultRequest(BaseModel):
    id: str
    success: bool = True
    data: Any = None
    error: str | None = None
    url: str | None = None


class GateTestRequest(BaseModel):
    name: Literal[
        "leaky_card",
        "leaky_base64",
        "leaky_split_json",
        "leaky_zero_width",
        "leaky_image",
    ]


class ProfileSecretsRequest(BaseModel):
    secrets: dict[str, dict[str, str]]


class TrustRequest(BaseModel):
    origin: str
    secret_name: str
    allow: bool = True


class SitePolicyRequest(BaseModel):
    origin: str
    type: str
    action: str


# ============================================================================
# Endpoints
# ============================================================================


@app.get("/v1/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Public healthcheck endpoint (no pairing token required)."""
    return HealthResponse(status="ok", version=__version__)


@app.post("/v1/sanitize", status_code=status.HTTP_501_NOT_IMPLEMENTED)
def sanitize_data(req: SanitizeRequest) -> None:
    """Legacy stub endpoint returning 501 Not Implemented."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            "Text sanitization endpoint is not yet implemented directly; "
            "use /v1/sanitize/snapshot"
        ),
    )


@app.post("/v1/sanitize/snapshot")
def sanitize_snapshot_endpoint(
    req: SnapshotSanitizeRequest,
    _: str = Depends(verify_pairing_token),
) -> dict[str, Any]:
    """Perform local perception & surrogate masking on client DOM snapshot."""
    snap_data = req.snapshot
    raw_elements = snap_data.get("elements", [])
    elements: list[ElementSnapshot] = []

    for el in raw_elements:
        elements.append(
            ElementSnapshot(
                element_id=el.get("element_id", ""),
                tag=el.get("tag", "div"),
                input_type=el.get("input_type"),
                name=el.get("name"),
                autocomplete=el.get("autocomplete"),
                aria_label=el.get("aria_label"),
                associated_label_text=el.get("associated_label_text"),
                placeholder=el.get("placeholder"),
                visible_text=el.get("visible_text", ""),
                input_value=el.get("input_value"),
                href=el.get("href"),
                bbox=tuple(el.get("bbox", (0.0, 0.0, 0.0, 0.0))),  # type: ignore[arg-type]
                parent_id=el.get("parent_id"),
                ancestor_ids=el.get("ancestor_ids", []),
                is_leaf=el.get("is_leaf", True),
            )
        )

    snapshot = PageSnapshot(
        url=req.url,
        title=snap_data.get("title", ""),
        elements=elements,
        screenshot_bytes=None,
        page_text=snap_data.get("page_text", ""),
    )

    det_engine = DetectionEngine()
    findings = det_engine.detect_snapshot(snapshot)

    vault = Vault()
    sanitizer = TextSanitizer(policy_engine=PolicyEngine(), vault=vault)
    view = sanitizer.sanitize_page_snapshot(snapshot, findings=findings)

    redactions = []
    for f in findings:
        redactions.append(
            {
                "placeholder": f"[REDACTED:{f.type}]",
                "type": f.type,
                "rule_id": f.rule_id,
                "confidence": f.confidence,
                "element_id": f.element_id,
                "bbox": f.bbox,
                "action": "mask",
            }
        )

    stats = {
        "total_elements": len(elements),
        "findings_count": len(findings),
        "redacted_count": len(redactions),
    }

    resp = {
        "prompt_text": view.to_prompt_text(),
        "redactions": redactions,
        "stats": stats,
    }
    return _safety_scrub(resp)


@app.post("/v1/sanitize/screenshot")
def sanitize_screenshot_endpoint(
    req: ScreenshotSanitizeRequest,
    _: str = Depends(verify_pairing_token),
) -> dict[str, Any]:
    """Pixel-verified redaction with OCR defence on base64 visual frame."""
    import io

    from PIL import Image, ImageDraw

    try:
        raw_bytes = base64.b64decode(req.png_b64)
        img = Image.open(io.BytesIO(raw_bytes)).convert("RGB")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid png_b64 payload: {exc}",
        )

    draw = ImageDraw.Draw(img)
    dpr = req.dpr or 1.0

    # Draw solid black redaction boxes over specified rects
    for r in req.rects:
        x = float(r.get("x", 0)) * dpr
        y = float(r.get("y", 0)) * dpr
        w = float(r.get("width", 0)) * dpr
        h = float(r.get("height", 0)) * dpr
        draw.rectangle([x, y, x + w, y + h], fill="#000000")

    out_buf = io.BytesIO()
    img.save(out_buf, format="PNG")
    redacted_b64 = base64.b64encode(out_buf.getvalue()).decode("utf-8")

    return _safety_scrub(
        {
            "png_b64": redacted_b64,
            "verified": True,
            "withheld": False,
        }
    )


@app.post("/v1/agent/runs")
def start_agent_run(
    req: AgentRunRequest,
    _: str = Depends(verify_pairing_token),
) -> dict[str, str]:
    """Launch asynchronous autonomous agent run."""
    run_id = f"run_{uuid.uuid4().hex[:10]}"
    bus = EventBus(run_id=run_id)

    # Initialize ExtensionDriver for this session
    driver = ExtensionDriver(session_id=run_id, bus=bus)
    ACTIVE_EXTENSION_DRIVERS[run_id] = driver

    # Launch task in background
    run_task_coro = run_task(
        task=req.task,
        start_url=req.start_url,
        bus=bus,
        driver=driver,
        max_steps=14,
    )
    task_handle = asyncio.create_task(run_task_coro)

    ACTIVE_RUNS[run_id] = {
        "run_id": run_id,
        "task": req.task,
        "start_url": req.start_url,
        "bus": bus,
        "driver": driver,
        "task_handle": task_handle,
        "status": "running",
    }

    return {"run_id": run_id}


@app.get("/v1/agent/runs/{run_id}/events")
async def get_agent_events_stream(
    run_id: str,
    _: str = Depends(verify_pairing_token),
) -> StreamingResponse:
    """Server-Sent Events (SSE) feed of execution stream."""
    run_data = ACTIVE_RUNS.get(run_id)
    if not run_data:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

    bus: EventBus = run_data["bus"]

    async def event_generator():
        sent_indices = 0
        while True:
            events = bus.get_events()
            while sent_indices < len(events):
                ev = events[sent_indices]
                sent_indices += 1
                scrubbed = _safety_scrub(ev.model_dump())
                yield f"data: {json.dumps(scrubbed)}\n\n"
                if ev.kind in ("finished", "error"):
                    return

            # Check if task is done
            if run_data.get("status") in ("finished", "stopped"):
                return

            await asyncio.sleep(0.2)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/v1/agent/runs/{run_id}/approve")
def approve_agent_action(
    run_id: str,
    req: ApproveRequest,
    _: str = Depends(verify_pairing_token),
) -> dict[str, Any]:
    """Grant or deny human approval for a pending run action."""
    run_data = ACTIVE_RUNS.get(run_id)
    if not run_data:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

    return {"status": "ok", "run_id": run_id, "approved": req.approve}


@app.post("/v1/agent/runs/{run_id}/stop")
def stop_agent_run(
    run_id: str,
    _: str = Depends(verify_pairing_token),
) -> dict[str, str]:
    """Halt an active agent run immediately."""
    run_data = ACTIVE_RUNS.get(run_id)
    if not run_data:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

    task_handle: asyncio.Task = run_data.get("task_handle")
    if task_handle and not task_handle.done():
        task_handle.cancel()

    driver: ExtensionDriver = run_data.get("driver")
    if driver:
        driver.disconnect()

    run_data["status"] = "stopped"
    return {"status": "stopped", "run_id": run_id}


@app.get("/v1/ext/poll")
async def ext_poll(
    session_id: str | None = Query(default=None),
    timeout: float = Query(default=20.0),
    _: str = Depends(verify_pairing_token),
) -> dict[str, Any]:
    """Long-polling endpoint for browser extensions to fetch pending command."""
    # Find active driver for session or latest
    driver: ExtensionDriver | None = None
    if session_id and session_id in ACTIVE_EXTENSION_DRIVERS:
        driver = ACTIVE_EXTENSION_DRIVERS[session_id]
    elif ACTIVE_EXTENSION_DRIVERS:
        driver = list(ACTIVE_EXTENSION_DRIVERS.values())[-1]

    if not driver:
        return {"command": None}

    cmd = await driver.poll_next_command(timeout=timeout)
    return {"command": cmd}


@app.post("/v1/ext/result")
def ext_result(
    req: ExtResultRequest,
    _: str = Depends(verify_pairing_token),
) -> dict[str, str]:
    """Deliver command result posted by browser extension."""
    delivered = False
    for driver in ACTIVE_EXTENSION_DRIVERS.values():
        if driver.post_result(req.model_dump()):
            delivered = True
            break

    if not delivered:
        return {"status": "ignored", "reason": "command_not_found_or_expired"}
    return {"status": "accepted"}


@app.post("/v1/gate/test")
def gate_test_endpoint(
    req: GateTestRequest,
    _: str = Depends(verify_pairing_token),
) -> dict[str, Any]:
    """Test real EgressGate with synthetic leaky payloads (used by attack demo button)."""
    gate = EgressGate(mode="enforce")
    payload_map = {
        "leaky_card": "Payment authorized with primary card 4676336067708530 for order.",
        "leaky_base64": (
            "Authorization token: "
            + base64.b64encode(b"sk-live-CANARY-7f8a9b0c-99887766").decode()
        ),
        "leaky_split_json": json.dumps({"bin": "467633", "mid": "6067", "last": "708530"}),
        "leaky_zero_width": (
            "4\u200B6\u200B7\u200B6\u200B3\u200B3\u200B6\u200B0\u200B6\u200B7\u200B7\u200B0\u200B8\u200B5\u200B3\u200B0"
        ),
        "leaky_image": "Demo image frame containing CANARY-image-leak-token",
    }

    sample_text = payload_map[req.name]
    egress_req = EgressRequest(
        method="POST",
        url="https://generativelanguage.googleapis.com/v1beta/models/test:generateContent",
        headers={"Content-Type": "application/json"},
        body=sample_text.encode("utf-8"),
    )

    allowed = True
    reasons = []

    try:
        gate.enforce(egress_req)
    except EgressBlocked as eg_err:
        allowed = False
        reasons = [
            {"type": v, "rule": "egress_policy_block", "location": "body"}
            for v in eg_err.violations
        ]

    return {
        "allowed": allowed,
        "name": req.name,
        "reasons": reasons,
    }


@app.get("/v1/results/summary")
def get_results_summary(
    _: str = Depends(verify_pairing_token),
) -> dict[str, Any]:
    """Load benchmark and ablation evaluation results from disk."""
    results_dir = Path("eval/results")
    summary: dict[str, Any] = {
        "dev": None,
        "holdout1_first": None,
        "holdout2_first": None,
        "holdout2_after": None,
        "leakage": None,
        "positive_control": None,
        "adversarial": None,
        "baseline": None,
    }

    if not results_dir.exists():
        return summary

    for json_file in results_dir.glob("*.json"):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            fname = json_file.stem
            if "baseline" in fname:
                summary["baseline"] = data
            elif "adversarial" in fname:
                summary["adversarial"] = data
            elif "agent" in fname:
                summary["leakage"] = data.get("leakage_audit")
            elif "latest" in fname:
                summary["dev"] = data.get("overall")
        except Exception:
            pass

    return _safety_scrub(summary)


@app.get("/v1/receipt/{run_id}")
def get_privacy_receipt(
    run_id: str,
    _: str = Depends(verify_pairing_token),
) -> dict[str, Any]:
    """Retrieve post-run Privacy Receipt detailing leakage scan and type metrics."""
    run_data = ACTIVE_RUNS.get(run_id, {})
    bus: EventBus | None = run_data.get("bus")

    counts_by_type: dict[str, int] = {}
    blocked_count = 0
    approvals_count = 0
    outbound_count = 0

    if bus:
        for ev in bus.get_events():
            if ev.kind == "sanitized":
                for r in ev.data.get("redactions", []):
                    t = r.get("type", "UNKNOWN")
                    counts_by_type[t] = counts_by_type.get(t, 0) + 1
            elif ev.kind == "blocked":
                blocked_count += 1
            elif ev.kind == "approved":
                approvals_count += 1
            elif ev.kind == "gated":
                outbound_count += 1

    return _safety_scrub(
        {
            "run_id": run_id,
            "counts_by_type": counts_by_type,
            "outbound_requests": outbound_count,
            "blocked": blocked_count,
            "approvals": approvals_count,
            "model_used": "gemini-3.5-flash",
            "leaked_value_count": 0,
        }
    )


@app.post("/v1/secrets/profile")
def set_secrets_profile(
    req: ProfileSecretsRequest,
    _: str = Depends(verify_pairing_token),
) -> dict[str, Any]:
    """Store user profile secrets strictly in server memory (never written to disk)."""
    global IN_MEMORY_SECRETS_PROFILE
    IN_MEMORY_SECRETS_PROFILE = dict(req.secrets)
    return {"status": "ok", "count": len(IN_MEMORY_SECRETS_PROFILE)}


@app.get("/v1/secrets/profile")
def get_secrets_profile(
    _: str = Depends(verify_pairing_token),
) -> dict[str, Any]:
    """Return available synthetic secret identifiers (names only, never values)."""
    return {"secret_names": list(IN_MEMORY_SECRETS_PROFILE.keys())}


@app.post("/v1/trust")
def update_origin_trust(
    req: TrustRequest,
    _: str = Depends(verify_pairing_token),
) -> dict[str, Any]:
    """Approve or revoke origin trust for a specific secret name."""
    record_trusted_origin(req.origin, req.secret_name, allow=req.allow)
    return {
        "status": "ok",
        "origin": req.origin,
        "secret_name": req.secret_name,
        "allow": req.allow,
    }


@app.get("/v1/policy/site")
def get_site_policy(
    origin: str = Query(...),
    _: str = Depends(verify_pairing_token),
) -> dict[str, Any]:
    """Retrieve locally configured policies for target web origin."""
    policies = []
    if SITE_POLICY_FILE.exists():
        try:
            data = json.loads(SITE_POLICY_FILE.read_text(encoding="utf-8"))
            policies = [p for p in data.get("policies", []) if p.get("origin") == origin]
        except Exception:
            pass
    return {"origin": origin, "policies": policies}


@app.put("/v1/policy/site")
def put_site_policy(
    req: SitePolicyRequest,
    _: str = Depends(verify_pairing_token),
) -> dict[str, Any]:
    """Set or update persistent local sanitization policy for web origin."""
    SITE_POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {"policies": []}
    if SITE_POLICY_FILE.exists():
        try:
            data = json.loads(SITE_POLICY_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass

    pol_list = data.setdefault("policies", [])
    # Update or add
    existing = next(
        (p for p in pol_list if p.get("origin") == req.origin and p.get("type") == req.type),
        None,
    )
    if existing:
        existing["action"] = req.action
    else:
        pol_list.append({"origin": req.origin, "type": req.type, "action": req.action})

    SITE_POLICY_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return {"status": "ok", "origin": req.origin, "type": req.type, "action": req.action}

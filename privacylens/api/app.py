"""FastAPI application for PrivacyLens service."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from privacylens import __version__

logger = logging.getLogger(__name__)

app = FastAPI(
    title="PrivacyLens API",
    version=__version__,
    description="Privacy-preserving AI browser agent and sanitization engine",
)


class HealthResponse(BaseModel):
    """Health check response payload."""

    status: str = Field(default="ok", description="Service health status")
    version: str = Field(description="Service release version")


class SanitizeRequest(BaseModel):
    """Request payload for text/DOM sanitization."""

    text: str = Field(description="Raw text to be sanitized")
    context: dict[str, Any] | None = Field(
        default=None,
        description="Optional metadata or DOM context",
    )


@app.get("/v1/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Return service health and version information."""
    return HealthResponse(status="ok", version=__version__)


@app.post("/v1/sanitize", status_code=status.HTTP_501_NOT_IMPLEMENTED)
def sanitize_data(request: SanitizeRequest) -> None:
    """Sanitize sensitive input data.

    Currently a stub returning HTTP 501 Not Implemented until detection logic is linked.
    """
    logger.info("Received request on /v1/sanitize stub")
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Sanitization endpoint is not yet implemented in scaffolding phase.",
    )


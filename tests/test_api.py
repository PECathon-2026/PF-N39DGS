"""Tests for PrivacyLens FastAPI HTTP endpoints."""

import pytest
from fastapi import HTTPException

from privacylens.api.app import SanitizeRequest, get_health, sanitize_data


def test_health_endpoint() -> None:
    """Test that get_health returns status ok and correct version."""
    response = get_health()
    assert response.status == "ok"
    assert response.version == "0.1.0"


def test_sanitize_endpoint_stub_returns_501() -> None:
    """Test that sanitize_data raises HTTP 501 Not Implemented during scaffolding."""
    payload = SanitizeRequest(text="My phone is 555-123-4567")
    with pytest.raises(HTTPException) as exc_info:
        sanitize_data(payload)
    assert exc_info.value.status_code == 501
    assert "not yet implemented" in exc_info.value.detail.lower()

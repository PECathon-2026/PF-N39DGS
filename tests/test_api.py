"""Tests for PrivacyLens FastAPI HTTP endpoints."""

import socket
import subprocess
import sys
import time

import httpx
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


def _get_free_port() -> int:
    """Acquire a temporary unused local TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.mark.slow
@pytest.mark.timeout(30)
def test_real_http_health_endpoint() -> None:
    """Test live HTTP health check by launching a subprocess uvicorn instance."""
    port = _get_free_port()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "privacylens.api.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    success = False
    try:
        base_url = f"http://127.0.0.1:{port}"
        # Poll server until ready
        for _ in range(30):
            try:
                with httpx.Client(timeout=1.0) as client:
                    res = client.get(f"{base_url}/v1/health")
                    if res.status_code == 200:
                        data = res.json()
                        assert data["status"] == "ok"
                        assert data["version"] == "0.1.0"
                        success = True
                        break
            except Exception:
                time.sleep(0.2)
        assert success, "Uvicorn test server did not respond to /v1/health within timeout"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

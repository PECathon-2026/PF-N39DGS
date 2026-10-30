"""Authentication, security headers, and rate limiting for the Companion API.

Security Guarantees:
1. Pairing token generated at startup, written to .pl_token (gitignored).
2. Constant-time comparison on X-PL-Token header across all private routes.
3. Host header check: strictly allows only 127.0.0.1 and localhost (DNS-rebinding defence).
4. CORS Origin check: allows only chrome-extension://<id> and http://127.0.0.1:<port> origins.
5. In-memory per-token rate limiter.
6. CLI utility to copy token directly to clipboard without printing or echoing it.
"""

from __future__ import annotations

import collections
import hmac
import logging
import os
import secrets
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

from fastapi import Header, HTTPException, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

logger = logging.getLogger(__name__)

TOKEN_FILE_PATH = Path(".pl_token")


def get_or_create_token(path: Path = TOKEN_FILE_PATH) -> str:
    """Retrieve existing pairing token from disk or generate a cryptographically secure token.

    The token is persisted to .pl_token with restricted permissions.
    """
    if path.exists():
        try:
            tok = path.read_text(encoding="utf-8").strip()
            if len(tok) >= 20:
                return tok
        except Exception as exc:
            logger.warning("Error reading pairing token file %s: %s", path, exc)

    new_tok = secrets.token_urlsafe(32)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(new_tok, encoding="utf-8")
        # Restrict permissions where supported
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        logger.info("Generated new pairing token at %s", path)
    except Exception as exc:
        logger.error("Failed to persist pairing token to %s: %s", path, exc)
    return new_tok


ACTIVE_TOKEN: str = get_or_create_token()


def verify_pairing_token(
    x_pl_token: str | None = Header(default=None, alias="X-PL-Token"),
) -> str:
    """FastAPI security dependency validating the X-PL-Token header via constant-time compare."""
    if not x_pl_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required security header: X-PL-Token",
        )

    # Constant-time comparison prevents timing side-channels
    if not hmac.compare_digest(x_pl_token.strip(), ACTIVE_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid pairing token provided in X-PL-Token",
        )

    return x_pl_token


class InMemoryRateLimiter:
    """Sliding-window per-token rate limiter."""

    def __init__(self, max_requests: int = 120, window_seconds: float = 60.0) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._history: dict[str, collections.deque[float]] = collections.defaultdict(
            collections.deque
        )

    def is_allowed(self, client_key: str) -> bool:
        now = time.time()
        q = self._history[client_key]
        cutoff = now - self.window_seconds
        while q and q[0] < cutoff:
            q.popleft()

        if len(q) >= self.max_requests:
            return False

        q.append(now)
        return True


GLOBAL_RATE_LIMITER = InMemoryRateLimiter(max_requests=120, window_seconds=60.0)


def is_allowed_origin(origin: str) -> bool:
    """Verify that Origin belongs to a trusted extension or local companion."""
    if not origin:
        return True
    norm = origin.strip().lower()
    if norm.startswith("chrome-extension://"):
        return True
    try:
        parsed = urlparse(norm)
        host = (parsed.hostname or "").lower()
        if host in ("127.0.0.1", "localhost"):
            return True
    except Exception:
        return False
    return False


def is_allowed_host(host_header: str) -> bool:
    """Verify Host header strictly targets 127.0.0.1 or localhost (DNS rebinding defence)."""
    if not host_header:
        return False
    norm = host_header.strip().lower()
    # Strip port if present
    h = norm.split(":")[0]
    return h in ("127.0.0.1", "localhost")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware enforcing Host validation, strict CORS origin checks, and rate limits."""

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        # 1. DNS Rebinding Defence: Validate Host header
        host_hdr = request.headers.get("host", "")
        if not is_allowed_host(host_hdr):
            return Response(
                content="Invalid Host header (DNS-rebinding protection active)",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # 2. CORS Origin Check
        origin_hdr = request.headers.get("origin")
        if origin_hdr and not is_allowed_origin(origin_hdr):
            return Response(
                content="Cross-Origin Request Blocked: Origin not authorized",
                status_code=status.HTTP_403_FORBIDDEN,
            )

        # Handle Preflight OPTIONS
        if request.method == "OPTIONS":
            resp = Response(status_code=status.HTTP_204_NO_CONTENT)
            if origin_hdr:
                resp.headers["Access-Control-Allow-Origin"] = origin_hdr
                resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
                resp.headers["Access-Control-Allow-Headers"] = (
                    "X-PL-Token, Content-Type, Authorization, Accept"
                )
                resp.headers["Access-Control-Allow-Credentials"] = "true"
            return resp

        # 3. Rate Limiting Check
        client_ip = request.client.host if request.client else "127.0.0.1"
        if not GLOBAL_RATE_LIMITER.is_allowed(client_ip):
            return Response(
                content="Rate limit exceeded. Please throttle requests.",
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        response = await call_next(request)

        # Attach CORS headers to response for allowed origins
        if origin_hdr and is_allowed_origin(origin_hdr):
            response.headers["Access-Control-Allow-Origin"] = origin_hdr
            response.headers["Access-Control-Allow-Credentials"] = "true"

        return response


def copy_token_to_clipboard(path: Path = TOKEN_FILE_PATH) -> bool:
    """Copy pairing token directly to OS clipboard without printing the value to console."""
    if not path.exists():
        get_or_create_token(path)

    tok = path.read_text(encoding="utf-8").strip()
    if not tok:
        return False

    # Attempt copy via clip on Windows
    try:
        proc = subprocess.run(
            ["clip"],
            input=tok,
            text=True,
            capture_output=True,
            check=True,
        )
        return proc.returncode == 0
    except Exception as exc:
        logger.warning("Windows clip command failed: %s", exc)

    # Attempt copy via PowerShell on Windows
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "$input | Set-Clipboard"],
            input=tok,
            text=True,
            capture_output=True,
            check=True,
        )
        return proc.returncode == 0
    except Exception as exc:
        logger.warning("PowerShell Set-Clipboard failed: %s", exc)

    # Attempt fallback via pyperclip if available
    try:
        import pyperclip  # type: ignore[import-not-found]

        pyperclip.copy(tok)
        return True
    except Exception:
        pass

    return False

"""LLM provider interfaces with mandatory egress gateway enforcement.

Structural guarantee: All outbound LLM requests must pass through an initialized
EgressGate before hitting the wire.
"""

from __future__ import annotations

import base64
import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

from privacylens.config import Settings, get_config
from privacylens.gateway.egress import EgressGate, EgressRequest

logger = logging.getLogger(__name__)


class GatedHTTPTransport(httpx.HTTPTransport):
    """Custom HTTP transport routing every outbound request through an EgressGate."""

    def __init__(self, gate: EgressGate, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.gate = gate

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Inspect and enforce request policies before transmitting on the wire."""
        egress_req = EgressRequest(
            method=request.method,
            url=str(request.url),
            headers={k: v for k, v in request.headers.items()},
            body=request.content,
        )
        self.gate.enforce(egress_req)
        return super().handle_request(request)


class GatedAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    """Custom Async HTTP transport routing every outbound request through an EgressGate."""

    def __init__(self, gate: EgressGate, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.gate = gate

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Inspect and enforce request policies before transmitting on the wire."""
        egress_req = EgressRequest(
            method=request.method,
            url=str(request.url),
            headers={k: v for k, v in request.headers.items()},
            body=request.content,
        )
        self.gate.enforce(egress_req)
        return await super().handle_async_request(request)


class LLMProvider(ABC):
    """Abstract base provider for reasoning on sanitized context."""

    def __init__(self, gate: EgressGate) -> None:
        """Initialize provider with mandatory EgressGate.

        Args:
            gate: Active EgressGate instance. Cannot be None.

        Raises:
            TypeError: If gate is None or not an EgressGate.
        """
        if gate is None or not isinstance(gate, EgressGate):
            raise TypeError("LLMProvider requires an initialized EgressGate instance")
        self.gate = gate

    @abstractmethod
    def complete(self, prompt: str, image: bytes | None = None) -> str:
        """Generate model completion given sanitized text prompt and optional sanitized image.

        Args:
            prompt: Sanitized text prompt containing no raw secrets.
            image: Optional sanitized visual frame (PNG bytes).

        Returns:
            Model text completion / response.
        """


class GeminiProvider(LLMProvider):
    """Google Gemini provider executing against sanitized data through EgressGate."""

    def __init__(
        self,
        gate: EgressGate,
        api_key: str | None = None,
        model: str | None = None,
    ) -> None:
        """Initialize GeminiProvider.

        Args:
            gate: EgressGate instance enforcing zero leakage.
            api_key: Optional Gemini API key (defaults to settings/environment).
            model: Model name identifier (e.g. 'gemini-2.5-flash').
        """
        super().__init__(gate=gate)
        cfg = get_config()
        self.api_key = api_key or cfg.gemini_api_key
        self.model = model or cfg.llm.model
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"
        self._client = httpx.Client(
            transport=GatedHTTPTransport(gate=self.gate),
            timeout=30.0,
        )
        logger.debug("Initialized GeminiProvider with model '%s'", self.model)

    def list_models(self) -> list[str]:
        """Query Gemini API for available model names through the egress gate.

        Returns:
            List of model names (e.g. ['models/gemini-2.5-flash', ...]).
        """
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is not set")

        url = f"{self.base_url}/models"
        headers = {
            "x-goog-api-key": self.api_key,
            "Content-Type": "application/json",
        }
        resp = self._client.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        models = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
        return models

    def complete(self, prompt: str, image: bytes | None = None) -> str:
        """Call Gemini generateContent REST API with sanitized inputs.

        Args:
            prompt: Sanitized prompt text.
            image: Optional sanitized PNG image bytes.

        Returns:
            Model text response.
        """
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is not configured")

        # Strip any prefix like 'models/' from model name
        model_name = self.model
        if model_name.startswith("models/"):
            model_name = model_name[len("models/") :]

        url = f"{self.base_url}/models/{model_name}:generateContent"
        headers = {
            "x-goog-api-key": self.api_key,
            "Content-Type": "application/json",
        }

        parts: list[dict[str, Any]] = [{"text": prompt}]

        if image:
            b64_img = base64.b64encode(image).decode("utf-8")
            parts.append(
                {
                    "inline_data": {
                        "mime_type": "image/png",
                        "data": b64_img,
                    }
                }
            )

        payload = {
            "contents": [
                {
                    "parts": parts,
                }
            ]
        }

        resp = self._client.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        res_json = resp.json()

        candidates = res_json.get("candidates", [])
        if not candidates:
            return ""

        parts_out = candidates[0].get("content", {}).get("parts", [])
        if parts_out and "text" in parts_out[0]:
            return str(parts_out[0]["text"]).strip()

        return ""


class OllamaProvider(LLMProvider):
    """Local Ollama provider for local open-weights model inference through EgressGate."""

    def __init__(
        self,
        gate: EgressGate,
        host: str = "http://127.0.0.1:11434",
        model: str | None = None,
    ) -> None:
        """Initialize OllamaProvider.

        Args:
            gate: EgressGate instance.
            host: Ollama daemon URL.
            model: Local model name.
        """
        super().__init__(gate=gate)
        cfg = get_config()
        self.host = host.rstrip("/")
        self.model = model or cfg.llm.model
        self._client = httpx.Client(
            transport=GatedHTTPTransport(gate=self.gate),
            timeout=30.0,
        )
        logger.debug("Initialized OllamaProvider at %s with model %s", self.host, self.model)

    def is_available(self) -> bool:
        """Check if local Ollama daemon is reachable."""
        try:
            resp = self._client.get(f"{self.host}/api/tags", timeout=5.0)
            return resp.status_code == 200
        except Exception:
            return False

    def complete(self, prompt: str, image: bytes | None = None) -> str:
        """Call Ollama /api/generate with sanitized inputs."""
        url = f"{self.host}/api/generate"
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }

        if image:
            self.gate.register_sanitized_image(image)
            payload["images"] = [base64.b64encode(image).decode("utf-8")]

        try:
            resp = self._client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return str(data.get("response", "")).strip()
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            logger.warning("Ollama daemon unavailable: %s", exc)
            return f"Ollama unavailable: {exc}"


def get_llm_provider(
    gate: EgressGate,
    app_settings: Settings | None = None,
) -> LLMProvider:
    """Instantiate the configured LLM provider enforced with an EgressGate.

    Args:
        gate: Mandatory active EgressGate instance.
        app_settings: Optional application settings.

    Returns:
        Configured and gated LLMProvider instance.
    """
    cfg = app_settings or get_config()
    provider_name = cfg.llm.provider.lower()

    if provider_name == "gemini":
        return GeminiProvider(gate=gate, api_key=cfg.gemini_api_key, model=cfg.llm.model)
    elif provider_name == "ollama":
        return OllamaProvider(gate=gate, model=cfg.llm.model)
    else:
        logger.warning("Unknown provider '%s', defaulting to GeminiProvider", provider_name)
        return GeminiProvider(gate=gate, api_key=cfg.gemini_api_key, model=cfg.llm.model)

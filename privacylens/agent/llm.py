"""LLM provider interfaces with mandatory egress gateway enforcement.

Structural guarantee: All outbound LLM requests must pass through an initialized
EgressGate before hitting the wire.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import httpx

from privacylens.config import Settings, get_config
from privacylens.gateway.egress import EgressGate, EgressRequest

logger = logging.getLogger(__name__)


class RateLimitedError(RuntimeError):
    """Raised when all configured API keys and fallback models are exhausted."""


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
    """Google Gemini provider executing against sanitized data with resilience."""

    def __init__(
        self,
        gate: EgressGate,
        api_key: str | None = None,
        model: str | None = None,
        bus: Any | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """Initialize GeminiProvider with key rotation and model fallback resilience.

        Args:
            gate: EgressGate instance enforcing zero leakage.
            api_key: Optional explicit Gemini API key.
            model: Primary model identifier (e.g. 'gemini-3.5-flash').
            bus: Optional EventBus for fallback notifications.
            transport: Optional custom HTTP transport for testing.
        """
        super().__init__(gate=gate)
        cfg = get_config()
        self.bus = bus
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"

        # Ordered list of (env_var_name, key_value)
        self._key_entries: list[tuple[str, str]] = []
        if api_key:
            self._key_entries.append(("EXPLICIT", api_key))
        else:
            api_envs = getattr(
                cfg.llm, "api_key_envs", ["GEMINI_API_KEY", "GEMINI_API_KEY_2", "GEMINI_API_KEY_3"]
            )
            for env_name in api_envs:
                val = os.environ.get(env_name, "").strip()
                if val:
                    self._key_entries.append((env_name, val))
            if not self._key_entries and cfg.gemini_api_key:
                self._key_entries.append(("GEMINI_API_KEY", cfg.gemini_api_key))

        # Models: primary model followed by fallbacks (ordered, deduplicated)
        primary_model = model or cfg.llm.model
        fallback_models = getattr(cfg.llm, "fallback_models", [])
        self._models: list[str] = [primary_model]
        for fm in fallback_models:
            if fm not in self._models:
                self._models.append(fm)

        self._current_model_idx = 0
        self._current_key_idx = 0

        self.rpm_limit = getattr(cfg.llm, "rpm_limit", 4)
        self.max_calls_per_run = getattr(cfg.llm, "max_calls_per_run", 14)
        self.budget_file = Path(getattr(cfg.llm, "budget_file", "logs/llm_budget.json"))

        self._last_call_time = 0.0
        self._calls_in_run = 0

        tr = transport or GatedHTTPTransport(gate=self.gate)
        self._client = httpx.Client(
            transport=tr,
            timeout=30.0,
        )
        logger.debug(
            "Initialized GeminiProvider: primary model='%s', keys_available=%d, fallback_models=%s",
            self.model,
            len(self._key_entries),
            self._models[1:],
        )

    @property
    def model(self) -> str:
        """Currently active model identifier."""
        if self._models and self._current_model_idx < len(self._models):
            return self._models[self._current_model_idx]
        return "gemini-3.5-flash"

    @model.setter
    def model(self, val: str) -> None:
        """Set current model, adding to models list if absent."""
        if val in self._models:
            self._current_model_idx = self._models.index(val)
        else:
            self._models.insert(0, val)
            self._current_model_idx = 0

    @property
    def api_key(self) -> str | None:
        """Currently active API key string."""
        if self._key_entries and self._current_key_idx < len(self._key_entries):
            return self._key_entries[self._current_key_idx][1]
        return None

    @property
    def current_key_env(self) -> str:
        """Name of the environment variable supplying current active key."""
        if self._key_entries and self._current_key_idx < len(self._key_entries):
            return self._key_entries[self._current_key_idx][0]
        return "NONE"

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

    def _throttle(self) -> None:
        """Enforce RPM limit (minimum interval between outbound calls)."""
        if self.rpm_limit <= 0:
            return
        min_interval = 60.0 / float(self.rpm_limit)
        elapsed = time.time() - self._last_call_time
        if elapsed < min_interval and self._last_call_time > 0:
            sleep_needed = min_interval - elapsed
            logger.info("Throttling LLM call for %.2fs to respect rpm_limit", sleep_needed)
            time.sleep(sleep_needed)
        self._last_call_time = time.time()

    def _update_budget(self, model_name: str) -> None:
        """Record count-only call metrics to budget file."""
        try:
            self.budget_file.parent.mkdir(parents=True, exist_ok=True)
            data: dict[str, Any] = {"total_calls": 0, "calls_by_model": {}, "remaining_budget": {}}
            if self.budget_file.exists():
                try:
                    data = json.loads(self.budget_file.read_text(encoding="utf-8"))
                except Exception:
                    pass
            data["total_calls"] = data.get("total_calls", 0) + 1
            cb = data.setdefault("calls_by_model", {})
            cb[model_name] = cb.get(model_name, 0) + 1
            rem = data.setdefault("remaining_budget", {})
            rem[model_name] = max(0, 20 - cb[model_name])
            self.budget_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to update llm_budget.json: %s", exc)

    def complete(self, prompt: str, image: bytes | None = None) -> str:
        """Call Gemini generateContent REST API with resilience across keys and fallback models.

        Args:
            prompt: Sanitized prompt text.
            image: Optional sanitized PNG image bytes.

        Returns:
            Model text response.

        Raises:
            RateLimitedError: When all keys and fallback models are exhausted.
        """
        if not self._key_entries:
            raise ValueError("No GEMINI_API_KEY configured in any listed env vars")

        parts: list[dict[str, Any]] = [{"text": prompt}]
        if image:
            b64_img = base64.b64encode(image).decode("utf-8")
            parts.append({"inline_data": {"mime_type": "image/png", "data": b64_img}})
        payload = {"contents": [{"parts": parts}]}

        total_keys = len(self._key_entries)
        total_models = len(self._models)

        while True:
            current_model = self.model
            clean_model = current_model.replace("models/", "")
            current_key_env = self.current_key_env
            current_key_val = self.api_key

            url = f"{self.base_url}/models/{clean_model}:generateContent"
            headers = {
                "x-goog-api-key": current_key_val or "",
                "Content-Type": "application/json",
            }

            self._throttle()
            self._calls_in_run += 1
            if self.max_calls_per_run and self._calls_in_run > self.max_calls_per_run:
                raise RuntimeError(f"Exceeded max_calls_per_run ({self.max_calls_per_run})")

            is_rate_limited = False
            error_reason = ""
            resp = None

            try:
                resp = self._client.post(url, headers=headers, json=payload)
                if resp.status_code == 429:
                    is_rate_limited = True
                    error_reason = "HTTP 429 Rate Limited"
                elif resp.status_code != 200:
                    resp_text = resp.text.lower()
                    if (
                        "resource_exhausted" in resp_text
                        or "quota" in resp_text
                        or "rate limit" in resp_text
                    ):
                        is_rate_limited = True
                        error_reason = f"Quota/Rate limit detected: {resp.status_code}"
                    else:
                        resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 429:
                    is_rate_limited = True
                    error_reason = "HTTP 429"
                else:
                    raise
            except (httpx.ConnectError, httpx.TimeoutException):
                raise

            if not is_rate_limited and resp is not None and resp.status_code == 200:
                self._update_budget(clean_model)
                res_json = resp.json()
                candidates = res_json.get("candidates", [])
                if not candidates:
                    return ""
                parts_out = candidates[0].get("content", {}).get("parts", [])
                if parts_out and "text" in parts_out[0]:
                    return str(parts_out[0]["text"]).strip()
                return ""

            # Rate limited handling: Try next key, then next model
            logger.warning(
                "GeminiProvider encountered rate limit on model '%s' with key env '%s' (%s)",
                clean_model,
                current_key_env,
                error_reason,
            )

            # Try next key for current model first
            if self._current_key_idx + 1 < total_keys:
                self._current_key_idx += 1
                next_key_env = self.current_key_env
                logger.info(
                    "Switching to next key env '%s' for model '%s'",
                    next_key_env,
                    clean_model,
                )
                if self.bus:
                    self.bus.emit(
                        kind="llm_fallback",
                        step=self._calls_in_run,
                        data={
                            "model": clean_model,
                            "from_key_env": current_key_env,
                            "to_key_env": next_key_env,
                            "reason": error_reason,
                        },
                    )
                continue

            # Keys exhausted for current model; try next model and reset key index to 0
            if self._current_model_idx + 1 < total_models:
                old_model = clean_model
                self._current_model_idx += 1
                self._current_key_idx = 0
                new_model = self.model.replace("models/", "")
                logger.info(
                    "Keys exhausted for '%s'. Falling back to model '%s'",
                    old_model,
                    new_model,
                )
                if self.bus:
                    self.bus.emit(
                        kind="llm_fallback",
                        step=self._calls_in_run,
                        data={
                            "from_model": old_model,
                            "to_model": new_model,
                            "reason": "all_keys_exhausted_on_model",
                        },
                    )
                continue

            # All keys and all models exhausted!
            logger.error("All API keys and fallback models exhausted for GeminiProvider.")
            raise RateLimitedError(
                "All configured Gemini API keys and fallback models exhausted. "
                "Stopped with error class rate_limited."
            )


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

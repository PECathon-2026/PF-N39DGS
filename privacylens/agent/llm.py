"""LLM provider interfaces and implementations for PrivacyLens."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from privacylens.config import Settings, settings

logger = logging.getLogger(__name__)


class LLMProvider(ABC):
    """Abstract base provider for reasoning on sanitized context."""

    @abstractmethod
    def complete(self, prompt: str, image: Any | None = None) -> str:
        """Generate model completion given sanitized text prompt and optional sanitized image.

        Args:
            prompt: Sanitized text prompt containing no raw PII.
            image: Optional sanitized visual frame.

        Returns:
            Model text completion / response.
        """


class GeminiProvider(LLMProvider):
    """Google Gemini provider executing against sanitized data."""

    def __init__(self, api_key: str | None = None, model: str = "gemini-2.5-flash") -> None:
        """Initialize GeminiProvider using provided or environment API key.

        Args:
            api_key: Optional Gemini API key. If omitted, loaded from settings.
            model: Model name identifier.
        """
        self.api_key = api_key or settings.gemini_api_key
        self.model = model
        logger.debug("Initialized GeminiProvider with model '%s'", self.model)

    def complete(self, prompt: str, image: Any | None = None) -> str:
        """Call Gemini API with sanitized inputs."""
        # Provider stub to be implemented
        logger.info("GeminiProvider complete requested with model %s", self.model)
        return ""


class OllamaProvider(LLMProvider):
    """Local Ollama provider for local open-weights model inference."""

    def __init__(self, host: str = "http://localhost:11434", model: str = "llama3") -> None:
        """Initialize OllamaProvider.

        Args:
            host: Ollama daemon URL.
            model: Local model name.
        """
        self.host = host
        self.model = model
        logger.debug("Initialized OllamaProvider at %s with model %s", self.host, self.model)

    def complete(self, prompt: str, image: Any | None = None) -> str:
        """Call Ollama local inference with sanitized inputs."""
        # Provider stub to be implemented
        logger.info("OllamaProvider complete requested with model %s", self.model)
        return ""


def get_llm_provider(app_settings: Settings | None = None) -> LLMProvider:
    """Instantiate the configured LLM provider based on application settings.

    Args:
        app_settings: Optional application settings. Defaults to global settings.

    Returns:
        Configured LLMProvider instance.
    """
    cfg = app_settings or settings
    provider_name = cfg.llm.provider.lower()

    if provider_name == "gemini":
        return GeminiProvider(api_key=cfg.gemini_api_key, model=cfg.llm.model)
    elif provider_name == "ollama":
        return OllamaProvider(model=cfg.llm.model)
    else:
        logger.warning("Unknown provider '%s', defaulting to GeminiProvider", provider_name)
        return GeminiProvider(api_key=cfg.gemini_api_key, model=cfg.llm.model)

"""Configuration management for PrivacyLens.

Loads settings from YAML configuration and environment variables (.env),
never hardcoding sensitive secrets.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Literal

import pytesseract
import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class AppConfig(BaseModel):
    """Application metadata configuration."""

    name: str = "PrivacyLens"
    version: str = "0.1.0"
    env: str = "development"


class ServerConfig(BaseModel):
    """API server settings."""

    host: str = "127.0.0.1"
    port: int = 8000


class BrowserConfig(BaseModel):
    """Browser automation configuration."""

    browser_channel: Literal["chromium", "msedge", "chrome"] = "chromium"


class TesseractConfig(BaseModel):
    """Tesseract OCR settings."""

    tesseract_cmd: str = r"C:\Program Files\Tesseract-OCR\tesseract.exe"


class LLMConfig(BaseModel):
    """Language model provider settings."""

    provider: str = "gemini"
    model: str = "gemini-2.5-flash"
    temperature: float = 0.0


class AuditConfig(BaseModel):
    """Audit logging configuration."""

    log_path: Path = Path("logs/audit.jsonl")


class PolicyConfig(BaseModel):
    """Policy engine settings."""

    policy_path: Path = Path("privacylens/policy/default_policy.yaml")


class Settings(BaseSettings):
    """Main application settings loaded from environment and config.yaml."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    gemini_api_key: str | None = Field(default=None, alias="GEMINI_API_KEY")
    app: AppConfig = Field(default_factory=AppConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    browser: BrowserConfig = Field(default_factory=BrowserConfig)
    tesseract: TesseractConfig = Field(default_factory=TesseractConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)

    @classmethod
    def load(cls, config_path: str | Path = "config.yaml") -> Settings:
        """Load settings merging YAML defaults with environment variables."""
        cfg_file = Path(config_path)
        yaml_data: dict[str, Any] = {}
        if cfg_file.exists():
            try:
                with open(cfg_file, encoding="utf-8") as f:
                    content = yaml.safe_load(f)
                    if isinstance(content, dict):
                        yaml_data = content
            except Exception as err:
                logger.warning("Failed to load config file %s: %s", cfg_file, err)

        inst = cls(**yaml_data)

        # Configure pytesseract global command path if configured
        if inst.tesseract.tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = inst.tesseract.tesseract_cmd

        return inst


# Global settings instance
settings = Settings.load()

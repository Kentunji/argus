"""Configuration loader for Argus.

Loads settings from environment variables (with .env support via python-dotenv)
and validates that required values are present. Fail fast — if config is wrong,
we surface it at startup, not mid-scan.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Config:
    """Immutable runtime configuration for Argus."""

    deepseek_api_key: str
    deepseek_base_url: str
    deepseek_model: str
    target_url: str
    max_crawl_depth: int
    scan_timeout: int
    log_level: str

    @classmethod
    def load(cls, env_file: Path | None = None) -> "Config":
        """Load configuration from environment / .env file.

        Args:
            env_file: Optional path to a .env file. Defaults to ./.env.

        Raises:
            ConfigError: If required values are missing or malformed.
        """
        if env_file is None:
            env_file = Path.cwd() / ".env"
        if env_file.exists():
            load_dotenv(env_file, override=False)

        api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
        if not api_key or api_key == "your_deepseek_api_key_here":
            raise ConfigError(
                "DEEPSEEK_API_KEY is not set. Copy .env.example to .env and add "
                "your real key from https://platform.deepseek.com"
            )

        target_url = os.getenv("TARGET_URL", "").strip()
        if not target_url:
            raise ConfigError("TARGET_URL is not set in .env")

        try:
            max_depth = int(os.getenv("MAX_CRAWL_DEPTH", "3"))
            timeout = int(os.getenv("SCAN_TIMEOUT", "300"))
        except ValueError as exc:
            raise ConfigError(f"Numeric config value is not an integer: {exc}") from exc

        return cls(
            deepseek_api_key=api_key,
            deepseek_base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com").strip(),
            deepseek_model=os.getenv("DEEPSEEK_MODEL", "deepseek-chat").strip(),
            target_url=target_url,
            max_crawl_depth=max_depth,
            scan_timeout=timeout,
            log_level=os.getenv("LOG_LEVEL", "INFO").upper().strip(),
        )

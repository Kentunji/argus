"""Configuration loader for Argus."""

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
    max_crawl_pages: int
    scan_timeout: int
    log_level: str
    seed_forms_path: Path | None
    reports_dir: Path

    @classmethod
    def load(cls, env_file: Path | None = None) -> "Config":
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
            max_pages = int(os.getenv("MAX_CRAWL_PAGES", "200"))
            timeout = int(os.getenv("SCAN_TIMEOUT", "300"))
        except ValueError as exc:
            raise ConfigError(f"Numeric config value is not an integer: {exc}") from exc

        seed_path_str = os.getenv("SEED_FORMS", "").strip()
        seed_forms_path = Path(seed_path_str) if seed_path_str else None
        if seed_forms_path and not seed_forms_path.is_absolute():
            seed_forms_path = Path.cwd() / seed_forms_path

        reports_dir = Path(os.getenv("REPORTS_DIR", "reports").strip())
        if not reports_dir.is_absolute():
            reports_dir = Path.cwd() / reports_dir

        return cls(
            deepseek_api_key=api_key,
            deepseek_base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com").strip(),
            deepseek_model=os.getenv("DEEPSEEK_MODEL", "deepseek-chat").strip(),
            target_url=target_url,
            max_crawl_depth=max_depth,
            max_crawl_pages=max_pages,
            scan_timeout=timeout,
            log_level=os.getenv("LOG_LEVEL", "INFO").upper().strip(),
            seed_forms_path=seed_forms_path,
            reports_dir=reports_dir,
        )

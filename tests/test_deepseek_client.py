"""Smoke test for the DeepSeek client.

Skipped automatically if the DeepSeek API key can't be loaded from .env
or the environment, so CI won't break without a key configured.
"""

from __future__ import annotations

import pytest

from src.config import Config, ConfigError
from src.llm.deepseek_client import DeepSeekClient


def _load_config_or_skip() -> Config:
    """Load config; if the key isn't set, skip the test cleanly."""
    try:
        config = Config.load()
    except ConfigError as exc:
        pytest.skip(f"DeepSeek not configured: {exc}")
    return config


def test_deepseek_roundtrip() -> None:
    """Send a trivial prompt and assert we get a non-empty response."""
    config = _load_config_or_skip()
    client = DeepSeekClient(config)

    response = client.analyze(
        "Respond with exactly the word: pong",
        system="You are a test echo service. Reply with exactly what the user asks.",
        temperature=0.0,
        max_tokens=10,
    )

    assert response.content, "Empty response from DeepSeek"
    assert "pong" in response.content.lower(), f"Unexpected response: {response.content!r}"
    assert response.prompt_tokens > 0
    assert response.completion_tokens > 0

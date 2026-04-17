"""DeepSeek client for Argus.

Thin wrapper around the OpenAI Python SDK pointed at DeepSeek's OpenAI-compatible
endpoint. Keeps our scanner code free of HTTP plumbing.

Usage:
    client = DeepSeekClient(config)
    answer = client.analyze("Is this a SQL injection?", context={"payload": "..."})
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from openai import OpenAI
from openai import APIError, APITimeoutError, RateLimitError

from src.config import Config
from src.logger import get_logger

log = get_logger(__name__)


@dataclass
class LLMResponse:
    """A single response from DeepSeek."""

    content: str
    model: str
    prompt_tokens: int
    completion_tokens: int


class DeepSeekClient:
    """Wrapper around the DeepSeek / OpenAI-compatible chat completions API."""

    def __init__(self, config: Config, *, max_retries: int = 3, backoff_seconds: float = 2.0) -> None:
        self._config = config
        self._max_retries = max_retries
        self._backoff = backoff_seconds
        self._client = OpenAI(
            api_key=config.deepseek_api_key,
            base_url=config.deepseek_base_url,
        )

    def analyze(
        self,
        prompt: str,
        *,
        system: str | None = None,
        context: dict[str, Any] | None = None,
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        """Send a prompt to DeepSeek and return the response.

        Args:
            prompt: The user-facing prompt.
            system: Optional system message to steer the model.
            context: Optional dict appended to the prompt as formatted key/value pairs.
            temperature: Sampling temperature (low = deterministic).
            max_tokens: Maximum tokens in the response.

        Raises:
            RuntimeError: If all retries are exhausted.
        """
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})

        user_content = prompt
        if context:
            context_block = "\n".join(f"- {k}: {v}" for k, v in context.items())
            user_content = f"{prompt}\n\nContext:\n{context_block}"
        messages.append({"role": "user", "content": user_content})

        last_error: Exception | None = None
        for attempt in range(1, self._max_retries + 1):
            try:
                response = self._client.chat.completions.create(
                    model=self._config.deepseek_model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                choice = response.choices[0].message.content or ""
                usage = response.usage
                return LLMResponse(
                    content=choice.strip(),
                    model=response.model,
                    prompt_tokens=getattr(usage, "prompt_tokens", 0),
                    completion_tokens=getattr(usage, "completion_tokens", 0),
                )
            except (APITimeoutError, RateLimitError, APIError) as exc:
                last_error = exc
                log.warning(
                    "DeepSeek call failed (attempt %d/%d): %s",
                    attempt, self._max_retries, exc,
                )
                if attempt < self._max_retries:
                    time.sleep(self._backoff * attempt)

        raise RuntimeError(f"DeepSeek request failed after {self._max_retries} retries: {last_error}")

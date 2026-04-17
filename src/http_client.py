"""Shared HTTP client for Argus.

All modules (crawler, detectors) should use this session instead of raw
`requests.get()` calls. Gives us consistent timeouts, headers, and a single
cookie jar so authenticated scans Just Work later.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests

USER_AGENT = "Argus-Scanner/0.1 (+https://github.com/Kentunji/argus)"
DEFAULT_TIMEOUT = 15  # seconds


@dataclass
class HttpResponse:
    """Minimal response wrapper; normalized so tests don't depend on requests."""

    url: str
    status_code: int
    headers: dict[str, str]
    text: str
    elapsed_ms: float


def build_session() -> requests.Session:
    """Return a pre-configured requests.Session for scanning."""
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
    )
    return session


def fetch(
    session: requests.Session,
    url: str,
    *,
    method: str = "GET",
    data: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> HttpResponse:
    """Issue a request and return a normalized HttpResponse.

    Raises:
        requests.RequestException: for network-level failures.
    """
    resp = session.request(
        method=method.upper(),
        url=url,
        data=data,
        timeout=timeout,
        allow_redirects=True,
    )
    return HttpResponse(
        url=resp.url,
        status_code=resp.status_code,
        headers={k: v for k, v in resp.headers.items()},
        text=resp.text,
        elapsed_ms=resp.elapsed.total_seconds() * 1000,
    )

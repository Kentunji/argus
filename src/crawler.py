"""Web crawler for Argus.

Breadth-first crawl of the target, staying within scope, with depth limit.
Extracts URLs and HTML forms. Forms are the raw material for vulnerability
detectors later on.

Limitations (v0.1):
- Static HTML only. JavaScript-rendered content is not visible. SPAs like
  Juice Shop will expose little through static crawling. A Playwright-based
  dynamic crawler is planned for v0.3.
- Asset files (JS, CSS, images, fonts) are skipped; they are not attack surface.
- No robots.txt respect. Targets are expected to be authorized.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup

from src.http_client import HttpResponse, build_session, fetch
from src.logger import get_logger

log = get_logger(__name__)

# Extensions that are never interesting attack surface for a web vuln scanner.
_SKIP_EXTENSIONS = {
    ".js", ".mjs", ".css", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".webm", ".mp3", ".ogg", ".wav",
    ".pdf", ".zip", ".tar", ".gz",
}


@dataclass(frozen=True)
class FormInput:
    """A single <input>, <textarea>, or <select> field from an HTML form."""

    name: str
    type: str
    value: str = ""


@dataclass(frozen=True)
class Form:
    """An HTML form discovered during crawling."""

    action: str  # absolute URL
    method: str  # "GET" or "POST"
    inputs: tuple[FormInput, ...]
    source_page: str  # URL of the page the form was found on


@dataclass
class CrawlResult:
    """Everything the crawler learned about the target."""

    target: str
    urls_visited: set[str] = field(default_factory=set)
    urls_discovered: set[str] = field(default_factory=set)
    out_of_scope_urls: set[str] = field(default_factory=set)
    skipped_assets: set[str] = field(default_factory=set)
    forms: list[Form] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)


def _same_host(a: str, b: str) -> bool:
    return urlparse(a).hostname == urlparse(b).hostname


def _normalize_url(url: str) -> str:
    """Strip fragments so /page#x and /page#y aren't treated as separate."""
    clean, _ = urldefrag(url)
    return clean.rstrip("/") or clean


def _is_asset(url: str) -> bool:
    """True if the URL's path ends with a known static-asset extension."""
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _SKIP_EXTENSIONS)


def _extract_links(html: str, base_url: str) -> list[str]:
    """Extract only <a href> links. <link rel> tags point at assets, not pages."""
    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []
    for tag in soup.find_all("a", href=True):
        absolute = urljoin(base_url, tag["href"])
        if absolute.startswith(("http://", "https://")):
            links.append(_normalize_url(absolute))
    return links


def _extract_forms(html: str, base_url: str) -> list[Form]:
    soup = BeautifulSoup(html, "html.parser")
    forms: list[Form] = []
    for form_tag in soup.find_all("form"):
        action = urljoin(base_url, form_tag.get("action") or base_url)
        method = (form_tag.get("method") or "GET").upper()
        inputs: list[FormInput] = []
        for field_tag in form_tag.find_all(["input", "textarea", "select"]):
            name = field_tag.get("name")
            if not name:
                continue
            inputs.append(
                FormInput(
                    name=name,
                    type=field_tag.get("type", field_tag.name),
                    value=field_tag.get("value", ""),
                )
            )
        forms.append(
            Form(
                action=action,
                method=method if method in ("GET", "POST") else "GET",
                inputs=tuple(inputs),
                source_page=base_url,
            )
        )
    return forms


def crawl(
    target: str,
    *,
    max_depth: int = 3,
    max_pages: int = 200,
    session: requests.Session | None = None,
) -> CrawlResult:
    """Breadth-first crawl of `target`, staying on the same host."""
    session = session or build_session()
    start = _normalize_url(target)
    result = CrawlResult(target=start)

    queue: deque[tuple[str, int]] = deque([(start, 0)])
    result.urls_discovered.add(start)

    while queue and len(result.urls_visited) < max_pages:
        url, depth = queue.popleft()
        if url in result.urls_visited:
            continue
        if _is_asset(url):
            result.skipped_assets.add(url)
            continue

        try:
            response: HttpResponse = fetch(session, url)
        except requests.RequestException as exc:
            log.warning("Fetch failed for %s: %s", url, exc)
            result.errors.append((url, str(exc)))
            continue

        result.urls_visited.add(url)
        log.info("Crawled [%d] %s (%d)", depth, url, response.status_code)

        if "text/html" not in response.headers.get("Content-Type", "").lower():
            continue

        for form in _extract_forms(response.text, response.url):
            result.forms.append(form)

        if depth >= max_depth:
            continue

        for link in _extract_links(response.text, response.url):
            if not _same_host(link, start):
                result.out_of_scope_urls.add(link)
                continue
            if _is_asset(link):
                result.skipped_assets.add(link)
                continue
            if link not in result.urls_discovered:
                result.urls_discovered.add(link)
                queue.append((link, depth + 1))

    return result

"""Tests for the crawler.

Two kinds:
1. Unit tests with mocked HTML — fast, deterministic, no network.
2. One live integration test against Juice Shop, skipped if the target
   isn't reachable on localhost:3000.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from src.crawler import _extract_forms, _extract_links, crawl


SEED_HTML = """
<!DOCTYPE html>
<html><body>
  <a href="/about">About</a>
  <a href="https://other.example.com/external">External</a>
  <a href="products/1">Relative</a>
  <a href="#fragment">Fragment only</a>
  <form action="/login" method="POST">
    <input name="email" type="email" value="">
    <input name="password" type="password">
    <input type="submit" value="Go">
  </form>
</body></html>
"""

PLAIN_HTML = "<html><body><p>Nothing interesting here.</p></body></html>"


def test_extract_links_resolves_relative_and_absolute() -> None:
    links = _extract_links(SEED_HTML, "http://target.test/")
    assert "http://target.test/about" in links
    assert "http://target.test/products/1" in links
    assert "https://other.example.com/external" in links


def test_extract_forms_captures_named_inputs_only() -> None:
    forms = _extract_forms(SEED_HTML, "http://target.test/")
    assert len(forms) == 1
    form = forms[0]
    assert form.action == "http://target.test/login"
    assert form.method == "POST"
    input_names = [i.name for i in form.inputs]
    assert input_names == ["email", "password"]  # submit has no name


def _mock_session_url_aware(responses: dict[str, str]) -> MagicMock:
    """Return a mock session whose response body depends on the requested URL.

    Any URL not in `responses` gets `PLAIN_HTML`.
    """
    session = MagicMock(spec=requests.Session)

    def _request(method, url, data=None, timeout=None, allow_redirects=True):
        body = responses.get(url.rstrip("/"), responses.get(url, PLAIN_HTML))
        resp = MagicMock()
        resp.url = url
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/html"}
        resp.text = body
        resp.elapsed.total_seconds.return_value = 0.01
        return resp

    session.request.side_effect = _request
    return session


def test_crawl_stays_in_scope() -> None:
    session = _mock_session_url_aware({"http://target.test": SEED_HTML})
    result = crawl("http://target.test/", max_depth=1, session=session)

    visited_normalized = {u.rstrip("/") for u in result.urls_visited}
    assert "http://target.test" in visited_normalized
    assert any("other.example.com" in u for u in result.out_of_scope_urls)
    # Only the seed page serves the login form; linked pages serve PLAIN_HTML.
    assert len(result.forms) == 1
    assert result.forms[0].action == "http://target.test/login"


def test_crawl_follows_multiple_pages_collects_all_forms() -> None:
    """Two pages each with their own form -> we collect both."""
    page_a = '<html><body><form action="/a" method="POST"><input name="x"></form><a href="/b">B</a></body></html>'
    page_b = '<html><body><form action="/b" method="GET"><input name="y"></form></body></html>'
    session = _mock_session_url_aware(
        {
            "http://target.test": page_a,
            "http://target.test/b": page_b,
        }
    )
    result = crawl("http://target.test/", max_depth=1, session=session)

    assert len(result.forms) == 2
    actions = {f.action for f in result.forms}
    assert actions == {"http://target.test/a", "http://target.test/b"}


def test_crawl_respects_depth_zero() -> None:
    session = _mock_session_url_aware({"http://target.test": SEED_HTML})
    result = crawl("http://target.test/", max_depth=0, session=session)

    # Only the seed page is fetched at depth 0
    assert len(result.urls_visited) == 1


def test_crawl_against_juice_shop_live() -> None:
    """Live smoke test against the Oracle-hosted Juice Shop (via SSH tunnel)."""
    try:
        requests.get("http://localhost:3000", timeout=3)
    except requests.RequestException:
        pytest.skip("Juice Shop not reachable on localhost:3000 (SSH tunnel down?)")

    result = crawl("http://localhost:3000", max_depth=1, max_pages=10)

    assert len(result.urls_visited) >= 1
    assert result.target.startswith("http://localhost:3000")
    # Juice Shop is an SPA; static crawl exposes little. Just assert no errors.

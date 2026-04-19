"""Tests for the XSS detector.

Mix of unit tests with a fake echo server (no network) and one live test
against Juice Shop. The live test does NOT assert "must find XSS" because
that depends on what the SPA exposes statically — it asserts the detector
runs cleanly end-to-end against a real target.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from src.crawler import CrawlResult, Form, FormInput, crawl
from src.detectors.xss import XSSDetector, _is_unsafe_reflection, _make_marker


def test_unsafe_reflection_detects_raw_payload() -> None:
    marker = _make_marker()
    payload = f'"><{marker}>'
    html = f"<html><body>You searched for: {payload}</body></html>"
    unsafe, reason = _is_unsafe_reflection(html, marker)
    assert unsafe
    assert "raw HTML" in reason


def test_unsafe_reflection_ignores_encoded_payload() -> None:
    marker = _make_marker()
    # Properly encoded — safe.
    html = f"<html><body>You searched for: &lt;{marker}&gt;</body></html>"
    unsafe, _reason = _is_unsafe_reflection(html, marker)
    assert not unsafe


def test_unsafe_reflection_detects_script_body() -> None:
    marker = _make_marker()
    html = f'<html><head><script>var q = "{marker}";</script></head></html>'
    unsafe, reason = _is_unsafe_reflection(html, marker)
    assert unsafe
    assert "script" in reason.lower()


def _mock_session_echo(reflect: bool) -> MagicMock:
    """Mock that echoes whatever payload it receives, encoded or not."""
    session = MagicMock(spec=requests.Session)

    def _request(method, url, data=None, timeout=None, allow_redirects=True):
        from urllib.parse import parse_qsl, urlparse
        if method == "POST" and data:
            value = next(iter(data.values()))
        else:
            qs = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
            value = next(iter(qs.values())) if qs else ""

        body = (
            f"<html><body>Echo: {value}</body></html>"
            if reflect
            else "<html><body>Nothing here</body></html>"
        )
        resp = MagicMock()
        resp.url = url
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/html"}
        resp.text = body
        resp.elapsed.total_seconds.return_value = 0.01
        return resp

    session.request.side_effect = _request
    return session


def test_xss_detector_finds_reflected_form_input() -> None:
    crawl_result = CrawlResult(target="http://target.test")
    crawl_result.forms.append(
        Form(
            action="http://target.test/search",
            method="POST",
            inputs=(FormInput(name="q", type="text"),),
            source_page="http://target.test/",
        )
    )
    session = _mock_session_echo(reflect=True)

    findings = XSSDetector().run(crawl_result, session)
    assert len(findings) == 1
    assert findings[0].evidence.parameter == "q"
    assert findings[0].id == "ARG-XSS-001"
    assert findings[0].cwe == "CWE-79"


def test_xss_detector_no_false_positive_on_safe_app() -> None:
    crawl_result = CrawlResult(target="http://target.test")
    crawl_result.forms.append(
        Form(
            action="http://target.test/search",
            method="POST",
            inputs=(FormInput(name="q", type="text"),),
            source_page="http://target.test/",
        )
    )
    session = _mock_session_echo(reflect=False)

    findings = XSSDetector().run(crawl_result, session)
    assert findings == []


def test_xss_detector_against_juice_shop_live() -> None:
    """End-to-end: crawl Juice Shop, run XSS detector, ensure no exceptions."""
    try:
        requests.get("http://localhost:3000", timeout=3)
    except requests.RequestException:
        pytest.skip("Juice Shop not reachable on localhost:3000 (SSH tunnel down?)")

    from src.http_client import build_session
    session = build_session()
    result = crawl("http://localhost:3000", max_depth=1, max_pages=10, session=session)
    findings = XSSDetector().run(result, session)
    # Static crawl of an SPA may find nothing — that's OK, we just want clean execution.
    assert isinstance(findings, list)

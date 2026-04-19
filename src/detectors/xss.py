"""Reflected XSS detector.

Strategy:
1. For every form input and URL query parameter discovered by the crawler,
   inject a unique marker payload.
2. Fetch the response.
3. If the marker is reflected unencoded into the HTML in a script-executing
   context (raw text outside of attribute encoding, inside a script tag,
   inside an event handler attribute), report it as Reflected XSS.

Payloads are inert markers, not real exploits. They prove reflection happened
without actually executing JavaScript on anyone.
"""

from __future__ import annotations

import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

from src.crawler import CrawlResult, Form
from src.detectors.base import Detector
from src.findings import Confidence, Evidence, Finding, Severity
from src.http_client import fetch
from src.logger import get_logger

log = get_logger(__name__)


def _make_marker() -> str:
    """Unique, harmless marker like 'argusXSSa1b2c3d4'."""
    return f"argusXSS{secrets.token_hex(4)}"


def _make_payload(marker: str) -> str:
    """A payload that is reflective and tells us context, but does NOT execute."""
    return f'"><{marker}>'


def _is_unsafe_reflection(html: str, marker: str) -> tuple[bool, str]:
    """Return (vulnerable, reason) — marker present unencoded means we got reflection.

    We treat any raw appearance of the marker (without HTML entity encoding)
    as evidence the input is unfiltered. A safe app would render `&lt;marker&gt;`.
    """
    if marker not in html:
        return False, ""

    # If we sent `<marker>` and we see `<marker>` raw (not `&lt;marker&gt;`), that's bad.
    payload_raw = f"<{marker}>"
    if payload_raw in html:
        return True, "Payload reflected as raw HTML element (no encoding)"

    # Marker appears but maybe encoded — check by parsing
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(True):
        # Tag name itself is the marker — extreme reflection, definitely XSS
        if tag.name == marker.lower():
            return True, "Payload reflected as a tag name"
        # Marker appears inside a <script> body
        if tag.name == "script" and tag.string and marker in tag.string:
            return True, "Payload reflected inside <script> body"
        # Marker appears as an attribute name or in an event handler
        for attr_name, attr_val in (tag.attrs or {}).items():
            if marker in str(attr_name):
                return True, "Payload reflected as an HTML attribute name"
            if attr_name.lower().startswith("on") and marker in str(attr_val):
                return True, "Payload reflected inside an event handler attribute"

    return False, ""


def _inject_into_url(url: str, param: str, value: str) -> str:
    """Return `url` with `param` set to `value` in the query string."""
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    qs[param] = value
    return urlunparse(parsed._replace(query=urlencode(qs)))


class XSSDetector(Detector):
    name = "xss"

    def run(self, crawl: CrawlResult, session: requests.Session) -> list[Finding]:
        findings: list[Finding] = []
        finding_counter = 0

        # 1) Test URL query parameters
        for url in crawl.urls_visited:
            parsed = urlparse(url)
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            for param in params:
                finding = self._probe_url_param(url, param, session)
                if finding:
                    finding_counter += 1
                    findings.append(self._with_id(finding, finding_counter))

        # 2) Test form inputs
        for form in crawl.forms:
            for inp in form.inputs:
                finding = self._probe_form_input(form, inp.name, session)
                if finding:
                    finding_counter += 1
                    findings.append(self._with_id(finding, finding_counter))

        return findings

    def _with_id(self, finding: Finding, n: int) -> Finding:
        # Re-issue the finding with a sequential ID
        return Finding(
            id=f"ARG-XSS-{n:03d}",
            detector=finding.detector,
            type=finding.type,
            severity=finding.severity,
            confidence=finding.confidence,
            cwe=finding.cwe,
            owasp=finding.owasp,
            evidence=finding.evidence,
            remediation=finding.remediation,
        )

    def _probe_url_param(self, url: str, param: str, session: requests.Session) -> Finding | None:
        marker = _make_marker()
        payload = _make_payload(marker)
        probe_url = _inject_into_url(url, param, payload)
        try:
            resp = fetch(session, probe_url)
        except requests.RequestException as exc:
            log.warning("XSS probe failed on %s: %s", probe_url, exc)
            return None

        unsafe, reason = _is_unsafe_reflection(resp.text, marker)
        if not unsafe:
            return None

        return self._build_finding(
            method="GET",
            probe_url=probe_url,
            parameter=param,
            payload=payload,
            indicator=reason,
            response=resp.text,
        )

    def _probe_form_input(
        self,
        form: Form,
        param: str,
        session: requests.Session,
    ) -> Finding | None:
        marker = _make_marker()
        payload = _make_payload(marker)

        # Build the payload dict — fill all fields with placeholders so the form is "valid"
        data = {i.name: (payload if i.name == param else (i.value or "test")) for i in form.inputs}

        try:
            if form.method == "POST":
                resp = fetch(session, form.action, method="POST", data=data)
            else:
                probe_url = form.action + ("&" if "?" in form.action else "?") + urlencode(data)
                resp = fetch(session, probe_url)
        except requests.RequestException as exc:
            log.warning("XSS form probe failed on %s: %s", form.action, exc)
            return None

        unsafe, reason = _is_unsafe_reflection(resp.text, marker)
        if not unsafe:
            return None

        return self._build_finding(
            method=form.method,
            probe_url=form.action,
            parameter=param,
            payload=payload,
            indicator=reason,
            response=resp.text,
        )

    def _build_finding(
        self,
        *,
        method: str,
        probe_url: str,
        parameter: str,
        payload: str,
        indicator: str,
        response: str,
    ) -> Finding:
        # Snippet around the marker for the report
        snippet = response[:200] if len(response) <= 200 else response[:200] + "..."

        evidence = Evidence(
            method=method,
            url=probe_url,
            parameter=parameter,
            payload=payload,
            indicator=indicator,
            response_snippet=snippet,
        )
        return Finding(
            id="",  # set by run()
            detector=self.name,
            type="Reflected Cross-Site Scripting (XSS)",
            severity=Severity.HIGH,
            confidence=Confidence.LIKELY,
            cwe="CWE-79",
            owasp="A03:2021 Injection",
            evidence=evidence,
            remediation=(
                "Encode untrusted input on output. Use context-aware encoding "
                "(HTML body, attribute, JavaScript, URL). Consider a strict "
                "Content-Security-Policy with no unsafe-inline scripts."
            ),
        )

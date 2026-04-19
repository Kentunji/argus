"""Security headers + cookie flags audit.

Single GET request per target URL — checks the response for missing or
weak security headers and insecure cookie flags. No payloads, no injection,
no destructive behavior.

Maps to:
- OWASP A02:2021 Cryptographic Failures (HSTS missing on HTTPS)
- OWASP A05:2021 Security Misconfiguration (CSP, X-Frame-Options, etc.)
- CWE-693 Protection Mechanism Failure
- CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag
- CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
"""

from __future__ import annotations

from urllib.parse import urlparse

import requests
from http.cookies import SimpleCookie

from src.crawler import CrawlResult
from src.detectors.base import Detector
from src.findings import Confidence, Evidence, Finding, Severity
from src.http_client import fetch
from src.logger import get_logger

log = get_logger(__name__)


# Header → (severity, recommendation, what-to-look-for)
_HEADER_CHECKS: list[tuple[str, Severity, str, str, str]] = [
    (
        "Content-Security-Policy",
        Severity.MEDIUM,
        "CWE-693",
        "A05:2021 Security Misconfiguration",
        "Define a strict CSP. At minimum: default-src 'self'; avoid 'unsafe-inline' and 'unsafe-eval'.",
    ),
    (
        "Strict-Transport-Security",
        Severity.MEDIUM,
        "CWE-319",
        "A02:2021 Cryptographic Failures",
        "Add HSTS: 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    ),
    (
        "X-Frame-Options",
        Severity.LOW,
        "CWE-1021",
        "A05:2021 Security Misconfiguration",
        "Set 'X-Frame-Options: DENY' or use CSP 'frame-ancestors' to prevent clickjacking.",
    ),
    (
        "X-Content-Type-Options",
        Severity.LOW,
        "CWE-79",
        "A05:2021 Security Misconfiguration",
        "Set 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.",
    ),
    (
        "Referrer-Policy",
        Severity.LOW,
        "CWE-200",
        "A05:2021 Security Misconfiguration",
        "Set 'Referrer-Policy: strict-origin-when-cross-origin' or stricter to limit referrer leakage.",
    ),
    (
        "Permissions-Policy",
        Severity.INFO,
        "CWE-693",
        "A05:2021 Security Misconfiguration",
        "Define a Permissions-Policy to disable unused browser features (camera, microphone, geolocation, etc.).",
    ),
]


def _hsts_only_matters_on_https(url: str) -> bool:
    return urlparse(url).scheme == "https"


def _parse_cookie_flags(set_cookie: str) -> dict[str, dict[str, str | bool]]:
    """Parse a Set-Cookie header (possibly with multiple cookies) into name -> flags."""
    cookies: dict[str, dict[str, str | bool]] = {}
    # Set-Cookie can have multiple cookies separated by commas, but commas can also
    # appear in date values. Use SimpleCookie to handle the common case.
    sc: SimpleCookie = SimpleCookie()
    try:
        sc.load(set_cookie)
    except Exception:
        return cookies

    for name, morsel in sc.items():
        cookies[name] = {
            "secure": bool(morsel["secure"]),
            "httponly": bool(morsel["httponly"]),
            "samesite": morsel["samesite"] or "",
        }
    return cookies


class HeadersDetector(Detector):
    name = "headers"

    def run(self, crawl: CrawlResult, session: requests.Session) -> list[Finding]:
        findings: list[Finding] = []
        counter = 0
        # We only audit the seed target; checking every URL would create
        # noisy duplicate findings. The seed page is representative.
        target = crawl.target
        try:
            resp = fetch(session, target)
        except requests.RequestException as exc:
            log.warning("Headers audit failed for %s: %s", target, exc)
            return findings

        # ─── Header checks ──────────────────────────────────────────
        for header, severity, cwe, owasp, remediation in _HEADER_CHECKS:
            if header == "Strict-Transport-Security" and not _hsts_only_matters_on_https(target):
                continue
            if header in resp.headers:
                continue  # present, skip — could deepen this later (e.g. weak CSP detection)
            counter += 1
            findings.append(
                self._make_finding(
                    counter,
                    type_label=f"Missing security header: {header}",
                    severity=severity,
                    cwe=cwe,
                    owasp=owasp,
                    url=target,
                    indicator=f"Response did not include the {header} header",
                    response_snippet=str(dict(resp.headers))[:300],
                    remediation=remediation,
                    parameter=header,
                )
            )

        # ─── Cookie checks ──────────────────────────────────────────
        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie:
            cookies = _parse_cookie_flags(set_cookie)
            for name, flags in cookies.items():
                cookie_findings = self._audit_cookie(name, flags, target)
                for f in cookie_findings:
                    counter += 1
                    findings.append(self._renumber(f, counter))

        return findings

    def _audit_cookie(self, name: str, flags: dict, url: str) -> list[Finding]:
        out: list[Finding] = []
        is_https = urlparse(url).scheme == "https"

        if is_https and not flags.get("secure"):
            out.append(
                self._make_finding(
                    0,
                    type_label=f"Cookie '{name}' missing Secure flag",
                    severity=Severity.MEDIUM,
                    cwe="CWE-614",
                    owasp="A02:2021 Cryptographic Failures",
                    url=url,
                    indicator=f"Cookie '{name}' set without Secure flag on an HTTPS response",
                    response_snippet=f"Set-Cookie: {name}=...; (no Secure)",
                    remediation="Add the 'Secure' attribute so the cookie is only sent over HTTPS.",
                    parameter=name,
                )
            )

        if not flags.get("httponly"):
            out.append(
                self._make_finding(
                    0,
                    type_label=f"Cookie '{name}' missing HttpOnly flag",
                    severity=Severity.MEDIUM,
                    cwe="CWE-1004",
                    owasp="A05:2021 Security Misconfiguration",
                    url=url,
                    indicator=f"Cookie '{name}' set without HttpOnly flag — accessible to JavaScript",
                    response_snippet=f"Set-Cookie: {name}=...; (no HttpOnly)",
                    remediation="Add the 'HttpOnly' attribute to prevent JavaScript from reading the cookie.",
                    parameter=name,
                )
            )

        if not flags.get("samesite"):
            out.append(
                self._make_finding(
                    0,
                    type_label=f"Cookie '{name}' missing SameSite attribute",
                    severity=Severity.LOW,
                    cwe="CWE-352",
                    owasp="A05:2021 Security Misconfiguration",
                    url=url,
                    indicator=f"Cookie '{name}' set without SameSite — vulnerable to CSRF in some contexts",
                    response_snippet=f"Set-Cookie: {name}=...; (no SameSite)",
                    remediation="Add 'SameSite=Lax' or 'SameSite=Strict' depending on cross-site requirements.",
                    parameter=name,
                )
            )

        return out

    def _make_finding(
        self,
        n: int,
        *,
        type_label: str,
        severity: Severity,
        cwe: str,
        owasp: str,
        url: str,
        indicator: str,
        response_snippet: str,
        remediation: str,
        parameter: str,
    ) -> Finding:
        return Finding(
            id=f"ARG-HDR-{n:03d}" if n else "",
            detector=self.name,
            type=type_label,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            cwe=cwe,
            owasp=owasp,
            evidence=Evidence(
                method="GET",
                url=url,
                parameter=parameter,
                payload="(none)",
                indicator=indicator,
                response_snippet=response_snippet,
            ),
            remediation=remediation,
        )

    def _renumber(self, finding: Finding, n: int) -> Finding:
        return Finding(
            id=f"ARG-HDR-{n:03d}",
            detector=finding.detector,
            type=finding.type,
            severity=finding.severity,
            confidence=finding.confidence,
            cwe=finding.cwe,
            owasp=finding.owasp,
            evidence=finding.evidence,
            remediation=finding.remediation,
        )

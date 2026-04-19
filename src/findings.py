"""Finding — the universal output type for all detectors.

Every detector returns a list of these. The reporter consumes them. Keeping
this dataclass small and consistent is what lets v0.2/v0.3 add new detectors
without changing the report layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    UNCERTAIN = "uncertain"
    LIKELY = "likely"
    CONFIRMED = "confirmed"


@dataclass(frozen=True)
class Evidence:
    """The proof Argus collected for a finding."""

    method: str            # GET, POST, etc.
    url: str               # The URL probed
    parameter: str         # The vulnerable parameter / form field
    payload: str           # What we sent
    indicator: str         # Why we think this is a vulnerability
    response_snippet: str  # ~200 chars of the response showing the issue


@dataclass(frozen=True)
class Finding:
    """A single security finding produced by a detector."""

    id: str                # e.g. "ARG-001"
    detector: str          # which detector produced this (e.g. "xss")
    type: str              # human-readable type, e.g. "Reflected XSS"
    severity: Severity
    confidence: Confidence
    cwe: str               # e.g. "CWE-79"
    owasp: str             # e.g. "A03:2021 Injection"
    evidence: Evidence
    remediation: str       # short remediation suggestion
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

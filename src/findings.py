"""Finding — the universal output type for all detectors."""

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

    method: str
    url: str
    parameter: str
    payload: str
    indicator: str
    response_snippet: str


@dataclass(frozen=True)
class Triage:
    """LLM-generated analysis attached to a finding.

    The detector provides raw evidence; triage adds human-readable context
    and a tailored remediation that goes beyond generic advice.
    """

    confidence: Confidence          # LLM's independent confidence rating
    explanation: str                # plain-English why this matters
    tailored_remediation: str       # specific fix (often with code snippet)
    is_false_positive: bool = False # LLM's false-positive flag
    model: str = ""                 # which model produced this


@dataclass(frozen=True)
class Finding:
    """A single security finding produced by a detector."""

    id: str
    detector: str
    type: str
    severity: Severity
    confidence: Confidence
    cwe: str
    owasp: str
    evidence: Evidence
    remediation: str
    triage: Triage | None = None
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

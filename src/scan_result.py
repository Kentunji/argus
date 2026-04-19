"""ScanResult — what the orchestrator produces, what reporters consume."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.findings import Finding


@dataclass
class ScanResult:
    target: str
    started_at: datetime
    completed_at: datetime | None = None
    findings: list[Finding] = field(default_factory=list)
    urls_visited: int = 0
    forms_tested: int = 0
    detectors_run: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        if not self.completed_at:
            return 0.0
        return (self.completed_at - self.started_at).total_seconds()

    @property
    def finding_count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts


def now_utc() -> datetime:
    return datetime.now(timezone.utc)

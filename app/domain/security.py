"""Security-monitoring domain types: audit records, alerts, and detector contract.

Pure Python — no FastAPI, SQLAlchemy, or ML libraries — so detectors stay swappable.
"""

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol, Sequence


class Action(StrEnum):
    """Audit action names shared by event writers and detectors."""

    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILURE = "auth.login.failure"
    ACCESS_DENIED = "access.denied"
    PII_READ = "pii.read"
    PII_UPDATED = "pii.updated"
    GRADE_CREATED = "grade.created"
    CERT_ISSUED = "certificate.issued"
    CERT_INVALID = "certificate.invalid"


class Severity(StrEnum):
    """Alert severity levels."""

    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = {Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


@dataclass(frozen=True)
class AuditRecord:
    """One audit event, independent of the ORM model."""

    timestamp: datetime
    action: str
    actor_user_id: int | None = None
    resource_type: str = ""
    resource_id: str | None = None
    ip_address: str | None = None
    outcome: str = "success"

    @property
    def entity(self) -> str:
        """Primary subject: the authenticated user when known, otherwise the source IP."""
        if self.actor_user_id is not None:
            return f"user:{self.actor_user_id}"
        if self.ip_address:
            return f"ip:{self.ip_address}"
        return "unknown"


@dataclass(frozen=True)
class SecurityAlert:
    """A detector finding; `rule` is a stable code the UI can translate."""

    rule: str
    severity: Severity
    entity: str
    window_start: datetime
    window_end: datetime
    count: int
    description: str
    score: float | None = None
    details: dict[str, float] = field(default_factory=dict)
    ml_corroborated: bool = False


class AnomalyDetector(Protocol):
    """Contract implemented by rule-based and ML detectors."""

    def detect(self, events: Sequence[AuditRecord]) -> list[SecurityAlert]: ...


def _overlap(a: SecurityAlert, b: SecurityAlert, slack: timedelta) -> bool:
    return a.window_start <= b.window_end + slack and b.window_start <= a.window_end + slack


def merge_alerts(rule_alerts: Sequence[SecurityAlert], ml_alerts: Sequence[SecurityAlert],
                 slack: timedelta = timedelta(minutes=5)) -> list[SecurityAlert]:
    """Combine detectors: an ML alert overlapping a rule alert for the same entity only corroborates it."""
    merged = list(rule_alerts)
    extra: list[SecurityAlert] = []
    for ml in ml_alerts:
        hit = next((i for i, r in enumerate(merged) if r.entity == ml.entity and _overlap(r, ml, slack)), None)
        if hit is None:
            extra.append(ml)
        else:
            merged[hit] = replace(merged[hit], ml_corroborated=True, score=ml.score)
    result = merged + extra
    result.sort(key=lambda a: (-SEVERITY_ORDER[a.severity], -a.window_end.timestamp()))
    return result

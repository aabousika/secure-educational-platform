"""Incident-level precision/recall for detector output against labelled simulated attacks."""

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Sequence

from app.domain.security import SecurityAlert
from app.infrastructure.security.ml.simulation import Incident


@dataclass
class Metrics:
    """Counts needed to derive precision, recall, and F1 (poolable across runs)."""

    alerts: int = 0
    tp_alerts: int = 0
    incidents: int = 0
    caught: int = 0
    per_kind: dict[str, list[int]] = field(default_factory=dict)   # kind -> [caught, total]
    false_positives: list[SecurityAlert] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp_alerts / self.alerts if self.alerts else float("nan")

    @property
    def recall(self) -> float:
        return self.caught / self.incidents if self.incidents else float("nan")

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 0.0 if p != p or r != r or p + r == 0 else 2 * p * r / (p + r)

    def add(self, other: "Metrics") -> None:
        self.alerts += other.alerts
        self.tp_alerts += other.tp_alerts
        self.incidents += other.incidents
        self.caught += other.caught
        self.false_positives += other.false_positives
        for kind, (c, n) in other.per_kind.items():
            cur = self.per_kind.setdefault(kind, [0, 0])
            cur[0] += c
            cur[1] += n


def evaluate(alerts: Sequence[SecurityAlert], incidents: Sequence[Incident],
             slack: timedelta = timedelta(minutes=6)) -> Metrics:
    """An alert is a true positive if it names an entity of an incident and overlaps it in time."""
    def hit(a: SecurityAlert, inc: Incident) -> bool:
        return a.entity in inc.entities and a.window_start <= inc.end + slack and inc.start - slack <= a.window_end

    m = Metrics(alerts=len(alerts), incidents=len(incidents))
    for a in alerts:
        if any(hit(a, i) for i in incidents):
            m.tp_alerts += 1
        else:
            m.false_positives.append(a)
    for inc in incidents:
        caught = any(hit(a, inc) for a in alerts)
        m.caught += caught
        cur = m.per_kind.setdefault(inc.kind, [0, 0])
        cur[0] += caught
        cur[1] += 1
    return m

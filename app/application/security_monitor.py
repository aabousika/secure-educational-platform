"""Run rule-based and kNN-distance detectors over the audit log and merge their alerts."""

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import numpy as np
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.security import AuditRecord, SecurityAlert, merge_alerts
from app.infrastructure.database.models import AuditEventModel
from app.infrastructure.security.ml.features import build_windows
from app.infrastructure.security.ml.knn_detector import KnnDistanceDetector
from app.infrastructure.security.ml.rules import RuleBasedDetector
from app.infrastructure.security.ml.simulation import TrafficSimulator

BASELINE_DAYS = 14
MIN_BASELINE_WINDOWS = 400       # below this, the baseline is padded with synthetic benign windows (cold start)
MODEL_TTL_SECONDS = 600
MAX_EVENTS = 200_000
_SIM_EPOCH = datetime(2026, 1, 5, tzinfo=timezone.utc)


@dataclass
class SecurityReport:
    """Result of one analysis run."""

    generated_at: datetime
    hours: int
    events_analyzed: int
    baseline_windows: int
    synthetic_windows: int
    alerts: list[SecurityAlert] = field(default_factory=list)


def _to_record(row: AuditEventModel) -> AuditRecord:
    ts = row.created_at if row.created_at.tzinfo else row.created_at.replace(tzinfo=timezone.utc)
    return AuditRecord(ts, row.action, row.actor_user_id, row.resource_type, row.resource_id,
                       row.ip_address, row.outcome)


class SecurityMonitorService:
    """Stateless analysis over the audit table; the trained model is cached briefly in memory."""

    def __init__(self) -> None:
        self._rules = RuleBasedDetector()
        self._lock = threading.Lock()
        self._cached: tuple[float, KnnDistanceDetector, tuple[int, int]] | None = None

    def _model_for(self, baseline: list[AuditRecord]):
        with self._lock:
            if self._cached and time.monotonic() < self._cached[0]:
                return self._cached[1], self._cached[2]
            _, real = build_windows(baseline)
            X, synthetic = real, 0
            if len(real) < MIN_BASELINE_WINDOWS:
                _, pool = build_windows(TrafficSimulator(seed=1).normal(_SIM_EPOCH, BASELINE_DAYS))
                synthetic = min(MIN_BASELINE_WINDOWS - len(real), len(pool))
                pick = pool[np.random.default_rng(0).choice(len(pool), synthetic, replace=False)]
                X = np.vstack([real, pick]) if len(real) else pick
            model = KnnDistanceDetector().fit_windows(X)
            self._cached = (time.monotonic() + MODEL_TTL_SECONDS, model, (len(real), synthetic))
            return model, self._cached[2]

    def analyze(self, db: Session, hours: int = 24, now: datetime | None = None) -> SecurityReport:
        """Detect anomalies in the last `hours`, learning the baseline from the preceding two weeks."""
        now = now or datetime.now(timezone.utc)
        since = now - timedelta(hours=hours)
        rows = db.scalars(select(AuditEventModel)
                          .where(AuditEventModel.created_at >= since - timedelta(days=BASELINE_DAYS))
                          .order_by(AuditEventModel.created_at).limit(MAX_EVENTS))
        records = [_to_record(r) for r in rows]
        recent = [r for r in records if r.timestamp >= since]
        baseline = [r for r in records if r.timestamp < since]
        model, (real_n, synth_n) = self._model_for(baseline)
        alerts = merge_alerts(self._rules.detect(recent), model.detect(recent))
        return SecurityReport(now, hours, len(recent), real_n, synth_n, alerts)

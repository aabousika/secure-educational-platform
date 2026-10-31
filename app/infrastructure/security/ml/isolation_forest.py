"""Unsupervised Isolation Forest over per-entity activity windows."""

from datetime import timedelta
from typing import Sequence

import numpy as np
from sklearn.ensemble import IsolationForest

from app.domain.security import AuditRecord, SecurityAlert, Severity
from app.infrastructure.security.ml.features import ACTIVITY_IDX, FEATURES, WINDOW_MINUTES, best_per_episode, build_windows


class IsolationForestDetector:
    """Flags windows whose feature combination is rare compared with the training baseline."""

    def __init__(self, contamination: float = 0.01, n_estimators: int = 200, min_events: int = 3,
                 window_minutes: int = WINDOW_MINUTES, random_state: int = 42) -> None:
        self.min_events, self.window_minutes = min_events, window_minutes
        self._model = IsolationForest(n_estimators=n_estimators, contamination=contamination,
                                      random_state=random_state)
        self._mu = self._sd = None

    @property
    def fitted(self) -> bool:
        return self._mu is not None

    def fit_windows(self, X: np.ndarray) -> "IsolationForestDetector":
        """Fit on a matrix of baseline (mostly benign) windows."""
        self._model.fit(X)
        self._mu, self._sd = X.mean(axis=0), X.std(axis=0) + 1e-6
        return self

    def detect(self, events: Sequence[AuditRecord]) -> list[SecurityAlert]:
        if not self.fitted:
            raise RuntimeError("Detector must be fitted before use")
        keys, X = build_windows(events, self.window_minutes)
        if len(X) == 0:
            return []
        flagged, scores = self._model.predict(X) == -1, self._model.score_samples(X)
        z = (X - self._mu) / self._sd
        candidates = [(e, s, float(-scores[i]), i) for i, (e, s) in enumerate(keys)
                      if flagged[i] and X[i, ACTIVITY_IDX].sum() >= self.min_events]
        alerts = []
        for i in best_per_episode(candidates):
            entity = keys[i][0]
            top = sorted(range(len(FEATURES)), key=lambda c: -z[i, c])[:3]
            details = {FEATURES[c]: float(X[i, c]) for c in top if z[i, c] > 0 and X[i, c] > 0}
            start = keys[i][1]
            alerts.append(SecurityAlert(
                "ml_anomaly", Severity.MEDIUM, entity, start, start + timedelta(minutes=self.window_minutes),
                int(X[i, ACTIVITY_IDX].sum()), "Unusual activity pattern compared with the learned baseline",
                score=round(float(-scores[i]), 3), details=details))
        return alerts

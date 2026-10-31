"""Distance-based novelty detector: how far is this window from anything seen in the baseline?

Unlike Isolation Forest, distances keep growing for values far beyond the training range, so volume
spikes of a kind the rules do not cover (e.g. certificate flooding) are still flagged.
"""

from datetime import timedelta
from typing import Sequence

import numpy as np
from sklearn.neighbors import NearestNeighbors

from app.domain.security import AuditRecord, SecurityAlert, Severity
from app.infrastructure.security.ml.features import ACTIVITY_IDX, FEATURES, WINDOW_MINUTES, best_per_episode, build_windows


class KnnDistanceDetector:
    """Score = distance to the k-th nearest baseline window (log1p space) / learned threshold."""

    def __init__(self, k: int = 10, quantile: float = 0.995, min_distance: float = 1.0, min_events: int = 3,
                 window_minutes: int = WINDOW_MINUTES) -> None:
        self.k, self.quantile, self.min_distance = k, quantile, min_distance
        self.min_events, self.window_minutes = min_events, window_minutes
        self._nn = self._threshold = self._mu = self._sd = None

    @property
    def fitted(self) -> bool:
        return self._nn is not None

    def fit_windows(self, X: np.ndarray) -> "KnnDistanceDetector":
        """Learn the baseline; the threshold is a high quantile of leave-one-out k-NN distances."""
        Z = np.log1p(X)
        self._nn = NearestNeighbors(n_neighbors=self.k + 1).fit(Z)
        loo = self._nn.kneighbors(Z)[0][:, self.k]               # column 0 is the point itself
        self._threshold = max(float(np.quantile(loo, self.quantile)), self.min_distance)
        self._mu, self._sd = X.mean(axis=0), X.std(axis=0) + 1e-6
        return self

    def detect(self, events: Sequence[AuditRecord]) -> list[SecurityAlert]:
        if not self.fitted:
            raise RuntimeError("Detector must be fitted before use")
        keys, X = build_windows(events, self.window_minutes)
        if len(X) == 0:
            return []
        dist = self._nn.kneighbors(np.log1p(X), n_neighbors=self.k)[0][:, -1]
        ratio, z = dist / self._threshold, (X - self._mu) / self._sd
        flagged = [(e, s, float(ratio[i]), i) for i, (e, s) in enumerate(keys)
                   if ratio[i] >= 1.0 and X[i, ACTIVITY_IDX].sum() >= self.min_events]
        alerts = []
        for i in best_per_episode(flagged):
            entity = keys[i][0]
            top = sorted(range(len(FEATURES)), key=lambda c: -z[i, c])[:3]
            details = {FEATURES[c]: float(X[i, c]) for c in top if z[i, c] > 0 and X[i, c] > 0}
            start = keys[i][1]
            alerts.append(SecurityAlert(
                "ml_anomaly", Severity.MEDIUM, entity, start, start + timedelta(minutes=self.window_minutes),
                int(X[i, ACTIVITY_IDX].sum()), "Activity far from anything seen in the learned baseline",
                score=round(float(ratio[i]), 2), details=details))
        return alerts

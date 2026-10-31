"""Turn audit events into fixed-size numeric feature windows (entity x 5-minute bin)."""

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Iterable

import numpy as np

from app.domain.security import Action, AuditRecord

WINDOW_MINUTES = 5
FEATURES = ("login_fail", "login_ok", "login_targets", "denied", "pii_read", "pii_targets",
            "grade_created", "pii_updated", "cert_issued", "cert_invalid")
_IDX = {name: i for i, name in enumerate(FEATURES)}
ACTIVITY_IDX = [_IDX[n] for n in ("login_fail", "login_ok", "denied", "pii_read",
                                  "grade_created", "pii_updated", "cert_issued", "cert_invalid")]
_ACTION_FEATURE = {
    Action.LOGIN_FAILURE.value: "login_fail", Action.LOGIN_SUCCESS.value: "login_ok",
    Action.ACCESS_DENIED.value: "denied", Action.PII_READ.value: "pii_read",
    Action.GRADE_CREATED.value: "grade_created", Action.PII_UPDATED.value: "pii_updated",
    Action.CERT_ISSUED.value: "cert_issued", Action.CERT_INVALID.value: "cert_invalid",
}


def bin_start(ts: datetime, minutes: int = WINDOW_MINUTES) -> datetime:
    """Floor a timestamp to its tumbling-window start (UTC)."""
    secs = int(ts.timestamp())
    return datetime.fromtimestamp(secs - secs % (minutes * 60), tz=timezone.utc)


def best_per_episode(candidates: list[tuple[str, datetime, float, int]],
                     gap: timedelta = timedelta(minutes=30)) -> list[int]:
    """From flagged (entity, window_start, strength, row_index), keep the strongest row per entity episode.

    Windows of one entity less than `gap` apart belong to one episode, so separate incidents stay separate.
    """
    chosen: list[int] = []
    current = None                                                # [entity, last_start, strength, index]
    for entity, start, strength, idx in sorted(candidates, key=lambda c: (c[0], c[1])):
        if current and current[0] == entity and start - current[1] <= gap:
            current[1] = start
            if strength > current[2]:
                current[2], current[3] = strength, idx
        else:
            if current:
                chosen.append(current[3])
            current = [entity, start, strength, idx]
    if current:
        chosen.append(current[3])
    return chosen


def build_windows(events: Iterable[AuditRecord], minutes: int = WINDOW_MINUTES):
    """Return (keys, X): keys are (entity, window_start); X has one FEATURES row per key."""
    cells: dict[tuple[str, datetime], dict] = {}
    for ev in events:
        feat = _ACTION_FEATURE.get(ev.action)
        if feat is None:
            continue
        cell = cells.setdefault((ev.entity, bin_start(ev.timestamp, minutes)),
                                {"n": Counter(), "login": set(), "pii": set()})
        cell["n"][feat] += 1
        if feat == "login_fail":
            cell["login"].add(ev.resource_id)
        elif feat == "pii_read":
            cell["pii"].add(ev.resource_id)
    keys = sorted(cells)
    X = np.zeros((len(keys), len(FEATURES)))
    for row, key in enumerate(keys):
        cell = cells[key]
        for name, value in cell["n"].items():
            X[row, _IDX[name]] = value
        X[row, _IDX["login_targets"]] = len(cell["login"])
        X[row, _IDX["pii_targets"]] = len(cell["pii"])
    return keys, X

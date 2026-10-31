"""High-precision, explainable rules over sliding time windows."""

from bisect import bisect_left
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Sequence

from app.domain.security import Action, AuditRecord, SecurityAlert, Severity


@dataclass(frozen=True)
class Thresholds:
    """Tunable limits; defaults assume a small campus platform."""

    window_minutes: int = 5
    brute_force_ip: int = 8            # failed logins from one IP
    brute_force_account: int = 6       # failed logins against one account (any IPs)
    stuffing_accounts: int = 8         # distinct accounts failing from one IP
    takeover_failures: int = 5         # failures before a success from the same IP
    takeover_lookback_minutes: int = 10
    idor_denied: int = 5               # denied accesses by one user
    mass_pii_targets: int = 15         # distinct students' PII read by one user
    grade_burst: int = 20              # grades created by one user


def find_episodes(items: list[tuple[datetime, object]], width: timedelta, threshold: int,
                  distinct: bool = False) -> list[tuple[int, datetime, datetime]]:
    """Sliding-window scan returning (peak_count, start, end) per episode where the count reaches `threshold`.

    Consecutive qualifying windows merge into one episode, so two attacks hours apart yield two alerts.
    `distinct` counts unique keys instead of events.
    """
    items = sorted(items, key=lambda x: x[0])
    live: Counter = Counter()
    episodes: list[list] = []
    j = 0
    for i, (t, key) in enumerate(items):
        live[key] += 1
        while t - items[j][0] > width:
            old = items[j][1]
            live[old] -= 1
            if live[old] == 0:
                del live[old]
            j += 1
        n = len(live) if distinct else i - j + 1
        if n >= threshold:
            if episodes and t - episodes[-1][2] <= width:
                episodes[-1][0], episodes[-1][2] = max(episodes[-1][0], n), t
            else:
                episodes.append([n, items[j][0], t])
    return [tuple(e) for e in episodes]


class RuleBasedDetector:
    """Detect brute force, stuffing, takeover, IDOR probing, PII harvesting, grade bursts, bad signatures."""

    def __init__(self, thresholds: Thresholds | None = None) -> None:
        self.t = thresholds or Thresholds()

    def detect(self, events: Sequence[AuditRecord]) -> list[SecurityAlert]:
        t, width = self.t, timedelta(minutes=self.t.window_minutes)
        fail_ip, fail_acct = defaultdict(list), defaultdict(list)
        successes: list[tuple[datetime, str, str | None]] = []
        denied, pii, grades = defaultdict(list), defaultdict(list), defaultdict(list)
        invalid: dict[str, list[datetime]] = defaultdict(list)
        for ev in events:
            if ev.action == Action.LOGIN_FAILURE:
                if ev.ip_address:
                    fail_ip[ev.ip_address].append((ev.timestamp, ev.resource_id))
                fail_acct[ev.resource_id].append((ev.timestamp, ev.ip_address))
            if ev.action == Action.LOGIN_SUCCESS and ev.resource_id:
                successes.append((ev.timestamp, ev.resource_id, ev.ip_address))
            elif ev.action == Action.ACCESS_DENIED:
                denied[ev.entity].append((ev.timestamp, ev.resource_id))
            elif ev.action == Action.PII_READ:
                pii[ev.entity].append((ev.timestamp, ev.resource_id))
            elif ev.action == Action.GRADE_CREATED:
                grades[ev.entity].append((ev.timestamp, ev.resource_id))
            elif ev.action == Action.CERT_INVALID:
                invalid[str(ev.resource_id)].append(ev.timestamp)

        alerts: list[SecurityAlert] = []

        def add(rule, sev, entity, n, s, e, desc):
            alerts.append(SecurityAlert(rule, sev, entity, s, e, int(n), desc))

        brute_ips: set[str] = set()
        for ip, items in fail_ip.items():                       # R3 stuffing takes precedence over R1
            stuffing = find_episodes(items, width, t.stuffing_accounts, distinct=True)
            for n, s, e in stuffing:
                add("credential_stuffing", Severity.HIGH, f"ip:{ip}", n, s, e,
                    f"{n} different accounts failed to log in from one IP within {t.window_minutes} min")
            if stuffing:
                continue
            for n, s, e in find_episodes(items, width, t.brute_force_ip):
                brute_ips.add(ip)
                add("brute_force_ip", Severity.HIGH, f"ip:{ip}", n, s, e,
                    f"{n} failed logins from one IP within {t.window_minutes} min")

        for acct, items in fail_acct.items():                   # R2 distributed attack on one account
            for n, s, e in find_episodes(items, width, t.brute_force_account):
                ips = {ip for ts, ip in items if s <= ts <= e}
                if len(ips) == 1 and next(iter(ips)) in brute_ips:
                    continue                                    # already reported as brute_force_ip
                add("brute_force_account", Severity.HIGH, f"account:{acct}", n, s, e,
                    f"{n} failed logins against one account from {len(ips)} IP(s) within {t.window_minutes} min")

        lookback = timedelta(minutes=t.takeover_lookback_minutes)
        fail_times = {acct: sorted(ts for ts, _ in items) for acct, items in fail_acct.items()}
        best_by_acct: dict[str, tuple] = {}
        for ts, acct, ip in successes:                          # R4 success right after failures on the SAME account
            fails = fail_times.get(acct, [])
            lo, hi = bisect_left(fails, ts - lookback), bisect_left(fails, ts)
            if hi - lo >= t.takeover_failures and (acct not in best_by_acct or hi - lo > best_by_acct[acct][0]):
                best_by_acct[acct] = (hi - lo, fails[lo], ts)
        for acct, best in best_by_acct.items():
            add("account_takeover", Severity.CRITICAL, f"account:{acct}", *best,
                f"Successful login right after {best[0]} failed attempts on the same account")

        for user, items in denied.items():                      # R5
            for n, s, e in find_episodes(items, width, t.idor_denied):
                add("idor_probe", Severity.HIGH, user, n, s, e,
                    f"{n} denied access attempts to other users' data within {t.window_minutes} min")
        for user, items in pii.items():                         # R6
            for n, s, e in find_episodes(items, width, t.mass_pii_targets, distinct=True):
                add("mass_pii_access", Severity.HIGH, user, n, s, e,
                    f"PII of {n} different students read within {t.window_minutes} min")
        for user, items in grades.items():                      # R7
            for n, s, e in find_episodes(items, width, t.grade_burst):
                add("grade_burst", Severity.MEDIUM, user, n, s, e,
                    f"{n} grades created within {t.window_minutes} min")
        for cert_id, times in invalid.items():                  # R8
            add("certificate_tamper", Severity.CRITICAL, f"certificate:{cert_id}", len(times),
                min(times), max(times), "Certificate failed digital-signature verification")
        return alerts

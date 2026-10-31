"""Synthetic audit traffic: benign behaviour plus labelled attack scenarios.

Every simulated event uses an IP from the RFC 5737 documentation ranges, so rows seeded into a real
database are recognisable and can be purged.
"""

import hashlib
import random
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.domain.security import Action, AuditRecord

TEST_NET_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
CAMPUS_IP = "192.0.2.10"
ATTACK_KINDS = ("brute_force", "credential_stuffing", "distributed_brute_force", "idor_probe",
                "mass_pii_harvest", "grade_burst", "cert_tamper", "slow_brute_force",
                "cert_flood", "pii_overwrite")   # last two: patterns no hand-written rule covers


@dataclass(frozen=True)
class Incident:
    """Ground-truth attack: which entities it touches and when."""

    kind: str
    entities: frozenset[str]
    start: datetime
    end: datetime


def acct_hash(user_id: int) -> str:
    """Stand-in for the HMAC pseudonym the real login audit stores instead of the e-mail."""
    return hashlib.sha256(f"acct:{user_id}".encode()).hexdigest()[:16]


class TrafficSimulator:
    """Deterministic (seeded) generator of benign traffic and labelled attacks."""

    def __init__(self, seed: int = 0, student_ids=None, instructor_ids=None, target_ids=None,
                 n_students: int = 120, n_instructors: int = 4) -> None:
        self.rng = random.Random(seed)
        self.students = list(student_ids) if student_ids else list(range(1000, 1000 + n_students))
        self.instructors = list(instructor_ids) if instructor_ids else list(range(100, 100 + n_instructors))
        self.targets = list(target_ids) if target_ids else list(range(9000, 9120))
        self.home = {u: f"198.51.100.{self.rng.randint(1, 250)}" for u in self.students + self.instructors}

    @staticmethod
    def _e(ts, action, actor=None, rtype="", rid=None, ip=None, outcome="success") -> AuditRecord:
        return AuditRecord(ts, str(action), actor, rtype, None if rid is None else str(rid), ip, outcome)

    # ---------------------------------------------------------------- benign
    def _login(self, ev, user, t, ip, typo_p):
        r, tries = self.rng, 0
        while tries < 3 and r.random() < typo_p:                  # mistyped passwords
            ev.append(self._e(t, Action.LOGIN_FAILURE, None, "login", acct_hash(user), ip, "failure"))
            t += timedelta(seconds=r.uniform(8, 30))
            tries += 1
        ev.append(self._e(t, Action.LOGIN_SUCCESS, user, "login", acct_hash(user), ip))
        return t

    def _student_session(self, ev, s, t):
        r, ip = self.rng, self.home[s]
        t = self._login(ev, s, t, ip, 0.08)
        if r.random() < 0.2:
            ev.append(self._e(t + timedelta(seconds=r.uniform(10, 120)), Action.PII_READ, s, "student_pii", s, ip))
        if r.random() < 0.01:                                     # mistyped URL / stale link
            ev.append(self._e(t + timedelta(seconds=r.uniform(10, 120)), Action.ACCESS_DENIED, s, "grade",
                              r.choice(self.targets), ip, "denied"))

    def _instructor_session(self, ev, i, t):
        r, ip = self.rng, self.home[i]
        t = self._login(ev, i, t, ip, 0.05)
        if r.random() < 0.5:                                      # grade entry; sometimes an end-of-term bulk batch
            bulk = r.random() < 0.06
            n = r.randint(12, 18) if bulk else min(15, 1 + int(r.expovariate(1 / 5)))
            for _ in range(n):
                t += timedelta(seconds=r.uniform(3, 8) if bulk else r.uniform(5, 40))
                ev.append(self._e(t, Action.GRADE_CREATED, i, "grade", r.randint(1, 10**6), ip))
        if r.random() < 0.4:
            for tid in r.sample(self.targets, r.randint(1, 6)):
                t += timedelta(seconds=r.uniform(10, 60))
                ev.append(self._e(t, Action.PII_READ, i, "student_pii", tid, ip))
        if r.random() < 0.3:
            for _ in range(r.randint(1, 3)):
                t += timedelta(seconds=r.uniform(10, 60))
                ev.append(self._e(t, Action.PII_UPDATED, i, "student_pii", r.choice(self.targets), ip))
        if r.random() < 0.3:
            for _ in range(r.randint(1, 4)):
                t += timedelta(seconds=r.uniform(10, 60))
                ev.append(self._e(t, Action.CERT_ISSUED, i, "certificate", r.randint(1, 500), ip))

    def normal(self, start: datetime, days: int) -> list[AuditRecord]:
        """Benign traffic, including weekly lab sessions behind one shared campus NAT address."""
        r, ev = self.rng, []
        for d in range(days):
            day = start + timedelta(days=d)
            if d % 7 in (1, 3):
                t0 = day + timedelta(hours=9, minutes=r.randint(0, 120))
                for s in r.sample(self.students, min(25, len(self.students))):
                    self._login(ev, s, t0 + timedelta(seconds=r.uniform(0, 600)), CAMPUS_IP, 0.12)
            for s in self.students:
                if r.random() < 0.35:
                    self._student_session(ev, s, day + timedelta(hours=r.uniform(8, 22)))
            for i in self.instructors:
                if r.random() < 0.8:
                    self._instructor_session(ev, i, day + timedelta(hours=r.uniform(8, 18)))
        ev.sort(key=lambda e: e.timestamp)
        return ev

    # ---------------------------------------------------------------- attacks
    def attacker_ip(self) -> str:
        return f"203.0.113.{self.rng.randint(1, 250)}"

    def attack(self, kind: str, at: datetime) -> tuple[list[AuditRecord], Incident]:
        """Generate one labelled attack starting at `at`."""
        r, ev = self.rng, []

        def spread(n, secs):
            return sorted(at + timedelta(seconds=r.uniform(0, secs)) for _ in range(n))

        def fails(times, acct_of, ip_of):
            return [self._e(t, Action.LOGIN_FAILURE, None, "login", acct_of(k), ip_of(k), "failure")
                    for k, t in enumerate(times)]

        if kind == "brute_force":
            ip, victim = self.attacker_ip(), r.choice(self.students)
            ts = spread(r.randint(20, 60), r.uniform(120, 240))
            ev = fails(ts, lambda k: acct_hash(victim), lambda k: ip)
            if r.random() < 0.3:                                  # attacker eventually guesses the password
                ev.append(self._e(ts[-1] + timedelta(seconds=5), Action.LOGIN_SUCCESS, victim, "login", acct_hash(victim), ip))
            ents = {f"ip:{ip}", f"account:{acct_hash(victim)}"}
        elif kind == "credential_stuffing":
            ip = self.attacker_ip()
            ts = spread(r.randint(15, 40), r.uniform(120, 300))
            ev = fails(ts, lambda k: acct_hash(r.randint(10**6, 10**7)), lambda k: ip)
            ents = {f"ip:{ip}"}
        elif kind == "distributed_brute_force":
            victim, k = r.choice(self.students), r.randint(8, 12)
            ips = [self.attacker_ip() for _ in range(k)]
            ts = spread(k + r.randint(0, k), 240)
            ev = fails(ts, lambda j: acct_hash(victim), lambda j: ips[j % k])
            ents = {f"account:{acct_hash(victim)}"} | {f"ip:{ip}" for ip in ips}
        elif kind == "idor_probe":
            s = r.choice(self.students)
            ts = spread(r.randint(8, 30), r.uniform(60, 180))
            ev = [self._e(t, Action.ACCESS_DENIED, s, "grade", r.choice(self.targets), self.home[s], "denied") for t in ts]
            ents = {f"user:{s}"}
        elif kind == "mass_pii_harvest":
            i, n = r.choice(self.instructors), r.randint(20, 80)
            ts = spread(n, r.uniform(120, 360))
            ev = [self._e(t, Action.PII_READ, i, "student_pii", tid, self.home[i])
                  for t, tid in zip(ts, r.sample(self.targets, n))]
            ents = {f"user:{i}"}
        elif kind == "grade_burst":
            i = r.choice(self.instructors)
            ts = spread(r.randint(25, 70), r.uniform(180, 360))
            ev = [self._e(t, Action.GRADE_CREATED, i, "grade", r.randint(1, 10**6), self.home[i]) for t in ts]
            ents = {f"user:{i}"}
        elif kind == "cert_tamper":
            cid, s = r.randint(1, 500), r.choice(self.students)
            ts = [at]
            ev = [self._e(at, Action.CERT_INVALID, s, "certificate", cid, self.home[s], "failure")]
            ents = {f"certificate:{cid}"}
        elif kind == "slow_brute_force":                          # deliberately below every per-window threshold
            ip, victim = self.attacker_ip(), r.choice(self.students)
            ts = [at + timedelta(seconds=k * 100 + r.uniform(-10, 10)) for k in range(r.randint(36, 54))]
            ts[0] = max(ts[0], at)
            ev = fails(ts, lambda k: acct_hash(victim), lambda k: ip)
            ents = {f"ip:{ip}", f"account:{acct_hash(victim)}"}
        elif kind == "cert_flood":                                # abuse of certificate issuance
            i = r.choice(self.instructors)
            ts = spread(r.randint(30, 60), r.uniform(180, 360))
            ev = [self._e(t, Action.CERT_ISSUED, i, "certificate", r.randint(1, 500), self.home[i]) for t in ts]
            ents = {f"user:{i}"}
        elif kind == "pii_overwrite":                             # mass modification of stored PII
            i = r.choice(self.instructors)
            ts = spread(r.randint(30, 80), r.uniform(120, 300))
            ev = [self._e(t, Action.PII_UPDATED, i, "student_pii", r.choice(self.targets), self.home[i]) for t in ts]
            ents = {f"user:{i}"}
        else:
            raise ValueError(f"Unknown attack kind: {kind}")
        return ev, Incident(kind, frozenset(ents), min(e.timestamp for e in ev), max(e.timestamp for e in ev))

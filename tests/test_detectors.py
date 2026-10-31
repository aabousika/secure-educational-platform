"""Unit tests for rules, features, merging, and the kNN detector (no database needed)."""

from datetime import datetime, timedelta, timezone
from app.domain.security import Action, AuditRecord, SecurityAlert, Severity, merge_alerts

from app.infrastructure.security.ml.features import (
    FEATURES,
    best_per_episode,
    build_windows,
)

from app.infrastructure.security.ml.knn_detector import KnnDistanceDetector
from app.infrastructure.security.ml.rules import RuleBasedDetector
from app.infrastructure.security.ml.simulation import TrafficSimulator

from scripts.simulate_attacks import run_once
from scripts.simulate_attacks import run_once

T0 = datetime(2026, 3, 2, 10, 0, tzinfo=timezone.utc)


def ev(action, seconds, actor=None, rid=None, ip=None, rtype=""):
    return AuditRecord(T0 + timedelta(seconds=seconds), str(action), actor, rtype, rid, ip)


def rules_of(events):
    return [a.rule for a in RuleBasedDetector().detect(events)]


def test_brute_force_from_one_ip_is_a_single_alert():
    events = [ev(Action.LOGIN_FAILURE, i * 5, rid="acct1", ip="203.0.113.9") for i in range(10)]
    assert rules_of(events) == ["brute_force_ip"]


def test_few_failures_do_not_alert():
    assert rules_of([ev(Action.LOGIN_FAILURE, i * 20, rid="a", ip="1.1.1.1") for i in range(3)]) == []


def test_distributed_attack_on_one_account():
    events = [ev(Action.LOGIN_FAILURE, i * 10, rid="victim", ip=f"203.0.113.{i}") for i in range(8)]
    assert rules_of(events) == ["brute_force_account"]


def test_credential_stuffing():
    events = [ev(Action.LOGIN_FAILURE, i * 5, rid=f"acct{i}", ip="203.0.113.7") for i in range(10)]
    assert rules_of(events) == ["credential_stuffing"]


def test_takeover_needs_failures_on_the_same_account():
    streak = [ev(Action.LOGIN_FAILURE, i * 10, rid="victim", ip="203.0.113.5") for i in range(6)]
    hit = RuleBasedDetector().detect(streak + [ev(Action.LOGIN_SUCCESS, 90, actor=5, rid="victim", ip="203.0.113.5")])
    assert any(a.rule == "account_takeover" and a.severity == Severity.CRITICAL for a in hit)
    # shared campus NAT: many different accounts mistype once, someone else logs in fine
    lab = [ev(Action.LOGIN_FAILURE, i * 10, rid=f"s{i}", ip="192.0.2.10") for i in range(6)]
    lab.append(ev(Action.LOGIN_SUCCESS, 90, actor=7, rid="s99", ip="192.0.2.10"))
    assert "account_takeover" not in rules_of(lab)


def test_mass_pii_counts_distinct_students_only():
    many = [ev(Action.PII_READ, i * 3, actor=2, rid=str(i), ip="x") for i in range(20)]
    same = [ev(Action.PII_READ, i * 3, actor=2, rid="7", ip="x") for i in range(20)]
    assert rules_of(many) == ["mass_pii_access"]
    assert rules_of(same) == []


def test_separate_incidents_hours_apart_yield_separate_alerts():
    burst = lambda base: [ev(Action.GRADE_CREATED, base + i * 5, actor=3, rid=str(base + i)) for i in range(25)]
    alerts = RuleBasedDetector().detect(burst(0) + burst(3 * 3600))
    assert [a.rule for a in alerts] == ["grade_burst", "grade_burst"]


def test_invalid_certificate_is_critical():
    (alert,) = RuleBasedDetector().detect([ev(Action.CERT_INVALID, 0, actor=4, rid="12")])
    assert alert.rule == "certificate_tamper" and alert.severity == Severity.CRITICAL


def test_idor_probe():
    events = [ev(Action.ACCESS_DENIED, i * 4, actor=9, rid=str(i)) for i in range(6)]
    assert rules_of(events) == ["idor_probe"]


def test_build_windows_counts_and_distinct_targets():
    events = [ev(Action.PII_READ, i, actor=2, rid=str(i % 3)) for i in range(9)]
    keys, X = build_windows(events)
    assert len(keys) == 1 and keys[0][0] == "user:2"
    row = dict(zip(FEATURES, X[0]))
    assert row["pii_read"] == 9 and row["pii_targets"] == 3


def test_best_per_episode_splits_on_gap():
    base = T0
    cands = [("u", base, 1.0, 0), ("u", base + timedelta(minutes=5), 3.0, 1),
             ("u", base + timedelta(hours=3), 2.0, 2), ("v", base, 1.0, 3)]
    assert sorted(best_per_episode(cands)) == [1, 2, 3]


def test_merge_marks_corroboration_instead_of_duplicating():
    events = [ev(Action.GRADE_CREATED, i * 5, actor=3, rid=str(i)) for i in range(25)]
    (rule,) = RuleBasedDetector().detect(events)
    ml = SecurityAlert("ml_anomaly", Severity.MEDIUM, "user:3", rule.window_start,
                       rule.window_end + timedelta(minutes=5), 25, "unusual", score=2.4)
    other = SecurityAlert("ml_anomaly", Severity.MEDIUM, "user:8", rule.window_start, rule.window_end, 9, "unusual")
    merged = merge_alerts([rule], [ml, other])
    assert [(a.rule, a.entity, a.ml_corroborated) for a in merged] == [
        ("grade_burst", "user:3", True), ("ml_anomaly", "user:8", False)]


def test_knn_flags_unseen_volume_spike_without_flooding_benign_traffic():
    sim = TrafficSimulator(seed=11)
    detector = KnnDistanceDetector().fit_windows(build_windows(sim.normal(T0 - timedelta(days=14), 14))[1])
    benign = sim.normal(T0, 7)
    windows = len(build_windows(benign)[0])
    assert len(detector.detect(benign)) <= 0.02 * windows      # learned threshold keeps false alerts near 1%
    spike, incident = sim.attack("cert_flood", T0 + timedelta(days=8))
    assert any(a.entity in incident.entities for a in detector.detect(benign + spike))


def test_end_to_end_simulation_meets_quality_floor():
    metrics = run_once(seed=3, n_attacks=20, contamination=0.01)["Rules+kNN"]
    assert metrics.precision >= 0.9 and metrics.recall >= 0.8

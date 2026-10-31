"""Evaluate or demo the security monitor with simulated traffic. Run from the project root:

  python -m scripts.simulate_attacks evaluate [--seeds 5] [--attacks 40] [--contamination 0.01]
  python -m scripts.simulate_attacks seed  [--seed 1]     # write demo events into the database
  python -m scripts.simulate_attacks purge                # delete seeded demo events
"""

import argparse
import random
from collections import Counter
from datetime import datetime, timedelta, timezone

from app.domain.security import merge_alerts
from app.infrastructure.security.ml.evaluation import Metrics, evaluate
from app.infrastructure.security.ml.features import build_windows
from app.infrastructure.security.ml.isolation_forest import IsolationForestDetector
from app.infrastructure.security.ml.knn_detector import KnnDistanceDetector
from app.infrastructure.security.ml.rules import RuleBasedDetector
from app.infrastructure.security.ml.simulation import ATTACK_KINDS, TEST_NET_PREFIXES, TrafficSimulator


def run_once(seed: int, n_attacks: int, contamination: float) -> dict[str, Metrics]:
    """Train on 14 benign days, then test on a week containing labelled attacks."""
    sim = TrafficSimulator(seed=seed)
    start = datetime(2026, 1, 5, tzinfo=timezone.utc)
    normal = sim.normal(start, 21)
    split = start + timedelta(days=14)
    train = [e for e in normal if e.timestamp < split]
    test = [e for e in normal if e.timestamp >= split]
    rng, incidents = random.Random(seed + 100), []
    kinds = [ATTACK_KINDS[k % len(ATTACK_KINDS)] for k in range(n_attacks)]
    for kind, hour in zip(kinds, rng.sample(range(7 * 24 - 2), n_attacks)):
        events, incident = sim.attack(kind, split + timedelta(hours=hour, minutes=rng.randint(0, 50)))
        test += events
        incidents.append(incident)
    test.sort(key=lambda e: e.timestamp)
    rules = RuleBasedDetector().detect(test)
    model = IsolationForestDetector(contamination=contamination).fit_windows(build_windows(train)[1])
    ml = model.detect(test)
    knn = KnnDistanceDetector().fit_windows(build_windows(train)[1]).detect(test)
    return {"Rules": evaluate(rules, incidents), "IsolationForest": evaluate(ml, incidents),
            "kNN-distance": evaluate(knn, incidents), "Rules+IF": evaluate(merge_alerts(rules, ml), incidents),
            "Rules+kNN": evaluate(merge_alerts(rules, knn), incidents)}


def cmd_evaluate(args) -> None:
    pooled: dict[str, Metrics] = {}
    for seed in range(args.first_seed, args.first_seed + args.seeds):
        for name, m in run_once(seed, args.attacks, args.contamination).items():
            pooled.setdefault(name, Metrics()).add(m)
    print(f"\nPooled over seeds {args.first_seed}..{args.first_seed + args.seeds - 1} x {args.attacks} attacks (contamination={args.contamination})\n")
    print(f"{'Detector':<18}{'alerts':>7}{'TP':>6}{'precision':>11}{'caught':>8}{'recall':>9}{'F1':>7}")
    for name, m in pooled.items():
        print(f"{name:<18}{m.alerts:>7}{m.tp_alerts:>6}{m.precision:>11.2f}{m.caught:>5}/{m.incidents:<3}{m.recall:>7.2f}{m.f1:>7.2f}")
    print("\nRecall per attack type (caught/total)")
    print(f"{'attack':<26}" + "".join(f"{n:>17}" for n in pooled))
    for kind in ATTACK_KINDS:
        row = "".join(f"{pooled[n].per_kind[kind][0]:>12}/{pooled[n].per_kind[kind][1]:<4}" for n in pooled)
        print(f"{kind:<26}{row}")
    for name in ("Rules", "Rules+kNN"):
        fp = Counter(a.rule for a in pooled[name].false_positives)
        print(f"\n{name} false positives by rule:", dict(fp) or "none")


def _session():
    from app.infrastructure.database.session import SessionLocal
    return SessionLocal()


def cmd_seed(args) -> None:
    from sqlalchemy import select
    from app.infrastructure.database.models import AuditEventModel, UserModel
    db = _session()
    students = [u.id for u in db.scalars(select(UserModel).where(UserModel.role == "student"))]
    instructors = [u.id for u in db.scalars(select(UserModel).where(UserModel.role == "instructor"))]
    if not students or not instructors:
        print("Need at least one student and one instructor account first.")
        return
    sim = TrafficSimulator(seed=args.seed, student_ids=students, instructor_ids=instructors)
    now = datetime.now(timezone.utc)
    events = sim.normal(now - timedelta(days=14), 14)
    for kind, minutes_ago in (("brute_force", 90), ("mass_pii_harvest", 60), ("idor_probe", 40),
                              ("grade_burst", 25), ("credential_stuffing", 10)):
        events += sim.attack(kind, now - timedelta(minutes=minutes_ago))[0]
    db.add_all(AuditEventModel(actor_user_id=e.actor_user_id, action=e.action, resource_type=e.resource_type,
                               resource_id=e.resource_id, ip_address=e.ip_address, outcome=e.outcome,
                               created_at=e.timestamp) for e in events if e.timestamp <= now)
    db.commit()
    print(f"Seeded {len(events)} simulated events (IPs in documentation ranges). Run 'purge' to remove them.")


def cmd_purge(_args) -> None:
    from sqlalchemy import delete, or_
    from app.infrastructure.database.models import AuditEventModel
    db = _session()
    result = db.execute(delete(AuditEventModel).where(
        or_(*[AuditEventModel.ip_address.like(p + "%") for p in TEST_NET_PREFIXES])))
    db.commit()
    print(f"Deleted {result.rowcount} simulated events.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    ev = sub.add_parser("evaluate")
    ev.add_argument("--seeds", type=int, default=5)
    ev.add_argument("--first-seed", type=int, default=1, help="use unseen seeds for a hold-out check")
    ev.add_argument("--attacks", type=int, default=50)
    ev.add_argument("--contamination", type=float, default=0.01)
    ev.set_defaults(fn=cmd_evaluate)
    sd = sub.add_parser("seed")
    sd.add_argument("--seed", type=int, default=1)
    sd.set_defaults(fn=cmd_seed)
    sub.add_parser("purge").set_defaults(fn=cmd_purge)
    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()

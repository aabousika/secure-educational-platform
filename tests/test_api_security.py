"""API-level checks: audit events are written, no secrets leak into them, and alerts are instructor-only."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

PW = "a-very-long-password-1"


@pytest.fixture(scope="module")
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _login(client, email, password=PW):
    r = client.post("/auth/login", data={"username": email, "password": password})
    return r.json()["access_token"] if r.status_code == 200 else None


def _register(client, name, email):
    r = client.post("/auth/register", json={"full_name": name, "email": email, "password": PW})
    assert r.status_code == 201
    return r.json()["id"]


def _events(action):
    from app.infrastructure.database.models import AuditEventModel
    from app.infrastructure.database.session import SessionLocal
    with SessionLocal() as db:
        return list(db.scalars(select(AuditEventModel).where(AuditEventModel.action == action)))


@pytest.fixture(scope="module")
def instructor_token(client):
    from app.application.services import PlatformService
    from app.infrastructure.database.session import SessionLocal
    with SessionLocal() as db:
        PlatformService().create_instructor(db, "Ins", "ins@example.com", PW)
    return _login(client, "ins@example.com")


def test_failed_logins_are_audited_without_the_email_and_raise_an_alert(client, instructor_token):
    for _ in range(9):
        assert client.post("/auth/login", data={"username": "ghost@example.com", "password": "wrong-pass-123"}).status_code == 401
    rows = _events("auth.login.failure")
    assert len(rows) >= 9 and all(r.outcome == "failure" and r.ip_address for r in rows)
    assert all("ghost" not in (r.resource_id or "") and len(r.resource_id) == 16 for r in rows)
    body = client.get("/security/alerts?hours=1", headers=_auth(instructor_token)).json()
    assert "brute_force_ip" in {a["rule"] for a in body["alerts"]}


def test_students_cannot_read_alerts(client):
    _register(client, "Sam Student", "sam@example.com")
    assert client.get("/security/alerts", headers=_auth(_login(client, "sam@example.com"))).status_code == 403
    assert client.get("/security/alerts").status_code == 401


def test_cross_student_access_is_denied_and_audited(client):
    a, b = _register(client, "Ann A", "ann@example.com"), _register(client, "Bob B", "bob@example.com")
    token = _login(client, "ann@example.com")
    assert client.get(f"/grades/student/{b}", headers=_auth(token)).status_code == 403
    assert client.get(f"/students/{b}/pii", headers=_auth(token)).status_code == 403
    denied = [e for e in _events("access.denied") if e.actor_user_id == a]
    assert {e.resource_type for e in denied} == {"grade", "student_pii"}


def test_pii_reads_are_audited_for_instructors(client, instructor_token):
    sid = _register(client, "Cy C", "cy@example.com")
    body = {"address": "1 Main St", "phone_number": "+100000000", "date_of_birth": "2000-01-01"}
    assert client.put(f"/students/{sid}/pii", json=body, headers=_auth(instructor_token)).status_code == 204
    assert client.get(f"/students/{sid}/pii", headers=_auth(instructor_token)).status_code == 200
    assert any(e.resource_id == str(sid) for e in _events("pii.read"))

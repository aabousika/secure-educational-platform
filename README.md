# Secure Educational Platform

A security-focused educational platform API built with **FastAPI** and a **clean-architecture** layout. It manages students, grades, encrypted personal data and digitally signed certificates, and it ships with a **hybrid anomaly-detection engine** (explainable rules + a machine-learning detector) that analyses the audit log to surface attacks such as brute-force logins, credential stuffing, IDOR probing and PII harvesting.

A lightweight, dependency-free, Arabic/RTL web frontend is included for students and instructors.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi&logoColor=white)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.x-D71F00)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Neon-4169E1?logo=postgresql&logoColor=white)
![Tests](https://img.shields.io/badge/tests-18%20passing-brightgreen)

---

## Table of Contents

- [Key Features](#key-features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Security Design](#security-design)
- [Security Monitoring (Anomaly Detection)](#security-monitoring-anomaly-detection)
- [API Reference](#api-reference)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Frontend](#frontend)
- [Testing and Evaluation](#testing-and-evaluation)
- [Known Limitations and Production Checklist](#known-limitations-and-production-checklist)

---

## Key Features

| Area | What it does |
|---|---|
| **Authentication** | Email + password login, Argon2 password hashing, short-lived JWT access tokens (30 min by default). |
| **Role-based access control** | Two roles, `student` and `instructor`, enforced server-side on every endpoint. Students can only access their own data. |
| **PII protection** | Address, phone number and date of birth are encrypted with Fernet (authenticated encryption) before they reach the database. |
| **Signed certificates** | Certificates are canonicalised, hashed with SHA-256 and signed with **Ed25519**. Anyone with the public key can verify them. |
| **Audit logging** | Security-relevant events are stored as metadata only: no passwords, tokens or plaintext PII. Login identifiers are stored as keyed HMAC pseudonyms. |
| **Anomaly detection** | 8 explainable rules plus a k-NN distance novelty detector, merged into one alert stream exposed to instructors. |
| **Attack simulator** | Deterministic traffic generator with 10 labelled attack scenarios for evaluating the detectors (precision / recall / F1). |
| **Web UI** | Vanilla JS dashboards for students and instructors (Arabic, RTL, no build step, no dependencies). |

---

## Architecture

The backend follows a layered clean-architecture structure. Dependencies point inward: presentation depends on application, application on domain, and infrastructure provides the concrete implementations.

```mermaid
flowchart TB
    subgraph Presentation["presentation  (FastAPI)"]
        R[Routers / Schemas / Dependencies / CLI]
    end
    subgraph Application["application  (use cases)"]
        S[PlatformService]
        A[AuditService]
        M[SecurityMonitorService]
    end
    subgraph Domain["domain  (pure Python)"]
        E[Entities / Roles]
        D[Security types: AuditRecord, SecurityAlert, AnomalyDetector]
    end
    subgraph Infra["infrastructure"]
        DB[(SQLAlchemy + PostgreSQL)]
        C[Crypto: Argon2, JWT, Fernet, Ed25519]
        ML[Detectors: Rules, kNN, Isolation Forest]
    end
    R --> S
    R --> A
    R --> M
    S --> E
    M --> D
    S --> DB
    S --> C
    A --> DB
    M --> ML
    ML --> D
```

| Layer | Responsibility |
|---|---|
| `domain` | Business entities, roles, audit/alert types and the `AnomalyDetector` contract. No FastAPI, SQLAlchemy or ML imports, so detectors stay swappable. |
| `application` | Use cases: registration, grades, PII, certificates, audit writing and security analysis. |
| `infrastructure` | SQLAlchemy persistence, cryptographic services and the ML/rule-based detectors. |
| `presentation` | FastAPI routers, request/response schemas, authorization dependencies and the admin CLI. |
| `core` | Typed settings loaded from environment variables. |
| `main.py` | Composition root: wires routers, CORS and start-up tasks. |

---

## Project Structure

```text
.
├── app/
│   ├── main.py                       # Composition root
│   ├── core/config.py                # Typed settings (pydantic-settings)
│   ├── domain/
│   │   ├── entities.py               # Role enum, identity
│   │   ├── repositories.py           # Repository contracts (Protocols)
│   │   └── security.py               # AuditRecord, SecurityAlert, merge_alerts
│   ├── application/
│   │   ├── services.py               # Accounts, grades, PII, certificates
│   │   ├── audit.py                  # Audit writer + HMAC pseudonyms
│   │   └── security_monitor.py       # Runs detectors over the audit log
│   ├── infrastructure/
│   │   ├── database/                 # Models, session, lightweight migrations
│   │   └── security/
│   │       ├── crypto.py             # Argon2, JWT, Fernet, Ed25519
│   │       └── ml/                   # features, rules, kNN, Isolation Forest,
│   │                                 # simulation, evaluation
│   └── presentation/
│       ├── routers/                  # auth, grades, students, certificates, security
│       ├── schemas.py                # Pydantic models
│       ├── dependencies.py           # Auth / RBAC / client IP
│       └── cli.py                    # Instructor creation
├── frontend/                         # Arabic RTL UI (vanilla JS)
├── scripts/
│   ├── generate_signing_keys.py      # Ed25519 key pair generator
│   └── simulate_attacks.py           # evaluate / seed / purge
├── sql/                              # Reference schema and SQL migrations
├── tests/                            # 18 tests (API + detectors)
├── requirements.txt
├── requirements-dev.txt
└── .env.example
```

---

## Security Design

| Concern | Implementation |
|---|---|
| Password storage | Argon2 via `passlib`; minimum 12 characters (enforced by the API schema and the CLI). |
| Session tokens | JWT (HS256) with `sub`, `role` and `exp`. The server reloads the user from the database on every request and rejects inactive accounts. |
| Privilege escalation | Public registration always creates a `student`. Instructor accounts can only be created through the trusted CLI. |
| Authorization | Role checks live in FastAPI dependencies. Students are restricted to their own grades, PII and certificates; instructors can access any student. |
| PII at rest | Fernet-encrypted JSON blob in `student_pii`; the database never holds plaintext PII fields. |
| Certificate integrity | Canonical JSON, then SHA-256 digest, then Ed25519 signature. Verification compares the digest in constant time and then checks the signature. |
| Audit trail | Events are written in their own transaction so denials and failures persist even when a request errors. An audit failure never breaks the user's request. |
| Privacy in logs | Failed-login attempts store a keyed HMAC pseudonym (16 hex chars) of the identifier instead of the e-mail address. |
| Transport / CORS | CORS origins are configurable; only `GET`, `POST`, `PUT`, `DELETE` and the `Authorization` / `Content-Type` headers are allowed. |
| Secrets | All secrets come from environment variables. `.env` and the private signing key are git-ignored. |

### Audited events

`auth.login.success`, `auth.login.failure`, `access.denied`, `pii.read`, `pii.updated`, `grade.created`, `certificate.issued`, `certificate.invalid`

---

## Security Monitoring (Anomaly Detection)

Instructors can request an analysis of recent audit activity at `GET /security/alerts`. Two complementary detectors run and their results are merged.

### 1. Rule-based detector (high precision, explainable)

Thresholds are evaluated over a sliding 5-minute window and are tunable in `Thresholds`.

| Rule | Severity | Trigger (defaults) |
|---|---|---|
| `credential_stuffing` | High | 8+ distinct accounts failing to log in from one IP |
| `brute_force_ip` | High | 8+ failed logins from one IP |
| `brute_force_account` | High | 6+ failed logins against one account (any IPs) |
| `account_takeover` | Critical | Successful login after 5+ failures on the same account within 10 min |
| `idor_probe` | High | 5+ denied accesses by one user |
| `mass_pii_access` | High | PII of 15+ distinct students read by one user |
| `grade_burst` | Medium | 20+ grades created by one user |
| `certificate_tamper` | Critical | A certificate fails signature verification |

### 2. k-NN distance novelty detector (unknown patterns)

- Audit events are turned into **10 numeric features** per *entity x 5-minute window* (failed/successful logins, distinct login targets, denied accesses, PII reads, distinct PII targets, grades created, PII updates, certificates issued, invalid certificates).
- The detector learns a baseline from the preceding **14 days** and flags windows whose distance to their 10th nearest baseline neighbour exceeds a learned threshold (99.5th percentile of leave-one-out distances, `log1p` space).
- **Cold start:** if fewer than 400 real baseline windows exist, the baseline is padded with synthetic benign traffic. The API response reports `baseline_windows` and `synthetic_windows` so the provenance is transparent.
- The trained model is cached in memory for 10 minutes.

### Merging

An ML alert that overlaps a rule alert for the same entity does **not** create a duplicate; it marks the rule alert as `ml_corroborated` and attaches the score. ML-only findings are reported as `ml_anomaly` (medium). Results are sorted by severity, then recency.

> An Isolation Forest detector is also implemented and benchmarked, but the production monitor uses Rules + kNN (see results below).

### Evaluation results (simulated traffic)

Pooled over 5 seeds x 50 labelled attacks each (250 incidents); training on 14 benign days, testing on a following week:

| Detector | Precision | Recall | F1 |
|---|---:|---:|---:|
| Rules | 1.00 | 0.70 | 0.82 |
| Isolation Forest | 0.77 | 0.08 | 0.14 |
| kNN distance | 0.98 | 0.69 | 0.81 |
| Rules + Isolation Forest | 0.97 | 0.70 | 0.81 |
| **Rules + kNN (used in production)** | **0.98** | **0.90** | **0.94** |

The rules cover known attack patterns with zero false positives, while kNN adds coverage for patterns no rule describes (`cert_flood`, `pii_overwrite`). Slow, low-rate brute force (`slow_brute_force`) is **not** detected by any configuration; see [limitations](#known-limitations-and-production-checklist).

> These figures come from synthetic traffic generated by the bundled simulator. Treat them as a regression benchmark, not as a guarantee of real-world performance. Alerts are advisory and require human review.

---

## API Reference

Interactive documentation is served at `/docs` (Swagger UI) and `/redoc`.

| Method | Endpoint | Access | Description |
|---|---|---|---|
| `GET` | `/health` | Public | Liveness check |
| `POST` | `/auth/register` | Public | Student self-registration |
| `POST` | `/auth/login` | Public | OAuth2 password flow (`username` = e-mail); returns a bearer token |
| `POST` | `/grades` | Instructor | Create a grade |
| `GET` | `/grades/me` | Student | Own grades |
| `GET` | `/grades/student/{student_id}` | Instructor / owner | A student's grades |
| `PUT` | `/students/{student_id}/pii` | Instructor | Write encrypted PII |
| `GET` | `/students/{student_id}/pii` | Instructor / owner | Read decrypted PII (audited) |
| `POST` | `/certificates` | Instructor | Issue a signed certificate |
| `GET` | `/certificates/me` | Student | Own certificates |
| `GET` | `/certificates/{certificate_id}` | Instructor / owner | Certificate with verification status |
| `POST` | `/certificates/verify/{certificate_id}` | Instructor / owner | Verify digest and signature |
| `GET` | `/security/alerts?hours=24` | Instructor | Anomaly report (`hours`: 1 to 168) |

Example:

```bash
# Log in
curl -X POST http://127.0.0.1:8000/auth/login \
  -d "username=student@example.com&password=your-long-password"

# Use the token
curl http://127.0.0.1:8000/grades/me \
  -H "Authorization: Bearer <access_token>"
```

---

## Getting Started

### Prerequisites

- Python **3.11+**
- A PostgreSQL database (the project is configured for [Neon](https://neon.tech)); SQLite is used automatically by the test suite

### 1. Install

```bash
git clone https://github.com/aabousika/secure-educational-platform.git
cd secure-educational-platform

python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate

pip install -r requirements.txt
pip install numpy scikit-learn       # required by the security-monitoring engine
cp .env.example .env
```

### 2. Generate secrets and keys

```bash
# JWT secret  ->  JWT_SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(48))"

# Fernet key  ->  FERNET_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Ed25519 certificate signing keys  ->  keys/*.pem
python scripts/generate_signing_keys.py
```

Edit `.env` and set `DATABASE_URL` (format: `postgresql+psycopg://USER:PASSWORD@HOST/DBNAME?sslmode=require`), `JWT_SECRET_KEY` and `FERNET_KEY`.

> Never commit `.env` or the private signing key.

### 3. Run the API

```bash
uvicorn app.main:app --reload
```

Tables are created automatically at start-up, followed by the lightweight additive migrations. API docs: <http://127.0.0.1:8000/docs>

### 4. Create the first instructor

```bash
python -m app.presentation.cli create-instructor
```

---

## Configuration

All settings are read from environment variables (or `.env`).

| Variable | Required | Default | Description |
|---|:---:|---|---|
| `DATABASE_URL` | Yes | | SQLAlchemy URL of the database |
| `JWT_SECRET_KEY` | Yes | | Secret used to sign JWTs and derive audit pseudonyms |
| `FERNET_KEY` | Yes | | Key used to encrypt PII |
| `JWT_ALGORITHM` | No | `HS256` | JWT signing algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | No | `30` | Token lifetime |
| `CERTIFICATE_PRIVATE_KEY_PATH` | No | `keys/certificate_private_key.pem` | Ed25519 private key |
| `CERTIFICATE_PUBLIC_KEY_PATH` | No | `keys/certificate_public_key.pem` | Ed25519 public key |
| `CORS_ORIGINS` | No | `http://127.0.0.1:3000` | Comma-separated list of allowed origins |
| `APP_NAME` | No | `Secure Educational Platform API` | API title |
| `ENVIRONMENT` | No | `development` | Environment label |

---

## Frontend

A static, dependency-free web app (Arabic, right-to-left) lives in `frontend/`.

```bash
cd frontend
python -m http.server 3000
```

Then open <http://127.0.0.1:3000>. The default API address is `http://127.0.0.1:8000` and can be changed from the instructor "Administration" page. Serve it over HTTP rather than opening the file directly, otherwise the browser's CORS policy blocks the requests. Make sure your frontend origin is listed in `CORS_ORIGINS`.

| Page | Audience | Content |
|---|---|---|
| `index.html` / `pages/login.html` | Everyone | Sign in or create a student account |
| `pages/student.html` | Students | Own grades, certificates and personal data |
| `pages/teacher.html` | Instructors | Students, grades, PII and certificate issuing |
| `pages/admin.html` | Instructors | Server health, security alerts, certificate verification |

The JWT is kept in `sessionStorage` (cleared when the tab closes). The server re-validates every request, so the UI is a convenience layer and not a security boundary.

---

## Testing and Evaluation

### Test suite

```bash
pip install -r requirements-dev.txt numpy scikit-learn httpx
pytest
```

The suite (18 tests) runs against a throw-away SQLite database with generated keys, so it needs neither Neon nor your `.env`. It covers audit-event creation, absence of secrets in audit rows, role enforcement, cross-student access denial, every detection rule, window feature extraction, alert merging, and an end-to-end quality floor (Rules + kNN: precision at least 0.9, recall at least 0.8).

### Attack simulator

```bash
# Benchmark all detectors on labelled simulated attacks
python -m scripts.simulate_attacks evaluate --seeds 5 --attacks 50

# Seed demo traffic (benign + attacks) into the configured database
python -m scripts.simulate_attacks seed

# Remove the seeded events again
python -m scripts.simulate_attacks purge
```

Simulated events use IPs from the RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), so they are easy to recognise and purge. `seed` requires at least one student and one instructor account.

---

## Known Limitations and Production Checklist

This project is an academic reference implementation, not a production-certified security product.

**Current limitations**

- **Slow brute force is undetected.** Low-rate attacks spread over long periods fall below the 5-minute window thresholds.
- **Detector metrics are simulation-based.** Real traffic will differ; thresholds in `Thresholds` should be tuned to the deployment.
- **Repository contracts are not yet fully used.** `domain/repositories.py` defines the contracts, but the application services currently talk to SQLAlchemy sessions directly.
- **Client IP** is the direct peer address. Behind a reverse proxy, configure trusted forwarded headers.
- Monitoring analysis runs on demand per request (with a 10-minute model cache), not as a background job.

**Before going to production**

- [ ] Replace start-up `create_all` and the lightweight migrations with **Alembic** migrations
- [ ] Add **rate limiting** and account lockout on the login endpoint
- [ ] Implement **refresh-token** rotation and revocation
- [ ] Use a secrets manager / KMS for `JWT_SECRET_KEY`, `FERNET_KEY` and the signing key (plus key rotation)
- [ ] Pin dependency versions and add `numpy`, `scikit-learn` (and `httpx` for tests) to the requirements files
- [ ] Serve exclusively over HTTPS and set strict CORS origins
- [ ] Add backups, centralised logging and alert delivery
- [ ] Perform an independent security review

---

## Author

Built by [@aabousika](https://github.com/aabousika).

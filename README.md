# Secure Educational Platform — Clean Architecture

Python 3.11+, FastAPI, SQLAlchemy 2, PostgreSQL (Neon), Argon2, JWT, Fernet PII encryption, Ed25519 certificate signatures.

## Architecture
- `domain`: business entities and repository contracts.
- `application`: use cases / business services.
- `infrastructure`: SQLAlchemy persistence and cryptographic implementations.
- `presentation`: FastAPI routers, schemas, dependency wiring.
- `core`: settings and shared configuration.
- `main.py`: composition root / application entry point.

`__init__.py` files are included to make packages explicit and imports predictable. They can be empty.

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```
Set `DATABASE_URL` to your Neon URL, using:
`postgresql+psycopg://USER:PASSWORD@HOST/DBNAME?sslmode=require`

Generate secrets:
```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
python scripts/generate_signing_keys.py
```
Paste the first value into `JWT_SECRET_KEY`, the second into `FERNET_KEY`.
Never commit `.env` or the private signing key.

Run:
```bash
uvicorn app.main:app --reload
```
Docs: http://127.0.0.1:8000/docs

Create the first instructor account:
```bash
python -m app.presentation.cli create-instructor
```

Student self-registration is public; instructor registration is not. PII is encrypted before database storage. Certificates are signed using Ed25519 and verified against the public key.

This is a coursework scaffold, not a production-certified security system. Before production, add database migrations, rate limiting, refresh-token revocation/rotation, secure key management, backups, monitoring, and a security review.

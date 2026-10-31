"""Idempotent, additive schema upgrades. `create_all` never alters existing tables, so new audit
columns are added here; use Alembic for anything beyond simple additive changes."""

from sqlalchemy import text
from sqlalchemy.engine import Engine

AUDIT_DDL = (
    "ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45)",
    "ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS outcome VARCHAR(16) NOT NULL DEFAULT 'success'",
    "CREATE INDEX IF NOT EXISTS ix_audit_events_created_at ON audit_events (created_at)",
)


def apply_lightweight_migrations(engine: Engine) -> None:
    """Apply additive audit-table upgrades on PostgreSQL."""
    if engine.dialect.name != "postgresql":
        return
    with engine.begin() as conn:
        for ddl in AUDIT_DDL:
            conn.execute(text(ddl))

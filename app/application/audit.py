"""Audit-log writer for security-relevant events (metadata only — never secrets or plaintext PII)."""

import hashlib
import hmac
import logging

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.domain.security import Action
from app.infrastructure.database.models import AuditEventModel

logger = logging.getLogger(__name__)


class AuditService:
    """Record events in their own transaction so denials and failures persist even when a request errors."""

    @staticmethod
    def pseudonym(identifier: str) -> str:
        """Keyed hash of a login identifier: correlates attempts without storing the e-mail or a typed password."""
        key = hashlib.sha256(b"audit-pseudonym|" + get_settings().jwt_secret_key.encode()).digest()
        return hmac.new(key, identifier.strip().lower().encode(), hashlib.sha256).hexdigest()[:16]

    @staticmethod
    def record(db: Session, action: Action | str, *, actor_id: int | None = None, resource_type: str,
               resource_id: str | None = None, ip: str | None = None, outcome: str = "success") -> None:
        """Persist one event; audit failures are logged but never break the user's request."""
        try:
            db.add(AuditEventModel(actor_user_id=actor_id, action=str(action), resource_type=resource_type,
                                   resource_id=resource_id, ip_address=ip, outcome=outcome))
            db.commit()
        except Exception:  # noqa: BLE001 - auditing must not take the API down
            db.rollback()
            logger.exception("Failed to write audit event %s", action)

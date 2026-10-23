"""Domain-level entities and role constants, independent of FastAPI and SQLAlchemy."""

from dataclasses import dataclass
from enum import StrEnum


class Role(StrEnum):
    """Roles supported by the assignment's authorization policy."""

    STUDENT = "student"
    INSTRUCTOR = "instructor"


@dataclass(frozen=True)
class AuthenticatedIdentity:
    """Minimal identity claims used by application authorization."""

    user_id: int
    role: Role

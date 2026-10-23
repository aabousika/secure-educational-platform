"""Repository contracts that describe persistence operations without database details."""

from typing import Protocol, Any


class UserRepository(Protocol):
    """Persistence contract for user lookup and creation."""

    def get_by_id(self, user_id: int) -> Any | None: ...
    def get_by_email(self, email: str) -> Any | None: ...
    def add(self, user: Any) -> Any: ...


class GradeRepository(Protocol):
    """Persistence contract for grades."""

    def list_for_student(self, student_id: int) -> list[Any]: ...
    def add(self, grade: Any) -> Any: ...

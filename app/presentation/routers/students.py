"""Student PII routes with server-side authorization."""

from fastapi import APIRouter, HTTPException, Response
from app.application.services import PlatformService
from app.application.audit import AuditService
from app.domain.security import Action
from app.presentation.dependencies import Db, CurrentUser, InstructorUser, ClientIP
from app.presentation.schemas import PIIRequest, PIIResponse

router = APIRouter(prefix="/students", tags=["Student PII"])
service = PlatformService()


@router.put("/{student_id}/pii", status_code=204)
def update_pii(student_id: int, payload: PIIRequest, instructor: InstructorUser, db: Db):
    """Allow instructors to write PII; data is encrypted before persistence."""
    try:
        service.write_pii(db, instructor.id, student_id, payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return Response(status_code=204)


@router.get("/{student_id}/pii", response_model=PIIResponse)
def read_pii(student_id: int, user: CurrentUser, db: Db, ip: ClientIP):
    """Allow instructors to read any student's PII and students only their own."""
    if user.role == "student" and user.id != student_id:
        AuditService.record(db, Action.ACCESS_DENIED, actor_id=user.id, resource_type="student_pii",
                            resource_id=str(student_id), ip=ip, outcome="denied")
        raise HTTPException(status_code=403, detail="You may only access your own PII")
    if user.role not in {"student", "instructor"}:
        raise HTTPException(status_code=403, detail="Access denied")
    AuditService.record(db, Action.PII_READ, actor_id=user.id, resource_type="student_pii",
                        resource_id=str(student_id), ip=ip)
    payload = service.read_pii(db, student_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="PII record not found")
    return {"student_id": student_id, **payload}

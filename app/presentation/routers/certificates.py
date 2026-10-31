"""Certificate issue, view, and signature-verification routes."""

from fastapi import APIRouter, HTTPException
from app.application.services import PlatformService
from app.infrastructure.database.models import CertificateModel
from app.application.audit import AuditService
from app.domain.security import Action
from app.presentation.dependencies import Db, CurrentUser, InstructorUser, ClientIP
from app.presentation.schemas import CertificateCreate, CertificateResponse

router = APIRouter(prefix="/certificates", tags=["Certificates"])
service = PlatformService()


def as_response(cert: CertificateModel) -> CertificateResponse:
    """Convert a certificate ORM model into a safe response with verification status."""
    return CertificateResponse(
        id=cert.id, student_id=cert.student_id, course=cert.course,
        payload=cert.payload, digest_sha256=cert.digest_sha256,
        signature_b64=cert.signature_b64, issued_at=cert.issued_at,
        valid=service.verify_certificate(cert),
    )


@router.post("", response_model=CertificateResponse, status_code=201)
def issue(payload: CertificateCreate, instructor: InstructorUser, db: Db):
    """Issue a signed certificate as an instructor."""
    try:
        return as_response(service.issue_certificate(db, instructor.id, payload.student_id, payload.course))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/me", response_model=list[CertificateResponse])
def my_certificates(user: CurrentUser, db: Db):
    """List certificates belonging to the authenticated student."""
    if user.role != "student":
        raise HTTPException(status_code=403, detail="Student account required")
    return [as_response(cert) for cert in service_certificates(db, user.id)]


def service_certificates(db: Db, student_id: int) -> list[CertificateModel]:
    """Query a student's certificates; kept local to this presentation module."""
    from sqlalchemy import select
    return list(db.scalars(select(CertificateModel).where(CertificateModel.student_id == student_id)
                           .order_by(CertificateModel.id)))


@router.get("/{certificate_id}", response_model=CertificateResponse)
def get_certificate(certificate_id: int, user: CurrentUser, db: Db, ip: ClientIP):
    """Instructors can view any certificate; students only their own."""
    cert = db.get(CertificateModel, certificate_id)
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    if user.role == "student" and cert.student_id != user.id:
        AuditService.record(db, Action.ACCESS_DENIED, actor_id=user.id, resource_type="certificate",
                            resource_id=str(cert.id), ip=ip, outcome="denied")
        raise HTTPException(status_code=403, detail="You may only access your own certificates")
    response = as_response(cert)
    if not response.valid:
        AuditService.record(db, Action.CERT_INVALID, actor_id=user.id, resource_type="certificate",
                            resource_id=str(cert.id), ip=ip, outcome="failure")
    return response


@router.post("/verify/{certificate_id}")
def verify(certificate_id: int, user: CurrentUser, db: Db, ip: ClientIP):
    """Verify a certificate's digest and digital signature."""
    cert = db.get(CertificateModel, certificate_id)
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    if user.role == "student" and cert.student_id != user.id:
        AuditService.record(db, Action.ACCESS_DENIED, actor_id=user.id, resource_type="certificate",
                            resource_id=str(cert.id), ip=ip, outcome="denied")
        raise HTTPException(status_code=403, detail="You may only verify your own certificates")
    valid = service.verify_certificate(cert)
    if not valid:
        AuditService.record(db, Action.CERT_INVALID, actor_id=user.id, resource_type="certificate",
                            resource_id=str(cert.id), ip=ip, outcome="failure")
    return {"certificate_id": cert.id, "valid": valid}

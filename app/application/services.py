"""Application use cases. HTTP concerns stay in presentation; persistence uses SQLAlchemy here."""

from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.infrastructure.database.models import UserModel, GradeModel, StudentPIIModel, CertificateModel, AuditEventModel
from app.infrastructure.security.crypto import PasswordService, PIIEncryptionService, CertificateCryptoService


class PlatformService:
    """Coordinate account, grade, PII, and certificate use cases."""

    def __init__(self) -> None:
        """Initialize application-level cryptographic collaborators."""
        self._pii = PIIEncryptionService()
        self._cert_crypto = CertificateCryptoService()

    def register_student(self, db: Session, name: str, email: str, password: str) -> UserModel:
        """Register a student; callers cannot choose an elevated role."""
        email = email.strip().lower()
        if db.scalar(select(UserModel).where(UserModel.email == email)):
            raise ValueError("Email is already registered")
        user = UserModel(full_name=name.strip(), email=email,
                         password_hash=PasswordService.hash(password), role="student")
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    def create_instructor(self, db: Session, name: str, email: str, password: str) -> UserModel:
        """Create an instructor from the trusted CLI only."""
        email = email.strip().lower()
        if db.scalar(select(UserModel).where(UserModel.email == email)):
            raise ValueError("Email is already registered")
        user = UserModel(full_name=name.strip(), email=email,
                         password_hash=PasswordService.hash(password), role="instructor")
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    def authenticate(self, db: Session, email: str, password: str) -> UserModel | None:
        """Return an active user only when the supplied password is valid."""
        user = db.scalar(select(UserModel).where(UserModel.email == email.strip().lower()))
        if user is None or not user.is_active or not PasswordService.verify(password, user.password_hash):
            return None
        return user

    def create_grade(self, db: Session, instructor_id: int, student_id: int,
                     course: str, score: float, max_score: float) -> GradeModel:
        """Create a grade after validating student and score bounds."""
        student = db.get(UserModel, student_id)
        if student is None or student.role != "student":
            raise ValueError("Student account not found")
        if score < 0 or max_score <= 0 or score > max_score:
            raise ValueError("Score must be between zero and max_score")
        grade = GradeModel(student_id=student_id, course=course, score=score, max_score=max_score)
        db.add(grade)
        db.flush()
        self._audit(db, instructor_id, "grade.created", "grade", str(grade.id))
        db.commit()
        db.refresh(grade)
        return grade

    def grades_for(self, db: Session, student_id: int) -> list[GradeModel]:
        """Return a student's grades in stable order."""
        return list(db.scalars(select(GradeModel).where(GradeModel.student_id == student_id).order_by(GradeModel.id)))

    def write_pii(self, db: Session, actor_id: int, student_id: int, payload: dict) -> None:
        """Encrypt and persist student PII, recording a metadata-only audit event."""
        student = db.get(UserModel, student_id)
        if student is None or student.role != "student":
            raise ValueError("Student account not found")
        record = db.scalar(select(StudentPIIModel).where(StudentPIIModel.student_id == student_id))
        encrypted = self._pii.encrypt(payload)
        if record:
            record.encrypted_payload = encrypted
        else:
            db.add(StudentPIIModel(student_id=student_id, encrypted_payload=encrypted))
        self._audit(db, actor_id, "pii.updated", "student_pii", str(student_id))
        db.commit()

    def read_pii(self, db: Session, student_id: int) -> dict | None:
        """Decrypt PII; the API layer must authorize the caller before invoking this."""
        record = db.scalar(select(StudentPIIModel).where(StudentPIIModel.student_id == student_id))
        return self._pii.decrypt(record.encrypted_payload) if record else None

    def issue_certificate(self, db: Session, instructor_id: int, student_id: int, course: str) -> CertificateModel:
        """Create and digitally sign a certificate for an existing student."""
        student = db.get(UserModel, student_id)
        if student is None or student.role != "student":
            raise ValueError("Student account not found")
        payload = {
            "student_id": student.id,
            "student_name": student.full_name,
            "course": course,
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "issued_by": instructor_id,
        }
        canonical, digest, signature = self._cert_crypto.sign(payload)
        cert = CertificateModel(student_id=student_id, course=course, payload=canonical,
                                 digest_sha256=digest, signature_b64=signature, issued_by=instructor_id)
        db.add(cert)
        db.flush()
        self._audit(db, instructor_id, "certificate.issued", "certificate", str(cert.id))
        db.commit()
        db.refresh(cert)
        return cert

    def verify_certificate(self, cert: CertificateModel) -> bool:
        """Check the certificate's stored digest and digital signature."""
        return self._cert_crypto.verify(cert.payload, cert.digest_sha256, cert.signature_b64)

    @staticmethod
    def _audit(db: Session, actor_id: int, action: str, resource_type: str, resource_id: str) -> None:
        """Record an event without storing secrets or plaintext sensitive data."""
        db.add(AuditEventModel(actor_user_id=actor_id, action=action,
                               resource_type=resource_type, resource_id=resource_id))

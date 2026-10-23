"""Validated API request and response models."""

from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class RegisterRequest(BaseModel):
    """Student self-registration input."""

    full_name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class UserResponse(BaseModel):
    """Safe user representation without password hash."""

    model_config = ConfigDict(from_attributes=True)
    id: int
    full_name: str
    email: EmailStr
    role: str
    is_active: bool


class TokenResponse(BaseModel):
    """Bearer token response."""

    access_token: str
    token_type: str = "bearer"


class GradeCreate(BaseModel):
    """Grade creation request."""

    student_id: int
    course: str = Field(min_length=1, max_length=160)
    score: float = Field(ge=0)
    max_score: float = Field(gt=0, le=1000)


class GradeResponse(BaseModel):
    """Grade response."""

    model_config = ConfigDict(from_attributes=True)
    id: int
    student_id: int
    course: str
    score: float
    max_score: float
    updated_at: datetime


class PIIRequest(BaseModel):
    """Sensitive fields encrypted before database storage."""

    address: str = Field(min_length=1, max_length=500)
    phone_number: str = Field(min_length=3, max_length=40)
    date_of_birth: str = Field(min_length=8, max_length=20)


class PIIResponse(BaseModel):
    """Decrypted PII response for an authorized caller."""

    student_id: int
    address: str
    phone_number: str
    date_of_birth: str


class CertificateCreate(BaseModel):
    """Certificate issue request."""

    student_id: int
    course: str = Field(min_length=1, max_length=160)


class CertificateResponse(BaseModel):
    """Certificate metadata and cryptographic proof."""

    id: int
    student_id: int
    course: str
    payload: str
    digest_sha256: str
    signature_b64: str
    issued_at: datetime
    valid: bool

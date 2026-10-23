"""Student registration and password login routes."""

from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from app.presentation.dependencies import Db
from app.presentation.schemas import RegisterRequest, UserResponse, TokenResponse
from app.application.services import PlatformService
from app.infrastructure.security.crypto import JWTService

router = APIRouter(prefix="/auth", tags=["Authentication"])
service = PlatformService()


@router.post("/register", response_model=UserResponse, status_code=201)
def register(payload: RegisterRequest, db: Db):
    """Register a student; public callers cannot select their own role."""
    try:
        return service.register_student(db, payload.full_name, str(payload.email), payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.post("/login", response_model=TokenResponse)
def login(form: Annotated[OAuth2PasswordRequestForm, Depends()], db: Db):
    """Authenticate using email in the OAuth2 username field."""
    user = service.authenticate(db, form.username, form.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Incorrect email or password",
                            headers={"WWW-Authenticate": "Bearer"})
    return TokenResponse(access_token=JWTService.create(user.id, user.role))

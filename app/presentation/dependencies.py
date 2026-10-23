"""FastAPI dependency providers for database access and authorization."""

from typing import Annotated
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session
from app.infrastructure.database.session import get_db
from app.infrastructure.database.models import UserModel
from app.infrastructure.security.crypto import JWTService

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
Db = Annotated[Session, Depends(get_db)]


def current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Db) -> UserModel:
    """Validate bearer token and load the corresponding active account."""
    try:
        claims = JWTService.decode(token)
        user_id = int(claims["sub"])
    except (JWTError, KeyError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid or expired token",
                            headers={"WWW-Authenticate": "Bearer"})
    user = db.get(UserModel, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid or inactive account")
    return user


CurrentUser = Annotated[UserModel, Depends(current_user)]


def instructor_user(user: CurrentUser) -> UserModel:
    """Require the instructor role."""
    if user.role != "instructor":
        raise HTTPException(status_code=403, detail="Instructor role required")
    return user


InstructorUser = Annotated[UserModel, Depends(instructor_user)]

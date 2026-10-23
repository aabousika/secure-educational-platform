"""FastAPI composition root: initialize persistence and register API routers."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import get_settings
from app.infrastructure.database.base import Base
from app.infrastructure.database.session import engine
from app.infrastructure.database import models  # noqa: F401
from app.presentation.routers import auth, grades, students, certificates
from pathlib import Path
from fastapi.staticfiles import StaticFiles


settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Create tables for coursework development; production should use migrations."""
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(auth.router)
app.include_router(grades.router)
app.include_router(students.router)
app.include_router(certificates.router)


@app.get("/health", tags=["Health"])
def health() -> dict[str, str]:
    """Expose a basic liveness check."""
    return {"status": "ok"}

FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"

app.mount(
    "/dashboard",
    StaticFiles(directory=str(FRONTEND_DIR), html=True),
    name="dashboard",
)
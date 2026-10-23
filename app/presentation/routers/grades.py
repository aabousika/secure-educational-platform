"""Grade routes with instructor checks and student ownership enforcement."""

from fastapi import APIRouter, HTTPException
from sqlalchemy.orm import Session
from app.application.services import PlatformService
from app.presentation.dependencies import Db, CurrentUser, InstructorUser
from app.presentation.schemas import GradeCreate, GradeResponse

router = APIRouter(prefix="/grades", tags=["Grades"])
service = PlatformService()


@router.post("", response_model=GradeResponse, status_code=201)
def create_grade(payload: GradeCreate, instructor: InstructorUser, db: Db):
    """Allow instructors to create a grade."""
    try:
        return service.create_grade(db, instructor.id, payload.student_id, payload.course,
                                    payload.score, payload.max_score)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/me", response_model=list[GradeResponse])
def my_grades(user: CurrentUser, db: Db):
    """Return the authenticated student's own grades."""
    if user.role != "student":
        raise HTTPException(status_code=403, detail="Student account required")
    return service.grades_for(db, user.id)


@router.get("/student/{student_id}", response_model=list[GradeResponse])
def grades_for_student(student_id: int, user: CurrentUser, db: Db):
    """Instructors can read any student's grades; students only their own."""
    if user.role == "student" and user.id != student_id:
        raise HTTPException(status_code=403, detail="You may only access your own grades")
    if user.role not in {"student", "instructor"}:
        raise HTTPException(status_code=403, detail="Access denied")
    return service.grades_for(db, student_id)

"""Security-monitoring routes: anomaly alerts derived from the audit log (instructors only)."""

from fastapi import APIRouter, Query
from app.application.security_monitor import SecurityMonitorService
from app.presentation.dependencies import Db, InstructorUser
from app.presentation.schemas import SecurityReportResponse

router = APIRouter(prefix="/security", tags=["Security Monitoring"])
monitor = SecurityMonitorService()


@router.get("/alerts", response_model=SecurityReportResponse)
def alerts(instructor: InstructorUser, db: Db, hours: int = Query(24, ge=1, le=168)):
    """Return rule-based and ML alerts for the last `hours` hours."""
    return monitor.analyze(db, hours=hours)

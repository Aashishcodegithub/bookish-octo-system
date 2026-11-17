from datetime import datetime, timezone
from fastapi import APIRouter
from pydantic import BaseModel

from app.core.config import settings

router = APIRouter()


class HealthCheckResponse(BaseModel):
    status: str = "healthy"
    service: str
    version: str
    environment: str
    timestamp: datetime


@router.get(
    "/health",
    response_model=HealthCheckResponse,
    summary="Liveness and Readiness Probe",
    description="Endpoint for container orchestrators, load balancers, and monitoring systems."
)
def health_check() -> HealthCheckResponse:
    return HealthCheckResponse(
        status="healthy",
        service=settings.PROJECT_NAME,
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(timezone.utc),
    )

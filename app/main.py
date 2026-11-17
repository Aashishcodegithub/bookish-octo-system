from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.api import api_router
from app.core.config import settings
from app.schemas.base import ErrorDetail, ErrorResponse


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context for startup and graceful shutdown tasks."""
    # Startup: logging initialization, warm-up caches
    yield
    # Shutdown: close connection pools, cleanup resources


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "Production-grade Fraud Detection API featuring JWT Authentication, "
        "strict Pydantic v2 validation, real-time risk scoring, and transactional filtering."
    ),
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """
    Standardized validation error handler translating Pydantic v2 validation failures
    into structured, actionable, and client-friendly error envelopes.
    """
    details = []
    for error in exc.errors():
        field_path = ".".join(str(loc) for loc in error.get("loc", []))
        message = error.get("msg", "Invalid input")
        error_type = error.get("type", "validation_error")
        details.append(
            ErrorDetail(
                field=field_path,
                issue=message,
                code=error_type,
            )
        )

    error_response = ErrorResponse(
        success=False,
        code="VALIDATION_ERROR",
        message="Request validation failed. Verify input schema details.",
        details=details,
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=error_response.model_dump(),
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """
    Global handler for HTTPExceptions ensuring consistent API error response format.
    """
    error_response = ErrorResponse(
        success=False,
        code=f"HTTP_{exc.status_code}",
        message=str(exc.detail),
        details=None,
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response.model_dump(),
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Catch-all safety net preventing internal stack trace leaks to consumers in production.
    """
    error_response = ErrorResponse(
        success=False,
        code="INTERNAL_SERVER_ERROR",
        message="An unexpected internal server error occurred." if not settings.DEBUG else str(exc),
        details=None,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_response.model_dump(),
    )


# Mount API V1 routes
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/", include_in_schema=False)
def root_redirect():
    """Quick index redirect or health indicator."""
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": f"{settings.API_V1_STR}/docs",
        "health": f"{settings.API_V1_STR}/health",
    }

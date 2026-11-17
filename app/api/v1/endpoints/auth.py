from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import get_auth_service, get_current_user
from app.core.exceptions import (
    AuthenticationException,
    DuplicateResourceException,
    TokenExpiredException,
    TokenInvalidException,
)
from app.models.user import User
from app.schemas.auth import (
    TokenRefreshRequest,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from app.services.auth_service import AuthService

router = APIRouter()


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    description="Validates input credentials using strict Pydantic rules (password complexity, email syntax) and persists user."
)
def register(
    req: UserRegisterRequest,
    service: AuthService = Depends(get_auth_service),
) -> UserResponse:
    try:
        return service.register(req)
    except DuplicateResourceException as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=e.message,
        )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive JWT tokens",
    description="Validates email and password, returning short-lived access token and refresh token."
)
def login(
    req: UserLoginRequest,
    service: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    try:
        return service.login(req)
    except AuthenticationException as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.message,
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description="Submits a valid refresh token to obtain a fresh access token without re-entering credentials."
)
def refresh_token(
    req: TokenRefreshRequest,
    service: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    try:
        return service.refresh(req)
    except (TokenExpiredException, TokenInvalidException, AuthenticationException) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
    description="Returns the profile of the currently authenticated user identified by the Bearer JWT token."
)
def get_me(current_user: User = Depends(get_current_user)) -> UserResponse:
    return UserResponse.model_validate(current_user)

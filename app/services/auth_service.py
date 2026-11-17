import uuid
from datetime import datetime, timezone
from app.core.config import settings
from app.core.exceptions import (
    AuthenticationException,
    DuplicateResourceException,
    ResourceNotFoundException,
    TokenInvalidException,
)
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_jwt_token,
    get_password_hash,
    verify_password,
)
from app.db.repository import InMemoryRepository
from app.models.user import User
from app.schemas.auth import (
    TokenRefreshRequest,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)


class AuthService:
    """Service encapsulating user registration, authentication, and token management."""

    def __init__(self, repository: InMemoryRepository):
        self.repo = repository

    def register(self, req: UserRegisterRequest) -> UserResponse:
        existing = self.repo.get_user_by_email(req.email)
        if existing:
            raise DuplicateResourceException(f"User with email '{req.email}' already exists.")

        user_id = f"usr_{uuid.uuid4().hex[:12]}"
        user = User(
            id=user_id,
            email=req.email,
            hashed_password=get_password_hash(req.password),
            full_name=req.full_name,
            role=req.role,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        saved = self.repo.create_user(user)
        return UserResponse.model_validate(saved)

    def login(self, req: UserLoginRequest) -> TokenResponse:
        user = self.repo.get_user_by_email(req.email)
        if not user:
            raise AuthenticationException("Invalid email or password.")

        if not verify_password(req.password, user.hashed_password):
            raise AuthenticationException("Invalid email or password.")

        if not user.is_active:
            raise AuthenticationException("User account is disabled.")

        # Update last login
        user.last_login_at = datetime.now(timezone.utc)
        self.repo.update_user(user)

        access_token = create_access_token(subject=user.id, role=user.role.value)
        refresh_token = create_refresh_token(subject=user.id)

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    def refresh(self, req: TokenRefreshRequest) -> TokenResponse:
        payload = decode_jwt_token(req.refresh_token, expected_type="refresh")
        user_id = payload.get("sub")
        if not user_id:
            raise TokenInvalidException("Token subject missing.")

        user = self.repo.get_user_by_id(user_id)
        if not user or not user.is_active:
            raise AuthenticationException("User not found or inactive.")

        new_access_token = create_access_token(subject=user.id, role=user.role.value)
        new_refresh_token = create_refresh_token(subject=user.id)

        return TokenResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    def get_current_user_profile(self, user_id: str) -> UserResponse:
        user = self.repo.get_user_by_id(user_id)
        if not user:
            raise ResourceNotFoundException("User not found.")
        return UserResponse.model_validate(user)

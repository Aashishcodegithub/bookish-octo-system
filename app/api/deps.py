from typing import Callable, List, Optional
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.exceptions import (
    AuthenticationException,
    PermissionDeniedException,
    TokenExpiredException,
    TokenInvalidException,
)
from app.core.security import decode_jwt_token
from app.db.repository import InMemoryRepository, get_repository
from app.models.user import User, UserRole
from app.services.auth_service import AuthService
from app.services.fraud_engine import FraudDetectionEngine
from app.services.transaction_service import TransactionService

# HTTPBearer security scheme with custom challenge header
http_bearer_scheme = HTTPBearer(
    auto_error=False,
    description="JWT Bearer token standard authentication header. Format: 'Bearer <token>'"
)


def get_auth_service(repo: InMemoryRepository = Depends(get_repository)) -> AuthService:
    return AuthService(repository=repo)


def get_fraud_engine(repo: InMemoryRepository = Depends(get_repository)) -> FraudDetectionEngine:
    return FraudDetectionEngine(repository=repo)


def get_transaction_service(
    repo: InMemoryRepository = Depends(get_repository),
    engine: FraudDetectionEngine = Depends(get_fraud_engine),
) -> TransactionService:
    return TransactionService(repository=repo, fraud_engine=engine)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(http_bearer_scheme),
    repo: InMemoryRepository = Depends(get_repository),
) -> User:
    """
    Validates JWT access token from Authorization header and extracts the authenticated User entity.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = decode_jwt_token(token, expected_type="access")
    except TokenExpiredException as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token has expired",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\", error_description=\"The token has expired\""},
        ) from e
    except TokenInvalidException as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token credentials",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        ) from e

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload: missing subject",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = repo.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account no longer exists",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )

    return user


def require_roles(allowed_roles: List[UserRole]) -> Callable[[User], User]:
    """
    Role-Based Access Control (RBAC) dependency factory.
    Enforces authorization privileges for protected administrative or analyst routes.
    """
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User role '{current_user.role.value}' does not have sufficient permissions. Required: {[r.value for r in allowed_roles]}",
            )
        return current_user

    return role_checker

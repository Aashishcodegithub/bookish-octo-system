import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import bcrypt
import jwt

from app.core.config import settings
from app.core.exceptions import TokenExpiredException, TokenInvalidException


def get_password_hash(password: str) -> str:
    """
    Generate a secure bcrypt hash of the password with salt work factor 12.
    """
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against the stored bcrypt hash using constant-time comparison.
    """
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def create_jwt_token(
    subject: str,
    token_type: str,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Issue a cryptographically signed JWT token with standardized RFC 7519 claims:
    - sub (Subject): Unique user identifier
    - iat (Issued At): UTC timestamp of issuance
    - nbf (Not Before): UTC timestamp when token becomes active
    - exp (Expiration): UTC timestamp when token expires
    - jti (JWT ID): Unique UUIDv4 token identifier for replay prevention / audit
    - type (Token Type): "access" or "refresh"
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    elif token_type == "access":
        expire = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    elif token_type == "refresh":
        expire = now + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    else:
        expire = now + timedelta(minutes=15)

    payload: Dict[str, Any] = {
        "sub": str(subject),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": str(uuid.uuid4()),
        "type": token_type,
        "iss": settings.PROJECT_NAME,
    }

    if extra_claims:
        payload.update(extra_claims)

    encoded_jwt = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt


def create_access_token(
    subject: str,
    role: str,
    extra_claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Issue a short-lived access token with role permissions.
    """
    claims = {"role": role}
    if extra_claims:
        claims.update(extra_claims)
    return create_jwt_token(
        subject=subject,
        token_type="access",
        expires_delta=expires_delta,
        extra_claims=claims,
    )


def create_refresh_token(
    subject: str,
    extra_claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Issue a long-lived refresh token strictly bounded to token renewal.
    """
    return create_jwt_token(
        subject=subject,
        token_type="refresh",
        expires_delta=expires_delta,
        extra_claims=extra_claims,
    )


def decode_jwt_token(token: str, expected_type: Optional[str] = "access") -> Dict[str, Any]:
    """
    Validate and decode a JWT token.
    - Explicit algorithm whitelist prevents algorithm confusion attacks (e.g. 'none' algorithm).
    - Checks expiration, issued-at, not-before, and expected token type.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "iat", "sub", "type"]}
        )
    except jwt.ExpiredSignatureError as e:
        raise TokenExpiredException("JWT token has expired") from e
    except jwt.InvalidTokenError as e:
        raise TokenInvalidException(f"Invalid JWT token: {str(e)}") from e

    token_type = payload.get("type")
    if expected_type and token_type != expected_type:
        raise TokenInvalidException(
            f"Expected token of type '{expected_type}', got '{token_type}'"
        )

    return payload

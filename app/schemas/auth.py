import re
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models.user import UserRole


class UserRegisterRequest(BaseModel):
    """Schema for registering a new user with strict credential validation."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    email: EmailStr = Field(
        ...,
        description="Valid email address for authentication and notifications",
        examples=["analyst@enterprise-fraud.com"]
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=64,
        description="Password must be 8-64 chars with at least one uppercase, lowercase, digit, and special symbol"
    )
    full_name: str = Field(
        ...,
        min_length=2,
        max_length=100,
        description="User's full legal or display name",
        examples=["Jane Doe"]
    )
    role: UserRole = Field(
        default=UserRole.MERCHANT,
        description="User authorization role"
    )

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter [A-Z]")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter [a-z]")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit [0-9]")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character")
        return v


class UserLoginRequest(BaseModel):
    """Schema for user credentials authentication."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    email: EmailStr = Field(..., description="Registered account email", examples=["analyst@enterprise-fraud.com"])
    password: str = Field(..., min_length=1, description="Account password")


class TokenResponse(BaseModel):
    """Standardized OAuth2/JWT token response."""
    access_token: str = Field(..., description="Cryptographically signed short-lived JWT access token")
    refresh_token: str = Field(..., description="Cryptographically signed long-lived refresh token")
    token_type: str = Field("bearer", description="Token type according to RFC 6750")
    expires_in: int = Field(..., description="Access token expiration period in seconds")


class TokenRefreshRequest(BaseModel):
    """Schema for obtaining a new access token via refresh token."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    refresh_token: str = Field(..., description="Valid refresh token previously issued")


class TokenPayload(BaseModel):
    """Internal model for decoded JWT claims."""
    sub: str = Field(..., description="Subject identifier (User ID)")
    role: str = Field(..., description="User role assigned in token")
    type: str = Field(..., description="Token type: access or refresh")
    jti: str = Field(..., description="Unique JWT ID")
    iat: int = Field(..., description="Issued at timestamp (UTC)")
    exp: int = Field(..., description="Expiration timestamp (UTC)")


class UserResponse(BaseModel):
    """Public user profile representation without credential leakage."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: EmailStr
    full_name: str
    role: UserRole
    is_active: bool
    created_at: datetime

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    MERCHANT = "merchant"


class User(BaseModel):
    """Internal Domain Model for User."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    hashed_password: str
    full_name: str
    role: UserRole = UserRole.MERCHANT
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login_at: Optional[datetime] = None

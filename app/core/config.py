from typing import List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application Settings loaded from environment variables or .env file.
    Uses Pydantic v2 BaseSettings for type enforcement and validation.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    # Core Application
    PROJECT_NAME: str = "Enterprise Fraud Detection API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"

    # Security & JWT Configuration
    JWT_SECRET_KEY: str = Field(
        default="09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7",
        min_length=32,
        description="Cryptographic secret key for signing JWT tokens. Must be >= 32 characters in production."
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, ge=1, le=1440)
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, ge=1, le=90)

    # Fraud Detection Engine Parameters
    FRAUD_HIGH_RISK_THRESHOLD: int = Field(default=75, ge=0, le=100)
    FRAUD_REVIEW_THRESHOLD: int = Field(default=45, ge=0, le=100)
    FRAUD_MAX_SINGLE_TRANSACTION_AMOUNT: float = Field(default=25000.00, gt=0)
    FRAUD_VELOCITY_WINDOW_SECONDS: int = Field(default=300, ge=10)
    FRAUD_VELOCITY_MAX_COUNT: int = Field(default=5, ge=1)
    FRAUD_IMPOSSIBLE_TRAVEL_KMH: float = Field(default=900.0, gt=0)

    # CORS
    CORS_ORIGINS: List[str] = ["*"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        return v


settings = Settings()

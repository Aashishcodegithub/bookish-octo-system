from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

from app.models.transaction import TransactionStatus
from app.schemas.transaction import TransactionCreate


class RiskSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskFactorDetail(BaseModel):
    """Granular audit trail item for a triggered fraud risk heuristic."""
    code: str = Field(..., description="Unique machine-readable heuristic code (e.g., HIGH_VELOCITY)")
    severity: RiskSeverity = Field(..., description="Risk severity tier")
    description: str = Field(..., description="Detailed explanation of the heuristic trigger")
    score_impact: int = Field(..., ge=0, le=100, description="Additive risk score contribution")


class FraudEvaluationResponse(BaseModel):
    """Result of real-time fraud scoring evaluation."""
    decision: TransactionStatus = Field(..., description="Evaluation decision: APPROVED, FLAGGED, or REJECTED")
    risk_score: int = Field(..., ge=0, le=100, description="Composite risk score from 0 (safest) to 100 (highest risk)")
    risk_level: str = Field(..., description="Categorical risk tier: LOW, MEDIUM, or HIGH")
    factors: List[RiskFactorDetail] = Field(default_factory=list, description="Breakdown of all triggered risk heuristics")
    evaluated_at: datetime = Field(..., description="UTC timestamp of evaluation")

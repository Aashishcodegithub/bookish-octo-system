from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class TransactionStatus(str, Enum):
    APPROVED = "APPROVED"
    FLAGGED = "FLAGGED"
    REJECTED = "REJECTED"


class PaymentMethod(str, Enum):
    CREDIT_CARD = "CREDIT_CARD"
    DEBIT_CARD = "DEBIT_CARD"
    WIRE_TRANSFER = "WIRE_TRANSFER"
    DIGITAL_WALLET = "DIGITAL_WALLET"


class Transaction(BaseModel):
    """Internal Domain Model for a Financial Transaction and its Risk Assessment."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    account_id: str
    amount: Decimal
    currency: str
    payment_method: PaymentMethod
    merchant_id: str
    merchant_category_code: str
    ip_address: str
    device_fingerprint: str
    card_bin: Optional[str] = None
    card_last4: Optional[str] = None
    card_fingerprint: Optional[str] = None
    geo_latitude: Optional[float] = None
    geo_longitude: Optional[float] = None
    geo_country: Optional[str] = None
    status: TransactionStatus = TransactionStatus.APPROVED
    risk_score: int = 0
    risk_factors: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

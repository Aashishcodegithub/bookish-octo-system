from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional, Set
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    field_validator,
    model_validator,
)

from app.models.transaction import PaymentMethod, TransactionStatus

# Standard supported ISO 4217 Currency Codes
SUPPORTED_CURRENCIES: Set[str] = {
    "USD", "EUR", "GBP", "CAD", "AUD", "JPY", "CHF", "INR", "SGD", "HKD"
}


def luhn_checksum_is_valid(card_number: str) -> bool:
    """
    Validates card number using the ISO/IEC 7812 Luhn formula (mod 10 algorithm).
    """
    clean_digits = "".join(filter(str.isdigit, card_number))
    if len(clean_digits) < 13 or len(clean_digits) > 19:
        return False

    checksum = 0
    reverse_digits = clean_digits[::-1]

    for index, char in enumerate(reverse_digits):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit

    return checksum % 10 == 0


class CardDetails(BaseModel):
    """
    Strict payment card model with Luhn algorithm validation and expiration checking.
    PCI-DSS awareness: Raw card details are validated at ingress and never persisted in plaintext.
    """
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    card_number: str = Field(
        ...,
        description="13-19 digit card PAN validated via the Luhn algorithm",
        examples=["4532015112830366"]
    )
    exp_month: int = Field(
        ...,
        ge=1,
        le=12,
        description="Two-digit card expiration month (1-12)"
    )
    exp_year: int = Field(
        ...,
        ge=2000,
        le=2099,
        description="Four-digit card expiration year"
    )
    cvv: str = Field(
        ...,
        pattern=r"^\d{3,4}$",
        description="3 or 4 digit card verification value (CVV/CVC)"
    )

    @field_validator("card_number")
    @classmethod
    def validate_luhn_and_digits(cls, v: str) -> str:
        clean = v.replace(" ", "").replace("-", "")
        if not clean.isdigit():
            raise ValueError("Card number must contain only numeric digits")
        if not luhn_checksum_is_valid(clean):
            raise ValueError("Invalid card number: failed Luhn checksum verification")
        return clean

    @model_validator(mode="after")
    def validate_not_expired(self) -> "CardDetails":
        now = datetime.now(timezone.utc)
        current_year = now.year
        current_month = now.month

        if self.exp_year < current_year or (self.exp_year == current_year and self.exp_month < current_month):
            raise ValueError("Card is expired")
        return self


class GeoLocation(BaseModel):
    """Geographic coordinates for anomaly and impossible-travel detection."""
    model_config = ConfigDict(extra="forbid")

    latitude: float = Field(..., ge=-90.0, le=90.0, description="Latitude from -90 to +90")
    longitude: float = Field(..., ge=-180.0, le=180.0, description="Longitude from -180 to +180")
    country_code: str = Field(..., pattern=r"^[A-Z]{2}$", description="ISO 3166-1 alpha-2 two-letter uppercase country code")


class TransactionCreate(BaseModel):
    """
    Enterprise transaction ingestion schema.
    Includes comprehensive input validation across financial amounts, IDs, IP addresses, and metadata.
    """
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    account_id: str = Field(
        ...,
        pattern=r"^acc_[a-zA-Z0-9_\-]{6,32}$",
        description="Unique customer account identifier, prefixed with 'acc_'",
        examples=["acc_usr94821a"]
    )
    amount: Decimal = Field(
        ...,
        gt=Decimal("0.00"),
        decimal_places=2,
        max_digits=12,
        description="Transaction amount in decimal currency representation (precision: 2 decimals, positive)",
        examples=[Decimal("249.50")]
    )
    currency: str = Field(
        ...,
        description="ISO 4217 3-letter currency code",
        examples=["USD"]
    )
    payment_method: PaymentMethod = Field(
        ...,
        description="Method of payment"
    )
    card: Optional[CardDetails] = Field(
        None,
        description="Card details. Mandatory when payment_method is CREDIT_CARD or DEBIT_CARD."
    )
    merchant_id: str = Field(
        ...,
        pattern=r"^mch_[a-zA-Z0-9_\-]{6,24}$",
        description="Merchant entity identifier, prefixed with 'mch_'",
        examples=["mch_retail01"]
    )
    merchant_category_code: str = Field(
        ...,
        pattern=r"^\d{4}$",
        description="4-digit ISO 18245 Merchant Category Code (MCC)",
        examples=["5411"]
    )
    ip_address: IPvAnyAddress = Field(
        ...,
        description="Client IPv4 or IPv6 address",
        examples=["198.51.100.42"]
    )
    device_fingerprint: str = Field(
        ...,
        min_length=16,
        max_length=128,
        pattern=r"^[a-zA-Z0-9_\-]+$",
        description="Client device fingerprint hash",
        examples=["dfp_8f93e2b10a4c5d6e7f8a9b0c"]
    )
    location: Optional[GeoLocation] = Field(
        None,
        description="Geographic coordinates at transaction origination"
    )
    transaction_time: Optional[datetime] = Field(
        default=None,
        description="UTC transaction timestamp (defaults to current server UTC time if omitted)"
    )

    @field_validator("currency")
    @classmethod
    def validate_currency_code(cls, v: str) -> str:
        upper_curr = v.upper()
        if upper_curr not in SUPPORTED_CURRENCIES:
            raise ValueError(
                f"Unsupported currency '{v}'. Must be one of: {', '.join(sorted(SUPPORTED_CURRENCIES))}"
            )
        return upper_curr

    @field_validator("transaction_time")
    @classmethod
    def validate_transaction_time_bounds(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is None:
            return v
        now = datetime.now(timezone.utc)
        # Ensure timezone-aware UTC
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)

        diff_seconds = (v - now).total_seconds()
        # Disallow timestamps more than 5 minutes in the future (clock drift buffer)
        if diff_seconds > 300:
            raise ValueError("Transaction timestamp cannot be in the future")
        # Disallow timestamps older than 90 days
        if diff_seconds < -7776000:
            raise ValueError("Transaction timestamp cannot be older than 90 days")
        return v

    @model_validator(mode="after")
    def validate_card_presence(self) -> "TransactionCreate":
        if self.payment_method in (PaymentMethod.CREDIT_CARD, PaymentMethod.DEBIT_CARD):
            if self.card is None:
                raise ValueError(
                    f"Card details are required when payment_method is {self.payment_method.value}"
                )
        return self


class TransactionResponse(BaseModel):
    """
    Public sanitized transaction representation.
    Guarantees zero leakage of sensitive PAN or CVV information.
    """
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
    card_bin: Optional[str] = None
    card_last4: Optional[str] = None
    geo_country: Optional[str] = None
    status: TransactionStatus
    risk_score: int
    risk_factors: list[str] = Field(default_factory=list)
    created_at: datetime

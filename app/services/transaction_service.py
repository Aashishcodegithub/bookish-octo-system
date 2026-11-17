import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

from app.core.exceptions import ResourceNotFoundException
from app.db.repository import InMemoryRepository
from app.models.transaction import Transaction
from app.schemas.pagination import PaginatedResponse, PaginationParams, TransactionFilterParams
from app.schemas.transaction import TransactionCreate, TransactionResponse
from app.services.fraud_engine import FraudDetectionEngine


class TransactionService:
    """Service handling financial transaction intake, fraud scoring orchestration, and querying."""

    def __init__(self, repository: InMemoryRepository, fraud_engine: FraudDetectionEngine):
        self.repo = repository
        self.fraud_engine = fraud_engine

    def process_transaction(self, user_id: str, txn_in: TransactionCreate) -> TransactionResponse:
        # Run real-time fraud scoring evaluation
        fraud_result = self.fraud_engine.evaluate(txn_in)

        # Sanitize sensitive cardholder PAN data (PCI-DSS compliance)
        card_bin = None
        card_last4 = None
        card_fingerprint = None
        if txn_in.card:
            clean_pan = txn_in.card.card_number
            card_bin = clean_pan[:6]
            card_last4 = clean_pan[-4:]
            card_fingerprint = hashlib.sha256(clean_pan.encode("utf-8")).hexdigest()

        txn_id = f"txn_{uuid.uuid4().hex[:16]}"
        now = txn_in.transaction_time or datetime.now(timezone.utc)

        transaction = Transaction(
            id=txn_id,
            user_id=user_id,
            account_id=txn_in.account_id,
            amount=txn_in.amount,
            currency=txn_in.currency,
            payment_method=txn_in.payment_method,
            merchant_id=txn_in.merchant_id,
            merchant_category_code=txn_in.merchant_category_code,
            ip_address=str(txn_in.ip_address),
            device_fingerprint=txn_in.device_fingerprint,
            card_bin=card_bin,
            card_last4=card_last4,
            card_fingerprint=card_fingerprint,
            geo_latitude=txn_in.location.latitude if txn_in.location else None,
            geo_longitude=txn_in.location.longitude if txn_in.location else None,
            geo_country=txn_in.location.country_code if txn_in.location else None,
            status=fraud_result.decision,
            risk_score=fraud_result.risk_score,
            risk_factors=[f.code for f in fraud_result.factors],
            created_at=now,
        )

        saved = self.repo.save_transaction(transaction)
        return TransactionResponse.model_validate(saved)

    def get_transaction(self, transaction_id: str, user_id_scope: Optional[str] = None) -> TransactionResponse:
        txn = self.repo.get_transaction_by_id(transaction_id)
        if not txn:
            raise ResourceNotFoundException(f"Transaction '{transaction_id}' not found.")

        # If a non-admin scope is provided, ensure user owns the transaction
        if user_id_scope and txn.user_id != user_id_scope:
            raise ResourceNotFoundException(f"Transaction '{transaction_id}' not found.")

        return TransactionResponse.model_validate(txn)

    def list_transactions(
        self,
        filters: TransactionFilterParams,
        pagination: PaginationParams,
        user_id_scope: Optional[str] = None,
    ) -> PaginatedResponse[TransactionResponse]:
        txns, total = self.repo.filter_transactions(
            filters=filters,
            pagination=pagination,
            user_id_scope=user_id_scope,
        )
        items = [TransactionResponse.model_validate(t) for t in txns]
        return PaginatedResponse.create(items=items, total=total, params=pagination)

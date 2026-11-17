from copy import deepcopy
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from app.db.repository import repository
from app.models.transaction import Transaction, TransactionStatus, PaymentMethod
from app.schemas.transaction import TransactionCreate
from app.services.fraud_engine import FraudDetectionEngine


def test_fraud_engine_normal_transaction(valid_transaction_payload):
    engine = FraudDetectionEngine(repository=repository)
    txn = TransactionCreate.model_validate(valid_transaction_payload)
    result = engine.evaluate(txn)

    assert result.decision == TransactionStatus.APPROVED
    assert result.risk_score < 45
    assert result.risk_level == "LOW"


def test_fraud_engine_blacklisted_ip(valid_transaction_payload):
    engine = FraudDetectionEngine(repository=repository)
    payload = deepcopy(valid_transaction_payload)
    payload["ip_address"] = "203.0.113.195"  # Pre-seeded blacklisted IP

    txn = TransactionCreate.model_validate(payload)
    result = engine.evaluate(txn)

    assert result.decision == TransactionStatus.REJECTED
    assert result.risk_score == 100
    assert any(f.code == "BLACKLISTED_IP" for f in result.factors)


def test_fraud_engine_excessive_amount(valid_transaction_payload):
    engine = FraudDetectionEngine(repository=repository)
    payload = deepcopy(valid_transaction_payload)
    payload["amount"] = "35000.00"  # Exceeds 25000 limit

    txn = TransactionCreate.model_validate(payload)
    result = engine.evaluate(txn)

    assert any(f.code == "EXCESSIVE_TRANSACTION_AMOUNT" for f in result.factors)
    assert result.risk_score >= 50
    assert result.decision in (TransactionStatus.FLAGGED, TransactionStatus.REJECTED)


def test_fraud_engine_high_risk_mcc(valid_transaction_payload):
    engine = FraudDetectionEngine(repository=repository)
    payload = deepcopy(valid_transaction_payload)
    payload["merchant_category_code"] = "7995"  # Gambling

    txn = TransactionCreate.model_validate(payload)
    result = engine.evaluate(txn)

    assert any(f.code == "HIGH_RISK_MCC" for f in result.factors)


def test_fraud_engine_velocity_spike(valid_transaction_payload):
    engine = FraudDetectionEngine(repository=repository)
    account_id = "acc_velocity_test_user"

    # Pre-populate 5 recent transactions in the repository within the last 2 minutes
    now = datetime.now(timezone.utc)
    for i in range(5):
        txn = Transaction(
            id=f"txn_vel_{i}",
            user_id="usr_test",
            account_id=account_id,
            amount=Decimal("10.00"),
            currency="USD",
            payment_method=PaymentMethod.CREDIT_CARD,
            merchant_id="mch_store",
            merchant_category_code="5411",
            ip_address="198.51.100.1",
            device_fingerprint="dfp_1234567890123456",
            status=TransactionStatus.APPROVED,
            risk_score=0,
            risk_factors=[],
            created_at=now - timedelta(seconds=i * 20),
        )
        repository.save_transaction(txn)

    payload = deepcopy(valid_transaction_payload)
    payload["account_id"] = account_id

    txn = TransactionCreate.model_validate(payload)
    result = engine.evaluate(txn)

    assert any(f.code == "VELOCITY_SPIKE" for f in result.factors)
    assert result.risk_score >= 40


def test_fraud_engine_impossible_travel(valid_transaction_payload):
    engine = FraudDetectionEngine(repository=repository)
    account_id = "acc_travel_test_user"
    now = datetime.now(timezone.utc)

    # 1 hour ago: transaction in New York (lat 40.7128, lon -74.0060)
    prev_txn = Transaction(
        id="txn_ny_01",
        user_id="usr_test",
        account_id=account_id,
        amount=Decimal("50.00"),
        currency="USD",
        payment_method=PaymentMethod.CREDIT_CARD,
        merchant_id="mch_ny_store",
        merchant_category_code="5411",
        ip_address="198.51.100.2",
        device_fingerprint="dfp_1234567890123456",
        geo_latitude=40.7128,
        geo_longitude=-74.0060,
        geo_country="US",
        status=TransactionStatus.APPROVED,
        risk_score=0,
        risk_factors=[],
        created_at=now - timedelta(minutes=45),
    )
    repository.save_transaction(prev_txn)

    # Now: transaction in London (lat 51.5074, lon -0.1278) -> ~5,500 km in 45 minutes = ~7,300 km/h (impossible!)
    payload = deepcopy(valid_transaction_payload)
    payload["account_id"] = account_id
    payload["location"] = {
        "latitude": 51.5074,
        "longitude": -0.1278,
        "country_code": "GB",
    }

    txn = TransactionCreate.model_validate(payload)
    result = engine.evaluate(txn)

    assert any(f.code == "IMPOSSIBLE_TRAVEL_VELOCITY" for f in result.factors)
    assert result.risk_score >= 60

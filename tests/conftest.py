from datetime import datetime, timezone
from decimal import Decimal
from typing import Dict, Generator
import pytest
from fastapi.testclient import TestClient

from app.core.security import create_access_token
from app.db.repository import repository
from app.main import app
from app.models.user import User, UserRole


@pytest.fixture(scope="session")
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def admin_headers() -> Dict[str, str]:
    token = create_access_token(subject="usr_admin_001", role=UserRole.ADMIN.value)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers() -> Dict[str, str]:
    token = create_access_token(subject="usr_analyst_001", role=UserRole.ANALYST.value)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def merchant_user() -> User:
    merchant = User(
        id="usr_merchant_001",
        email="merchant@store.com",
        hashed_password="hashed_pw_test",
        full_name="Merchant Test Store",
        role=UserRole.MERCHANT,
        is_active=True,
    )
    if not repository.get_user_by_id(merchant.id):
        repository.create_user(merchant)
    return merchant


@pytest.fixture
def merchant_headers(merchant_user: User) -> Dict[str, str]:
    token = create_access_token(subject=merchant_user.id, role=merchant_user.role.value)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def valid_transaction_payload() -> dict:
    """Returns a valid transaction payload with a Luhn-compliant card number."""
    return {
        "account_id": "acc_cust123456",
        "amount": "149.99",
        "currency": "USD",
        "payment_method": "CREDIT_CARD",
        "card": {
            "card_number": "4532015112830366",  # Valid Luhn Visa test number
            "exp_month": 12,
            "exp_year": 2028,
            "cvv": "921",
        },
        "merchant_id": "mch_superstore1",
        "merchant_category_code": "5411",  # Grocery stores / supermarkets
        "ip_address": "198.51.100.42",
        "device_fingerprint": "dfp_a1b2c3d4e5f6789012345678",
        "location": {
            "latitude": 37.7749,
            "longitude": -122.4194,
            "country_code": "US",
        },
    }

from copy import deepcopy
from decimal import Decimal
import pytest
from pydantic import ValidationError

from app.schemas.transaction import CardDetails, TransactionCreate, luhn_checksum_is_valid


def test_luhn_algorithm():
    # Valid credit card numbers passing Luhn checksum
    assert luhn_checksum_is_valid("4532015112830366") is True  # Visa
    assert luhn_checksum_is_valid("5425233430109903") is True  # Mastercard
    assert luhn_checksum_is_valid("378282246310005") is True   # Amex

    # Altering the last digit breaks the checksum
    assert luhn_checksum_is_valid("4532015112830367") is False
    assert luhn_checksum_is_valid("5425233430109904") is False

    # Invalid lengths
    assert luhn_checksum_is_valid("1234") is False


def test_card_details_valid():
    card = CardDetails(
        card_number="4532015112830366",
        exp_month=11,
        exp_year=2028,
        cvv="123",
    )
    assert card.card_number == "4532015112830366"
    assert card.exp_month == 11
    assert card.exp_year == 2028
    assert card.cvv == "123"


def test_card_details_expired_fails():
    with pytest.raises(ValidationError) as exc:
        CardDetails(
            card_number="4532015112830366",
            exp_month=1,
            exp_year=2020,  # Expired
            cvv="123",
        )
    assert "Card is expired" in str(exc.value)


def test_card_details_invalid_luhn_fails():
    with pytest.raises(ValidationError) as exc:
        CardDetails(
            card_number="4532015112830367",  # Bad checksum
            exp_month=12,
            exp_year=2028,
            cvv="123",
        )
    assert "failed Luhn checksum" in str(exc.value)


def test_card_details_invalid_cvv():
    with pytest.raises(ValidationError):
        CardDetails(
            card_number="4532015112830366",
            exp_month=12,
            exp_year=2028,
            cvv="12",  # Too short (needs 3-4 digits)
        )


def test_transaction_create_valid(valid_transaction_payload):
    txn = TransactionCreate.model_validate(valid_transaction_payload)
    assert txn.amount == Decimal("149.99")
    assert txn.currency == "USD"
    assert str(txn.ip_address) == "198.51.100.42"


def test_transaction_create_negative_amount_fails(valid_transaction_payload):
    payload = deepcopy(valid_transaction_payload)
    payload["amount"] = "-50.00"
    with pytest.raises(ValidationError) as exc:
        TransactionCreate.model_validate(payload)
    assert "Input should be greater than 0" in str(exc.value)


def test_transaction_create_zero_amount_fails(valid_transaction_payload):
    payload = deepcopy(valid_transaction_payload)
    payload["amount"] = "0.00"
    with pytest.raises(ValidationError) as exc:
        TransactionCreate.model_validate(payload)
    assert "Input should be greater than 0" in str(exc.value)


def test_transaction_create_unsupported_currency_fails(valid_transaction_payload):
    payload = deepcopy(valid_transaction_payload)
    payload["currency"] = "BTC"  # Only ISO fiat codes allowed in this rule
    with pytest.raises(ValidationError) as exc:
        TransactionCreate.model_validate(payload)
    assert "Unsupported currency 'BTC'" in str(exc.value)


def test_transaction_create_invalid_account_pattern(valid_transaction_payload):
    payload = deepcopy(valid_transaction_payload)
    payload["account_id"] = "invalid_no_acc_prefix"
    with pytest.raises(ValidationError):
        TransactionCreate.model_validate(payload)


def test_transaction_create_invalid_ip_fails(valid_transaction_payload):
    payload = deepcopy(valid_transaction_payload)
    payload["ip_address"] = "300.400.500.600"
    with pytest.raises(ValidationError):
        TransactionCreate.model_validate(payload)


def test_transaction_create_invalid_geolocation(valid_transaction_payload):
    payload = deepcopy(valid_transaction_payload)
    payload["location"]["latitude"] = 999.0  # Latitude max is 90.0
    with pytest.raises(ValidationError):
        TransactionCreate.model_validate(payload)


def test_transaction_missing_card_for_credit_card_method(valid_transaction_payload):
    payload = deepcopy(valid_transaction_payload)
    payload["payment_method"] = "CREDIT_CARD"
    payload["card"] = None
    with pytest.raises(ValidationError) as exc:
        TransactionCreate.model_validate(payload)
    assert "Card details are required when payment_method is CREDIT_CARD" in str(exc.value)


def test_api_422_standardized_error_response(client, merchant_headers):
    # Malformed payload to trigger custom RequestValidationError handler
    bad_payload = {
        "account_id": "bad_id",
        "amount": "-10.00",
        "currency": "FAKE",
        "payment_method": "CREDIT_CARD",
        "merchant_id": "invalid",
        "merchant_category_code": "12",  # MCC must be 4 digits
        "ip_address": "not_an_ip",
        "device_fingerprint": "short",
    }
    response = client.post("/api/v1/transactions/", json=bad_payload, headers=merchant_headers)
    assert response.status_code == 422
    body = response.json()
    assert body["success"] is False
    assert body["code"] == "VALIDATION_ERROR"
    assert "details" in body
    assert len(body["details"]) > 0
    # Every detail must contain field, issue, and code
    for detail in body["details"]:
        assert "field" in detail
        assert "issue" in detail
        assert "code" in detail

from copy import deepcopy
from decimal import Decimal
from fastapi.testclient import TestClient


def test_submit_transaction_unauthenticated(client: TestClient, valid_transaction_payload):
    response = client.post("/api/v1/transactions/", json=valid_transaction_payload)
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers


def test_submit_transaction_authenticated(client: TestClient, merchant_headers, valid_transaction_payload):
    response = client.post("/api/v1/transactions/", json=valid_transaction_payload, headers=merchant_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["id"].startswith("txn_")
    assert data["amount"] == "149.99"
    assert data["currency"] == "USD"
    assert data["status"] == "APPROVED"
    assert data["risk_score"] < 45
    # PCI-DSS Check: Ensure no raw PAN or CVV is leaked
    assert "card" not in data
    assert "card_number" not in data
    assert "cvv" not in data
    assert data["card_bin"] == "453201"
    assert data["card_last4"] == "0366"


def test_evaluate_endpoint_dry_run(client: TestClient, merchant_headers, valid_transaction_payload):
    response = client.post("/api/v1/transactions/evaluate", json=valid_transaction_payload, headers=merchant_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "APPROVED"
    assert "risk_score" in data
    assert "factors" in data


def test_list_transactions_pagination_and_scoping(
    client: TestClient, merchant_headers, analyst_headers, valid_transaction_payload
):
    # Create 3 transactions for merchant
    for i in range(3):
        payload = deepcopy(valid_transaction_payload)
        payload["amount"] = f"{(i + 1) * 25}.00"
        client.post("/api/v1/transactions/", json=payload, headers=merchant_headers)

    # Merchant queries transactions
    res_merchant = client.get("/api/v1/transactions/?page=1&limit=2", headers=merchant_headers)
    assert res_merchant.status_code == 200
    data_m = res_merchant.json()
    assert data_m["page"] == 1
    assert data_m["limit"] == 2
    assert len(data_m["items"]) == 2
    assert data_m["has_next"] is True
    assert data_m["has_prev"] is False

    # Analyst queries transactions (sees all records)
    res_analyst = client.get("/api/v1/transactions/?page=1&limit=10", headers=analyst_headers)
    assert res_analyst.status_code == 200
    data_a = res_analyst.json()
    assert data_a["total"] >= 3


def test_filtering_and_sorting(client: TestClient, merchant_headers, valid_transaction_payload):
    # Filter by min_amount and sort by amount asc
    res = client.get(
        "/api/v1/transactions/?min_amount=40.00&sort_by=amount&sort_order=asc",
        headers=merchant_headers,
    )
    assert res.status_code == 200
    items = res.json()["items"]
    if len(items) >= 2:
        assert Decimal(items[0]["amount"]) <= Decimal(items[1]["amount"])
    for item in items:
        assert Decimal(item["amount"]) >= Decimal("40.00")

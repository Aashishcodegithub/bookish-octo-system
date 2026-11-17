from datetime import timedelta
import jwt
import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.exceptions import TokenExpiredException, TokenInvalidException
from app.core.security import (
    create_access_token,
    create_jwt_token,
    create_refresh_token,
    decode_jwt_token,
    get_password_hash,
    verify_password,
)


def test_password_hashing():
    raw = "SecureP@ssw0rd!"
    hashed = get_password_hash(raw)
    assert hashed != raw
    assert verify_password(raw, hashed) is True
    assert verify_password("WrongP@ssw0rd!", hashed) is False


def test_jwt_token_creation_and_decoding():
    token = create_access_token(subject="user_123", role="merchant")
    payload = decode_jwt_token(token, expected_type="access")
    assert payload["sub"] == "user_123"
    assert payload["role"] == "merchant"
    assert payload["type"] == "access"
    assert "jti" in payload
    assert "exp" in payload


def test_jwt_token_expiration():
    expired_token = create_jwt_token(
        subject="user_123",
        token_type="access",
        expires_delta=timedelta(seconds=-10),  # expired 10s ago
    )
    with pytest.raises(TokenExpiredException):
        decode_jwt_token(expired_token, expected_type="access")


def test_jwt_tampered_signature():
    token = create_access_token(subject="user_123", role="merchant")
    # Tamper payload
    header, payload_part, signature = token.split(".")
    tampered_token = f"{header}.eyAidXNlciI6ICJoYWNrZXIiIH0.{signature}"
    with pytest.raises(TokenInvalidException):
        decode_jwt_token(tampered_token, expected_type="access")


def test_jwt_algorithm_confusion_rejection():
    # Attempting 'none' algorithm token
    none_token = jwt.encode({"sub": "user_123", "type": "access", "exp": 9999999999, "iat": 1}, key="", algorithm="none")
    with pytest.raises(TokenInvalidException):
        decode_jwt_token(none_token, expected_type="access")


def test_jwt_wrong_type_rejected():
    refresh_token = create_refresh_token(subject="user_123")
    # Expecting access token, passing refresh token
    with pytest.raises(TokenInvalidException):
        decode_jwt_token(refresh_token, expected_type="access")


def test_user_registration_success(client: TestClient):
    payload = {
        "email": "newuser@enterprise.com",
        "password": "ValidP@ssw0rd123",
        "full_name": "New User",
        "role": "merchant",
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "newuser@enterprise.com"
    assert data["full_name"] == "New User"
    assert "password" not in data
    assert "hashed_password" not in data


def test_user_registration_duplicate_email(client: TestClient):
    payload = {
        "email": "duplicate@enterprise.com",
        "password": "ValidP@ssw0rd123",
        "full_name": "Original User",
    }
    res1 = client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 201

    res2 = client.post("/api/v1/auth/register", json=payload)
    assert res2.status_code == 409
    assert res2.json()["code"] == "HTTP_409"


@pytest.mark.parametrize("invalid_password,expected_error", [
    ("short1!", "at least 8 characters"),
    ("alllowercase1!", "uppercase letter"),
    ("ALLUPPERCASE1!", "lowercase letter"),
    ("NoDigitsHere!", "at least one digit"),
    ("NoSpecialChars123", "special character"),
])
def test_password_strength_validation(client: TestClient, invalid_password, expected_error):
    payload = {
        "email": "testpw@enterprise.com",
        "password": invalid_password,
        "full_name": "Test PW",
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "VALIDATION_ERROR"
    assert any(expected_error in d["issue"] for d in body["details"])


def test_login_flow(client: TestClient):
    # Use pre-seeded admin credentials
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@enterprise-fraud.com", "password": "Admin123!@#"},
    )
    assert response.status_code == 200
    tokens = response.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens
    assert tokens["token_type"] == "bearer"
    assert tokens["expires_in"] == settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60

    # Test protected /me endpoint with received access token
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    me_resp = client.get("/api/v1/auth/me", headers=headers)
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "admin@enterprise-fraud.com"
    assert me_resp.json()["role"] == "admin"


def test_login_invalid_credentials(client: TestClient):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@enterprise-fraud.com", "password": "WrongPassword123!"},
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers


def test_token_refresh_flow(client: TestClient):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@enterprise-fraud.com", "password": "Admin123!@#"},
    )
    refresh_token = login_resp.json()["refresh_token"]

    refresh_resp = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_resp.status_code == 200
    new_tokens = refresh_resp.json()
    assert "access_token" in new_tokens
    assert "refresh_token" in new_tokens


def test_token_refresh_with_access_token_rejected(client: TestClient):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@enterprise-fraud.com", "password": "Admin123!@#"},
    )
    access_token = login_resp.json()["access_token"]

    # Passing access token to refresh endpoint must fail
    refresh_resp = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": access_token},
    )
    assert refresh_resp.status_code == 401

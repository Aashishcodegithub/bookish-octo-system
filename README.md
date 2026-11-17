# Enterprise Fraud Detection Starter Kit

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![Pydantic v2](https://img.shields.io/badge/Pydantic-v2.8+-e92063.svg)](https://docs.pydantic.dev/)
[![Tests](https://img.shields.io/badge/tests-42%20passed-brightgreen.svg)]()

Production-grade Fraud Detection Backend API engineered with **FastAPI**, **JWT Authentication (RFC 7519)**, **strict Pydantic v2 schema validation**, a **real-time heuristic fraud engine**, and **enterprise pagination & filtering**.

Designed specifically to address the architectural patterns and edge-case defenses that senior backend screeners look for.

---

## 🎯 What Backend Screeners Look For (Implemented Here)

Backend screeners and hiring committees review backend code to see whether an engineer understands real-world security, domain constraints, and production rigor. Here is how this codebase addresses each screening checkpoint:

| Screener Checkpoint | Common Junior Pitfall | Enterprise Implementation in this Repo |
| :--- | :--- | :--- |
| **Monetary Amounts** | Using `float` (subject to IEEE 754 precision errors) | Strict `Decimal` with fixed scale (`max_digits=12`, `decimal_places=2`, `gt=0.00`). |
| **Card Data Handling** | Storing or logging raw PANs or ignoring checksums | ISO/IEC 7812 **Luhn algorithm (mod 10)** checksum validation at ingress. Zero storage or leakage of PAN/CVV; only `card_bin` and `card_last4` exposed. |
| **JWT Architecture** | Storing sensitive data in claims, no `type` separation | Standard RFC 7519 claims (`sub`, `iat`, `exp`, `nbf`, `jti`, `type`). Explicit token type enforcement prevents using access tokens as refresh tokens and vice-versa. |
| **Algorithm Attacks** | Accepting whatever algorithm is in the token header | Strict whitelist verification (`algorithms=["HS256"]`) preventing algorithm confusion attacks (e.g., CVE-2015-9235 "none" algorithm). |
| **Password Hashing** | SHA256 / MD5 or un-salted hashes | **Bcrypt** with salt work factor 12 and constant-time password verification. |
| **Pydantic Validation** | Relying on default FastAPI 422 error dictionaries | Custom `RequestValidationError` handler transforming raw errors into structured, client-actionable error envelopes with specific field paths and error codes. |
| **Domain Validation** | Generic string fields for IPs, Currencies, and Dates | `IPvAnyAddress`, ISO 4217 Currency Whitelist, ISO 3166-1 country codes, 4-digit ISO 18245 MCCs, and UTC timestamp drift bounds (-90 days to +5 mins). |
| **Authorization / RBAC** | Relying on simple boolean checks | Dependency injection with reusable `require_roles([Role.ADMIN, Role.ANALYST])` enforcing principle of least privilege and multi-tenant data scoping. |

---

## 🏗️ Architecture & Project Structure

```
Fraud_Detection_Starter_Kit/
├── app/
│   ├── api/
│   │   ├── deps.py                      # FastAPI dependencies (JWT Auth, RBAC, Service injection)
│   │   └── v1/
│   │       ├── api.py                   # Central API v1 router aggregator
│   │       └── endpoints/
│   │           ├── auth.py              # Register, login, refresh, me endpoints
│   │           ├── transactions.py      # Ingest, list, filter, and evaluate transactions
│   │           └── health.py            # Container health check & readiness probe
│   ├── core/
│   │   ├── config.py                    # Pydantic BaseSettings with .env validation
│   │   ├── security.py                  # JWT encoding/decoding, bcrypt hashing
│   │   └── exceptions.py                # Typed application domain exceptions
│   ├── db/
│   │   └── repository.py                # Thread-safe repository pattern
│   ├── models/
│   │   ├── user.py                      # User domain model & UserRole enum
│   │   └── transaction.py               # Transaction domain model & TransactionStatus enum
│   ├── schemas/
│   │   ├── base.py                      # Standardized response & error envelopes
│   │   ├── auth.py                      # Strict authentication & token schemas
│   │   ├── transaction.py               # Financial input schemas with Luhn & Decimal validation
│   │   ├── fraud.py                     # Risk assessment schemas & risk factor breakdown
│   │   └── pagination.py                # Offset pagination & query filtering schemas
│   ├── services/
│   │   ├── auth_service.py              # Authentication lifecycle logic
│   │   ├── fraud_engine.py              # Multi-factor real-time fraud scoring engine
│   │   └── transaction_service.py       # Transaction orchestration & querying
│   └── main.py                          # FastAPI factory, custom exception handlers, CORS, lifespan
├── tests/
│   ├── conftest.py                      # Pytest fixtures (TestClient, auth tokens, sample data)
│   ├── test_auth.py                     # JWT lifecycle, expiration, tampering, password complexity
│   ├── test_validation.py               # Luhn algorithm, Decimal precision, bounds, 422 envelopes
│   ├── test_fraud_engine.py             # Velocity checks, impossible travel, blacklists, MCCs
│   └── test_transactions_api.py         # End-to-end endpoint tests, pagination, filtering, RBAC
├── Dockerfile                           # Multi-stage unprivileged production image
├── docker-compose.yml                   # Containerized local environment
├── requirements.txt                     # Pinned application dependencies
└── pytest.ini                           # Test suite configuration
```

---

## 🛡️ Real-Time Fraud Detection Engine

The fraud detection engine evaluates transactions across 5 independent risk heuristics:

1. **Known Malicious Entity Blacklist**:
   - Immediate **100 risk score** and transaction `REJECTED` if client IP or card fingerprint is in the threat intelligence blacklist.
2. **Excessive & High Value Thresholds**:
   - Transactions exceeding `$25,000.00` add **50 risk points**.
   - Transactions exceeding `$5,000.00` add **20 risk points**.
3. **High-Risk Merchant Category Codes (MCC)**:
   - High-risk codes (e.g., `7995` Gambling, `6051` Crypto/Quasi-Cash, `5967` Adult, `6211` Securities) add **25 risk points**.
4. **Velocity Spike Detection**:
   - Accounts exceeding 5 transactions within a 5-minute rolling window add **40 risk points**.
5. **Impossible Travel Anomaly (Haversine Formula)**:
   - Compares geographic distance between consecutive transactions for the same account within a 4-hour window. If the required velocity exceeds commercial flight speeds (`> 900 km/h`), flags impossible travel and adds **60 risk points**.

### Decision Tiers:
- **`0 - 44`**: `APPROVED` (Low Risk)
- **`45 - 74`**: `FLAGGED` (Medium Risk - Manual Analyst Review)
- **`75 - 100`**: `REJECTED` (High Risk - Blocked)

---

## 🚀 Quickstart

### 1. Local Setup
```bash
# Clone and enter the repository
git clone <repo-url>
cd Fraud_Detection_Starter_Kit

# Create virtual environment and activate
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the API server
uvicorn app.main:app --reload --port 8000
```

### 2. Run Test Suite
```bash
pytest -v
```
All **42 unit and integration tests** execute in under 2 seconds.

### 3. Run with Docker
```bash
docker compose up --build
```
Access the interactive Swagger documentation at [http://localhost:8000/api/v1/docs](http://localhost:8000/api/v1/docs).

---

## 🔑 Pre-Seeded Demonstration Accounts

| Role | Email | Password | Permissions |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin@enterprise-fraud.com` | `Admin123!@#` | Unrestricted global access, full transaction visibility |
| **Analyst** | `analyst@enterprise-fraud.com` | `Analyst123!@#` | Global transaction auditing & fraud analysis |

---

## 📡 API Usage Examples

### 1. Authenticate (Obtain JWT)
```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@enterprise-fraud.com",
    "password": "Admin123!@#"
  }'
```

**Response (`200 OK`)**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

### 2. Submit Transaction (with Strict Pydantic Input Validation)
```bash
curl -X POST "http://localhost:8000/api/v1/transactions/" \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "acc_usr892301",
    "amount": "249.99",
    "currency": "USD",
    "payment_method": "CREDIT_CARD",
    "card": {
      "card_number": "4532015112830366",
      "exp_month": 12,
      "exp_year": 2028,
      "cvv": "921"
    },
    "merchant_id": "mch_retailer99",
    "merchant_category_code": "5411",
    "ip_address": "198.51.100.42",
    "device_fingerprint": "dfp_9a8b7c6d5e4f3a2b1c0d",
    "location": {
      "latitude": 37.7749,
      "longitude": -122.4194,
      "country_code": "US"
    }
  }'
```

**Response (`201 Created`)** (Note: Zero PAN/CVV leakage, only `card_bin` and `card_last4`):
```json
{
  "id": "txn_8c1b2e3f4a5d6e7f",
  "user_id": "usr_admin_001",
  "account_id": "acc_usr892301",
  "amount": "249.99",
  "currency": "USD",
  "payment_method": "CREDIT_CARD",
  "merchant_id": "mch_retailer99",
  "merchant_category_code": "5411",
  "ip_address": "198.51.100.42",
  "card_bin": "453201",
  "card_last4": "0366",
  "geo_country": "US",
  "status": "APPROVED",
  "risk_score": 0,
  "risk_factors": [],
  "created_at": "2026-11-17T14:55:00.000000Z"
}
```

### 3. Filter & Paginate Transactions
```bash
curl -X GET "http://localhost:8000/api/v1/transactions/?status=APPROVED&min_amount=100.00&page=1&limit=10&sort_by=amount&sort_order=desc" \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

**Response (`200 OK`)**:
```json
{
  "items": [ ... ],
  "total": 45,
  "page": 1,
  "limit": 10,
  "pages": 5,
  "has_next": true,
  "has_prev": false
}
```

### 4. Client-Friendly Standardized 422 Validation Error
If a client submits an invalid card number that fails Luhn checksum, a negative amount, or an invalid currency code:

**Response (`422 Unprocessable Entity`)**:
```json
{
  "success": false,
  "code": "VALIDATION_ERROR",
  "message": "Request validation failed. Verify input schema details.",
  "details": [
    {
      "field": "body.card.card_number",
      "issue": "Value error, Invalid card number: failed Luhn checksum verification",
      "code": "value_error"
    },
    {
      "field": "body.amount",
      "issue": "Input should be greater than 0",
      "code": "greater_than"
    }
  ]
}
```

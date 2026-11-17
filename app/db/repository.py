import threading
from datetime import datetime, timezone
from decimal import Decimal
from typing import Dict, List, Optional, Tuple

from app.core.security import get_password_hash
from app.models.transaction import PaymentMethod, Transaction, TransactionStatus
from app.models.user import User, UserRole
from app.schemas.pagination import PaginationParams, TransactionFilterParams


class InMemoryRepository:
    """
    Thread-safe in-memory repository implementing the Repository Pattern.
    Separates domain data persistence from FastAPI routing and business logic.
    Pre-seeds default admin and analyst users for testing and demonstration.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._users_by_id: Dict[str, User] = {}
        self._users_by_email: Dict[str, User] = {}
        self._transactions_by_id: Dict[str, Transaction] = {}
        self._transactions_by_account: Dict[str, List[Transaction]] = {}
        
        # Blacklists for known malicious entities
        self._blacklisted_ips: set[str] = {
            "203.0.113.195",
            "198.51.100.99",
        }
        self._blacklisted_card_fingerprints: set[str] = {
            "compromised_pan_hash_sample_01",
        }

        # Seed initial system accounts
        self._seed_default_users()

    def _seed_default_users(self) -> None:
        # Default Admin: admin@enterprise-fraud.com / Admin123!@#
        admin_id = "usr_admin_001"
        admin = User(
            id=admin_id,
            email="admin@enterprise-fraud.com",
            hashed_password=get_password_hash("Admin123!@#"),
            full_name="Global Fraud Administrator",
            role=UserRole.ADMIN,
            is_active=True,
        )
        self._users_by_id[admin.id] = admin
        self._users_by_email[admin.email.lower()] = admin

        # Default Analyst: analyst@enterprise-fraud.com / Analyst123!@#
        analyst_id = "usr_analyst_001"
        analyst = User(
            id=analyst_id,
            email="analyst@enterprise-fraud.com",
            hashed_password=get_password_hash("Analyst123!@#"),
            full_name="Risk Lead Analyst",
            role=UserRole.ANALYST,
            is_active=True,
        )
        self._users_by_id[analyst.id] = analyst
        self._users_by_email[analyst.email.lower()] = analyst

    # --- User Operations ---
    def get_user_by_id(self, user_id: str) -> Optional[User]:
        with self._lock:
            return self._users_by_id.get(user_id)

    def get_user_by_email(self, email: str) -> Optional[User]:
        with self._lock:
            return self._users_by_email.get(email.lower().strip())

    def create_user(self, user: User) -> User:
        with self._lock:
            email_key = user.email.lower().strip()
            if email_key in self._users_by_email:
                raise ValueError(f"User with email '{user.email}' already exists.")
            self._users_by_id[user.id] = user
            self._users_by_email[email_key] = user
            return user

    def update_user(self, user: User) -> User:
        with self._lock:
            self._users_by_id[user.id] = user
            self._users_by_email[user.email.lower().strip()] = user
            return user

    # --- Transaction Operations ---
    def save_transaction(self, transaction: Transaction) -> Transaction:
        with self._lock:
            self._transactions_by_id[transaction.id] = transaction
            if transaction.account_id not in self._transactions_by_account:
                self._transactions_by_account[transaction.account_id] = []
            self._transactions_by_account[transaction.account_id].append(transaction)
            return transaction

    def get_transaction_by_id(self, transaction_id: str) -> Optional[Transaction]:
        with self._lock:
            return self._transactions_by_id.get(transaction_id)

    def get_recent_transactions_for_account(
        self, account_id: str, since: datetime
    ) -> List[Transaction]:
        with self._lock:
            txns = self._transactions_by_account.get(account_id, [])
            return [t for t in txns if t.created_at >= since]

    def get_last_transaction_for_account(
        self, account_id: str
    ) -> Optional[Transaction]:
        with self._lock:
            txns = self._transactions_by_account.get(account_id, [])
            if not txns:
                return None
            return sorted(txns, key=lambda x: x.created_at, reverse=True)[0]

    def filter_transactions(
        self,
        filters: TransactionFilterParams,
        pagination: PaginationParams,
        user_id_scope: Optional[str] = None,
    ) -> Tuple[List[Transaction], int]:
        with self._lock:
            results = list(self._transactions_by_id.values())

            # Scope to user if not an admin/analyst
            if user_id_scope:
                results = [t for t in results if t.user_id == user_id_scope]

            # Apply filters
            if filters.status:
                results = [t for t in results if t.status == filters.status]
            if filters.currency:
                results = [t for t in results if t.currency.upper() == filters.currency.upper()]
            if filters.min_amount is not None:
                results = [t for t in results if t.amount >= filters.min_amount]
            if filters.max_amount is not None:
                results = [t for t in results if t.amount <= filters.max_amount]
            if filters.account_id:
                results = [t for t in results if t.account_id == filters.account_id]
            if filters.merchant_id:
                results = [t for t in results if t.merchant_id == filters.merchant_id]
            if filters.start_date:
                results = [t for t in results if t.created_at >= filters.start_date]
            if filters.end_date:
                results = [t for t in results if t.created_at <= filters.end_date]

            # Sorting
            reverse = filters.sort_order == "desc"
            if filters.sort_by == "amount":
                results.sort(key=lambda x: x.amount, reverse=reverse)
            elif filters.sort_by == "risk_score":
                results.sort(key=lambda x: x.risk_score, reverse=reverse)
            else:
                results.sort(key=lambda x: x.created_at, reverse=reverse)

            total = len(results)
            start = pagination.offset
            end = start + pagination.limit
            paginated = results[start:end]

            return paginated, total

    # --- Blacklist Lookups ---
    def is_ip_blacklisted(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blacklisted_ips

    def is_card_fingerprint_blacklisted(self, fingerprint: str) -> bool:
        with self._lock:
            return fingerprint in self._blacklisted_card_fingerprints


# Singleton repository instance
repository = InMemoryRepository()


def get_repository() -> InMemoryRepository:
    """Dependency provider for database/repository."""
    return repository

from datetime import datetime
from decimal import Decimal
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import (
    get_current_user,
    get_fraud_engine,
    get_transaction_service,
    require_roles,
)
from app.core.exceptions import ResourceNotFoundException
from app.models.transaction import TransactionStatus
from app.models.user import User, UserRole
from app.schemas.fraud import FraudEvaluationResponse
from app.schemas.pagination import PaginatedResponse, PaginationParams, TransactionFilterParams
from app.schemas.transaction import TransactionCreate, TransactionResponse
from app.services.fraud_engine import FraudDetectionEngine
from app.services.transaction_service import TransactionService

router = APIRouter()


@router.post(
    "/evaluate",
    response_model=FraudEvaluationResponse,
    summary="Simulate / Evaluate fraud risk",
    description="Runs transaction through the fraud heuristic rules (velocity, impossible travel, blacklists, high amount) without persisting to DB."
)
def evaluate_transaction_risk(
    req: TransactionCreate,
    engine: FraudDetectionEngine = Depends(get_fraud_engine),
    current_user: User = Depends(get_current_user),
) -> FraudEvaluationResponse:
    return engine.evaluate(req)


@router.post(
    "/",
    response_model=TransactionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit financial transaction",
    description="Validates payload against strict Pydantic rules, applies real-time fraud assessment, and stores the transaction."
)
def submit_transaction(
    req: TransactionCreate,
    service: TransactionService = Depends(get_transaction_service),
    current_user: User = Depends(get_current_user),
) -> TransactionResponse:
    return service.process_transaction(user_id=current_user.id, txn_in=req)


@router.get(
    "/",
    response_model=PaginatedResponse[TransactionResponse],
    summary="List transactions with filtering and pagination",
    description="Query transactions by status, currency, amount range, account, merchant, date bounds, with sorting and offset pagination."
)
def list_transactions(
    page: int = Query(default=1, ge=1, description="Page index (1-based)"),
    limit: int = Query(default=20, ge=1, le=100, description="Items per page (max 100)"),
    status: Optional[TransactionStatus] = Query(default=None, description="Filter by status (APPROVED, FLAGGED, REJECTED)"),
    currency: Optional[str] = Query(default=None, description="Filter by 3-letter currency code (e.g. USD)"),
    min_amount: Optional[Decimal] = Query(default=None, ge=Decimal("0.00"), description="Filter by minimum amount"),
    max_amount: Optional[Decimal] = Query(default=None, ge=Decimal("0.00"), description="Filter by maximum amount"),
    account_id: Optional[str] = Query(default=None, description="Filter by account identifier"),
    merchant_id: Optional[str] = Query(default=None, description="Filter by merchant identifier"),
    start_date: Optional[datetime] = Query(default=None, description="Start date timestamp filter (inclusive)"),
    end_date: Optional[datetime] = Query(default=None, description="End date timestamp filter (inclusive)"),
    sort_by: str = Query(default="created_at", pattern=r"^(created_at|amount|risk_score)$", description="Field to sort by"),
    sort_order: str = Query(default="desc", pattern=r"^(asc|desc)$", description="Sort order: asc or desc"),
    service: TransactionService = Depends(get_transaction_service),
    current_user: User = Depends(get_current_user),
) -> PaginatedResponse[TransactionResponse]:
    pagination = PaginationParams(page=page, limit=limit)
    filters = TransactionFilterParams(
        status=status,
        currency=currency,
        min_amount=min_amount,
        max_amount=max_amount,
        account_id=account_id,
        merchant_id=merchant_id,
        start_date=start_date,
        end_date=end_date,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    # Scoping: Analysts and Admins can view all transactions; Merchants can only view their own
    user_scope = None if current_user.role in (UserRole.ADMIN, UserRole.ANALYST) else current_user.id
    return service.list_transactions(filters=filters, pagination=pagination, user_id_scope=user_scope)


@router.get(
    "/{transaction_id}",
    response_model=TransactionResponse,
    summary="Get transaction by ID",
    description="Fetch details of a specific transaction record."
)
def get_transaction_by_id(
    transaction_id: str,
    service: TransactionService = Depends(get_transaction_service),
    current_user: User = Depends(get_current_user),
) -> TransactionResponse:
    user_scope = None if current_user.role in (UserRole.ADMIN, UserRole.ANALYST) else current_user.id
    try:
        return service.get_transaction(transaction_id=transaction_id, user_id_scope=user_scope)
    except ResourceNotFoundException as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=e.message,
        )

import math
from datetime import datetime
from decimal import Decimal
from typing import Generic, List, Optional, TypeVar
from pydantic import BaseModel, Field

from app.models.transaction import TransactionStatus

T = TypeVar("T")


class PaginationParams(BaseModel):
    """Query parameters for offset-based pagination."""
    page: int = Field(default=1, ge=1, description="Page number starting at 1")
    limit: int = Field(default=20, ge=1, le=100, description="Number of records per page (max 100)")

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.limit


class PaginatedResponse(BaseModel, Generic[T]):
    """Standardized wrapper for paginated collections."""
    items: List[T] = Field(..., description="Page items")
    total: int = Field(..., ge=0, description="Total matching records across all pages")
    page: int = Field(..., ge=1, description="Current page index")
    limit: int = Field(..., ge=1, description="Number of items requested per page")
    pages: int = Field(..., ge=0, description="Total calculated page count")
    has_next: bool = Field(..., description="True if subsequent pages exist")
    has_prev: bool = Field(..., description="True if preceding pages exist")

    @classmethod
    def create(cls, items: List[T], total: int, params: PaginationParams) -> "PaginatedResponse[T]":
        pages = math.ceil(total / params.limit) if params.limit > 0 else 0
        return cls(
            items=items,
            total=total,
            page=params.page,
            limit=params.limit,
            pages=pages,
            has_next=params.page < pages,
            has_prev=params.page > 1,
        )


class TransactionFilterParams(BaseModel):
    """Filtering options for transactions listing."""
    status: Optional[TransactionStatus] = None
    currency: Optional[str] = None
    min_amount: Optional[Decimal] = None
    max_amount: Optional[Decimal] = None
    account_id: Optional[str] = None
    merchant_id: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    sort_by: str = Field(default="created_at", pattern=r"^(created_at|amount|risk_score)$")
    sort_order: str = Field(default="desc", pattern=r"^(asc|desc)$")

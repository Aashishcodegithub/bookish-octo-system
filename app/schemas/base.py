from typing import Any, Generic, List, Optional, TypeVar
from pydantic import BaseModel, Field

DataT = TypeVar("DataT")


class ErrorDetail(BaseModel):
    field: Optional[str] = Field(None, description="Path of the invalid field if applicable")
    issue: str = Field(..., description="Human-readable explanation of the validation or domain error")
    code: Optional[str] = Field(None, description="Error type or rule code")


class ErrorResponse(BaseModel):
    success: bool = Field(False, description="Always false for error responses")
    code: str = Field(..., description="High-level machine-readable error code")
    message: str = Field(..., description="Summary message of the error")
    details: Optional[List[ErrorDetail]] = Field(None, description="List of granular errors")


class SuccessResponse(BaseModel, Generic[DataT]):
    success: bool = Field(True, description="Always true for successful operations")
    message: str = Field("Operation completed successfully", description="Informational message")
    data: DataT = Field(..., description="Payload data")

from typing import Any, Dict, List, Optional
from fastapi import HTTPException, status


class AppBaseException(Exception):
    """Base application exception for domain errors."""
    def __init__(self, message: str, code: str = "INTERNAL_ERROR", details: Optional[Any] = None):
        self.message = message
        self.code = code
        self.details = details
        super().__init__(message)


class AuthenticationException(AppBaseException):
    """Raised when authentication fails."""
    def __init__(self, message: str = "Could not validate credentials", code: str = "AUTHENTICATION_FAILED", details: Optional[Any] = None):
        super().__init__(message=message, code=code, details=details)


class TokenExpiredException(AuthenticationException):
    """Raised when a JWT has expired."""
    def __init__(self, message: str = "Token has expired", code: str = "TOKEN_EXPIRED"):
        super().__init__(message=message, code=code)


class TokenInvalidException(AuthenticationException):
    """Raised when a JWT signature, format, or type is invalid."""
    def __init__(self, message: str = "Invalid or tampered token", code: str = "INVALID_TOKEN"):
        super().__init__(message=message, code=code)


class PermissionDeniedException(AppBaseException):
    """Raised when a user lacks required permissions or roles."""
    def __init__(self, message: str = "Operation not permitted", code: str = "FORBIDDEN"):
        super().__init__(message=message, code=code)


class ResourceNotFoundException(AppBaseException):
    """Raised when an entity is not found."""
    def __init__(self, message: str = "Resource not found", code: str = "NOT_FOUND"):
        super().__init__(message=message, code=code)


class DuplicateResourceException(AppBaseException):
    """Raised when a unique constraint is violated."""
    def __init__(self, message: str = "Resource already exists", code: str = "DUPLICATE_RESOURCE"):
        super().__init__(message=message, code=code)


class FraudRuleTriggeredException(AppBaseException):
    """Raised when an operation is blocked by fraud detection policies."""
    def __init__(self, message: str = "Transaction declined by fraud policy", details: Optional[Any] = None):
        super().__init__(message=message, code="FRAUD_RULE_TRIGGERED", details=details)

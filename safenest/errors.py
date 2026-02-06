"""Custom exceptions for SafeNest SDK."""

from typing import Any, Optional


class SafeNestError(Exception):
    """Base exception for SafeNest SDK errors."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class AuthenticationError(SafeNestError):
    """Raised when API key is invalid or missing."""

    pass


class RateLimitError(SafeNestError):
    """Raised when rate limit is exceeded."""

    pass


class ValidationError(SafeNestError):
    """Raised when request validation fails."""

    pass


class NotFoundError(SafeNestError):
    """Raised when a resource is not found."""

    pass


class ServerError(SafeNestError):
    """Raised when the server returns a 5xx error."""

    def __init__(
        self, message: str, status_code: int, details: Optional[Any] = None
    ) -> None:
        super().__init__(message, details)
        self.status_code = status_code


class TimeoutError(SafeNestError):
    """Raised when a request times out."""

    pass


class NetworkError(SafeNestError):
    """Raised when a network error occurs."""

    pass

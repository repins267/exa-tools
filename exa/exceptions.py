"""exa-tools exception hierarchy."""


class ExaError(Exception):
    """Base exception for exa-tools."""


class ExaAuthError(ExaError):
    """Authentication or token refresh failure."""


class ExaAPIError(ExaError):
    """Non-retryable API error."""

    def __init__(self, status_code: int, detail: str = "") -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


class ExaInternalFeatureError(ExaError):
    """Raised when a feature requires internal/employee tier access."""

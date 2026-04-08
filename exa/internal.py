"""Internal tier gating decorator.

Detects whether the authenticated API key belongs to an internal/employee
account by querying GET /access-control/v1/apikeys for the owner email.
Falls back to internal_mode=True if the endpoint is unavailable.

Functions decorated with @require_internal raise ExaInternalFeatureError
if the client is not in internal mode.
"""

from __future__ import annotations

import functools
from typing import TYPE_CHECKING, Any, Callable, ParamSpec, TypeVar

from exa.exceptions import ExaInternalFeatureError

if TYPE_CHECKING:
    from exa.client import ExaClient

P = ParamSpec("P")
T = TypeVar("T")


def detect_internal_mode(client: ExaClient) -> bool:
    """Check if the API key belongs to an internal/employee account.

    Queries GET /access-control/v1/apikeys and looks for a known internal
    email domain. Falls back to True if the endpoint is unavailable
    (assumes on-prem/internal deployment).
    """
    try:
        resp = client.get("/access-control/v1/apikeys")
        # Response is typically a list of API key objects with owner info
        if isinstance(resp, list):
            for key_info in resp:
                owner = key_info.get("ownerEmail", "") or key_info.get("owner", "")
                if isinstance(owner, str) and owner:
                    # Check for known internal domains
                    domain = owner.split("@")[-1].lower() if "@" in owner else ""
                    if domain in {"exabeam.com", "logrhythm.com"}:
                        return True
        return False
    except Exception:
        # If we can't reach the endpoint, assume internal (on-prem)
        return True


def require_internal(func: Callable[P, T]) -> Callable[P, T]:
    """Decorator that restricts a function to internal/employee tier access.

    The first argument must be an ExaClient instance. If the client does not
    have internal_mode set, it will be auto-detected on first call.
    """
    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        # Lazy import to avoid circular dependency
        from exa.client import ExaClient

        # Find the ExaClient argument
        client: ExaClient | None = None
        for arg in args:
            if isinstance(arg, ExaClient):
                client = arg
                break
        if client is None:
            client = kwargs.get("client")  # type: ignore[assignment]

        if client is None:
            raise TypeError(f"{func.__name__} requires an ExaClient argument")

        # Check/detect internal mode
        if not hasattr(client, "_internal_mode"):
            client._internal_mode = detect_internal_mode(client)  # type: ignore[attr-defined]

        if not client._internal_mode:  # type: ignore[attr-defined]
            raise ExaInternalFeatureError(
                f"{func.__name__} requires internal/employee tier access"
            )

        return func(*args, **kwargs)

    return wrapper

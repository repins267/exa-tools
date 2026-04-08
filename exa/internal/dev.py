"""Internal-only dev client via environment variables.

For internal development and testing only. Community users must
always pass client_id and client_secret explicitly.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from exa.exceptions import ExaAuthError
from exa.internal import require_internal

if TYPE_CHECKING:
    from exa.client import ExaClient


@require_internal
def get_dev_client(
    client: ExaClient,
    base_url: str = "https://api.us-west.exabeam.cloud",
) -> ExaClient:
    """Get an authenticated ExaClient from environment variables.

    For internal development and testing only.
    Requires EXA_CLIENT_ID and EXA_CLIENT_SECRET env vars.

    Args:
        client: Existing ExaClient (used only for @require_internal check).
        base_url: Exabeam API base URL.

    Returns:
        A new authenticated ExaClient.
    """
    from exa.client import ExaClient as _ExaClient

    client_id = os.environ.get("EXA_CLIENT_ID")
    client_secret = os.environ.get("EXA_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise ExaAuthError(
            "EXA_CLIENT_ID and EXA_CLIENT_SECRET env vars required. "
            "Set them in your session before calling get_dev_client()."
        )
    dev_client = _ExaClient(base_url, client_id, client_secret)
    dev_client.authenticate()
    return dev_client


def get_dev_client_from_env(
    base_url: str = "https://api.us-west.exabeam.cloud",
) -> ExaClient:
    """Get an authenticated ExaClient from environment variables.

    Standalone version that detects internal tier after first auth.
    Raises ExaAuthError if env vars are missing or if the authenticated
    user is not an internal/employee account.

    For internal development and testing only.
    """
    from exa.client import ExaClient as _ExaClient
    from exa.internal import detect_internal_mode
    from exa.exceptions import ExaInternalFeatureError

    client_id = os.environ.get("EXA_CLIENT_ID")
    client_secret = os.environ.get("EXA_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise ExaAuthError(
            "EXA_CLIENT_ID and EXA_CLIENT_SECRET env vars required. "
            "Set them in your session before calling get_dev_client_from_env()."
        )
    client = _ExaClient(base_url, client_id, client_secret)
    client.authenticate()

    # Gate: verify internal tier after auth
    if not detect_internal_mode(client):
        client.close()
        raise ExaInternalFeatureError(
            "get_dev_client_from_env() requires internal/employee tier access. "
            "Community users must pass client_id and client_secret explicitly."
        )

    client._internal_mode = True  # type: ignore[attr-defined]
    return client

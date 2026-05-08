"""Health and consumption API functions.

API endpoints used:
  GET /health-consumption/v1/consumption/lts              — LTS storage consumption
  GET /health-consumption/v2/license-details             — license details (v2, v1 deprecated)
  GET /health-consumption/v1/consumption/correlation-rules — correlation rule count
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient


def get_lts_consumption(client: ExaClient) -> dict[str, Any]:
    """Return LTS storage consumption stats.

    API: GET /health-consumption/v1/consumption/lts
    Response fields are TBC live — use .get() with fallbacks.
    """
    return client.get("/health-consumption/v1/consumption/lts")


def get_license_details(client: ExaClient) -> dict[str, Any]:
    """Return license details.

    API: GET /health-consumption/v2/license-details
    Note: v1 is deprecated — always use v2.
    """
    return client.get("/health-consumption/v2/license-details")


def get_correlation_rule_count(client: ExaClient) -> dict[str, Any]:
    """Return correlation rule consumption stats.

    API: GET /health-consumption/v1/consumption/correlation-rules
    """
    return client.get("/health-consumption/v1/consumption/correlation-rules")

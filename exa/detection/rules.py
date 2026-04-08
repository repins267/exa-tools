"""Detection (analytics) rule operations for Exabeam New-Scale.

API base path: /detection-management/v1/
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient


def get_detection_rules(
    client: ExaClient,
    *,
    name: str | None = None,
    status: str | None = None,
    limit: int = 100,
    after: str | None = None,
) -> list[dict[str, Any]]:
    """List detection/analytics rules with optional filters."""
    params: dict[str, Any] = {"limit": limit}
    if name:
        params["name"] = name
    if status:
        params["status"] = status
    if after:
        params["after"] = after

    resp = client.get("/detection-management/v1/analytics-rules", params=params)

    # API wraps in { rules: [...] }
    if isinstance(resp, dict) and "rules" in resp:
        return resp["rules"]
    return resp


def get_detection_rule(client: ExaClient, rule_id: str) -> dict[str, Any]:
    """Get a single detection rule by ID."""
    return client.get(f"/detection-management/v1/analytics-rules/{rule_id}")


def set_detection_rule_state(
    client: ExaClient,
    rule_id: str,
    *,
    enabled: bool,
) -> dict[str, Any]:
    """Enable or disable a detection rule."""
    return client.put(
        f"/detection-management/v1/analytics-rules/{rule_id}",
        json={"enabled": enabled},
    )

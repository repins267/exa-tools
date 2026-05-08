"""Detection (analytics) rule operations for Exabeam New-Scale.

API base path: /detection-management/v1/analytics-rules  # EXA-UNVERIFIED
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

# EXA-UNVERIFIED: base path — verify live with GET /detection-management/v1/analytics-rules
_BASE = "/detection-management/v1/analytics-rules"


def get_detection_rules(
    client: ExaClient,
    *,
    name: str | None = None,
    status: str | None = None,
    limit: int = 100,
    after: str | None = None,
) -> list[dict[str, Any]]:
    """List detection/analytics rules with optional filters.

    Args:
        client: Authenticated ExaClient.
        name: Filter by rule name (substring match).
        status: Filter by status, e.g. "enabled" or "disabled".
        limit: Max rules to return.
        after: Pagination cursor (value of last rule's id from prior page).

    Returns:
        List of rule dicts.

    API: GET /detection-management/v1/analytics-rules  # EXA-UNVERIFIED
    Response: {"rules": [...], ...}
    """
    params: dict[str, Any] = {"limit": limit}
    if name:
        params["name"] = name
    if status:
        params["status"] = status
    if after:
        params["after"] = after

    resp = client.get(_BASE, params=params)

    if isinstance(resp, dict) and "rules" in resp:
        return resp["rules"]
    return resp


def get_detection_rule(client: ExaClient, rule_id: str) -> dict[str, Any]:
    """Get a single detection rule by ID.

    API: GET /detection-management/v1/analytics-rules/{id}  # EXA-UNVERIFIED
    """
    return client.get(f"{_BASE}/{rule_id}")


def set_detection_rule_state(
    client: ExaClient,
    rule_id: str,
    *,
    enabled: bool,
) -> dict[str, Any]:
    """Enable or disable a detection rule.

    API: PUT /detection-management/v1/analytics-rules/{id}  # EXA-UNVERIFIED
    Request body: {"enabled": true|false}
    """
    return client.put(
        f"{_BASE}/{rule_id}",
        json={"enabled": enabled},
    )


def export_rules(
    client: ExaClient,
    rule_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Export analytics rules as a portable JSON bundle.

    Args:
        client: Authenticated ExaClient.
        rule_ids: Specific rule IDs to export. None = export all.

    Returns:
        Export bundle dict (write to file for backup/migration).

    API: POST /detection-management/v1/analytics-rules/export  # EXA-UNVERIFIED
    Request body: {"ruleIds": [...]} or {} for all rules
    """
    body: dict[str, Any] = {}
    if rule_ids is not None:
        body["ruleIds"] = rule_ids

    return client.post(f"{_BASE}/export", json=body)


def import_rules(
    client: ExaClient,
    bundle: dict[str, Any],
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Import analytics rules from an export bundle.

    Args:
        client: Authenticated ExaClient.
        bundle: Export bundle previously returned by export_rules().
        overwrite: If True, overwrite existing rules with same ID.

    Returns:
        Import result dict (imported count, skipped, errors).

    API: POST /detection-management/v1/analytics-rules/import  # EXA-UNVERIFIED
    Request body: {<bundle fields>, "overwrite": bool}
    """
    body = {**bundle, "overwrite": overwrite}
    return client.post(f"{_BASE}/import", json=body)

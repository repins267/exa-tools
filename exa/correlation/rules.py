"""Correlation rule CRUD operations for Exabeam New-Scale.

API base path: /correlation-rules/v2/
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient


def get_rules(
    client: ExaClient,
    *,
    name: str | None = None,
    exact: bool = False,
) -> list[dict[str, Any]]:
    """List all correlation rules, optionally filtered by name."""
    params: dict[str, str] = {}
    if name and not exact:
        params["nameContains"] = name

    rules: list[dict[str, Any]] = client.get(
        "/correlation-rules/v2/rules", params=params or None
    )

    if name and exact:
        rules = [r for r in rules if r.get("name") == name]

    return rules


def get_rule(client: ExaClient, rule_id: str) -> dict[str, Any]:
    """Get a single correlation rule by ID."""
    return client.get(f"/correlation-rules/v2/rules/{rule_id}")


def create_rule(client: ExaClient, rule: dict[str, Any]) -> dict[str, Any]:
    """Create a new correlation rule."""
    return client.post("/correlation-rules/v2/rules", json=rule)


def update_rule(
    client: ExaClient, rule_id: str, rule: dict[str, Any]
) -> dict[str, Any]:
    """Update an existing correlation rule."""
    return client.put(f"/correlation-rules/v2/rules/{rule_id}", json=rule)


def delete_rule(client: ExaClient, rule_id: str) -> None:
    """Delete a correlation rule."""
    client.delete(f"/correlation-rules/v2/rules/{rule_id}")


def set_rule_state(
    client: ExaClient,
    rule_id: str,
    *,
    enabled: bool,
) -> dict[str, Any]:
    """Enable or disable a correlation rule."""
    return client.put(
        f"/correlation-rules/v2/rules/{rule_id}",
        json={"enabled": enabled},
    )

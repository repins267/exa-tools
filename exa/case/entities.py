"""Entity history and profile helpers for case triage.

API endpoints used:
  POST /threat-center/v1/search/cases   — search prior cases by entity (verified)
  GET  /entity-management/v1/entities/{type}  — entity profile (EXA-UNVERIFIED)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient


def get_entity_cases(
    client: ExaClient,
    entity_name: str,
    *,
    lookback_days: int = 30,
    exclude_case_id: str | None = None,
) -> list[dict[str, Any]]:
    """Search prior cases involving a given entity (user or hostname).

    Args:
        client: Authenticated ExaClient.
        entity_name: Username or hostname to search for.
        lookback_days: How far back to search (default 30 days).
        exclude_case_id: Exclude this case ID from results (the current case).

    Returns:
        List of case dicts, sorted by creation timestamp descending.
    """
    from exa.case.cases import search_cases

    rows = search_cases(
        client,
        filter=f'users:"{entity_name}"',
        lookback_days=lookback_days,
        limit=100,
    )
    if exclude_case_id:
        rows = [r for r in rows if r.get("caseId") != exclude_case_id]
    return rows


def get_entity_profile(
    client: ExaClient,
    entity_name: str,
    entity_type: str = "users",
) -> dict[str, Any] | None:
    """Fetch entity profile from entity-management API.

    Returns None on any error — endpoint is EXA-UNVERIFIED and may require
    additional permissions not present on all tenants.

    # EXA-UNVERIFIED: GET /entity-management/v1/entities/{type}?query=<name>
    """
    try:
        resp = client.get(
            f"/entity-management/v1/entities/{entity_type}",
            params={"query": entity_name, "limit": 1},
        )
        items = resp.get("entities", resp.get("items", []))
        return items[0] if items else None
    except Exception:
        return None

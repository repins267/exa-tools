"""Threat Center alert operations.

API endpoints:
  POST /threat-center/v1/search/alerts  — search alerts
  GET  /threat-center/v1/alerts/{id}    — get alert details
  POST /threat-center/v1/alerts/{id}    — update alert
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient


def search_alerts(
    client: ExaClient,
    *,
    fields: list[str] | None = None,
    filter: str | None = None,
    order_by: list[str] | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    lookback_days: int | None = None,
    limit: int = 500,
    raw: bool = False,
) -> list[dict[str, Any]] | dict[str, Any]:
    """Search Threat Center alerts.

    Args:
        client: Authenticated ExaClient.
        fields: Fields to return. Defaults to ["*"] (all fields).
        filter: EQL-style filter expression, e.g. 'priority:"HIGH"'.
        order_by: Sort fields, e.g. ["riskScore DESC"].
        start_time/end_time: Absolute time range (UTC).
        lookback_days: Days to look back from now (default 30).
        limit: Max alerts to return (default 500, max 3000).
        raw: Return raw API response dict instead of rows list.

    Returns:
        List of alert dicts, or raw API response if raw=True.

    API: POST /threat-center/v1/search/alerts
    Response fields: rows (list), totalRows (int), startTime, endTime
    """
    now = datetime.now(UTC)
    if start_time is not None:
        t_start = start_time if start_time.tzinfo else start_time.replace(tzinfo=UTC)
        t_end = end_time if end_time is not None else now
        if t_end.tzinfo is None:
            t_end = t_end.replace(tzinfo=UTC)
    elif lookback_days is not None:
        t_start = now - timedelta(days=lookback_days)
        t_end = now
    else:
        t_start = now - timedelta(days=30)
        t_end = now

    body: dict[str, Any] = {
        "fields": fields if fields is not None else ["*"],
        "limit": limit,
        "orderBy": order_by if order_by is not None else ["riskScore DESC"],
        "startTime": t_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "endTime": t_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if filter is not None:
        body["filter"] = filter

    response = client.post("/threat-center/v1/search/alerts", json=body)

    if raw:
        return response

    return response.get("rows", [])


def get_alert(client: ExaClient, alert_id: str) -> dict[str, Any]:
    """Get details for a specific alert.

    Args:
        client: Authenticated ExaClient.
        alert_id: UUID of the alert.

    Returns:
        Alert attribute dict.

    API: GET /threat-center/v1/alerts/{alertId}
    """
    return client.get(f"/threat-center/v1/alerts/{alert_id}")


def update_alert(
    client: ExaClient,
    alert_id: str,
    *,
    name: str | None = None,
    description: str | None = None,
    priority: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Update attributes of a specific alert.

    Only provided (non-None) fields are included in the request body.

    Args:
        client: Authenticated ExaClient.
        alert_id: UUID of the alert.
        name: New alert name (API field: alertName).
        description: New alert description (API field: alertDescription).
        priority: "LOW", "MEDIUM", "HIGH", or "CRITICAL".
        tags: List of tag strings.

    Returns:
        Updated alert attribute dict.

    API: POST /threat-center/v1/alerts/{alertId}
    Updatable fields: alertName, alertDescription, priority, tags
    """
    body: dict[str, Any] = {}
    if name is not None:
        body["alertName"] = name
    if description is not None:
        body["alertDescription"] = description
    if priority is not None:
        body["priority"] = priority
    if tags is not None:
        body["tags"] = tags

    return client.post(f"/threat-center/v1/alerts/{alert_id}", json=body)

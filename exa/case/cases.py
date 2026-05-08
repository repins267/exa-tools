"""Threat Center case operations.

API endpoints:
  POST /threat-center/v1/search/cases   — search cases
  GET  /threat-center/v1/cases/{id}     — get case details
  POST /threat-center/v1/cases/{id}     — update case
  POST /threat-center/v1/cases          — create case
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient


def search_cases(
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
    """Search Threat Center cases.

    Args:
        client: Authenticated ExaClient.
        fields: Fields to return. Defaults to ["*"] (all fields).
        filter: EQL-style filter expression, e.g. 'NOT stage:"CLOSED"'.
        order_by: Sort fields, e.g. ["riskScore DESC", "caseCreationTimestamp DESC"].
        start_time/end_time: Absolute time range (UTC).
        lookback_days: Days to look back from now (default 30).
        limit: Max cases to return (default 500, max 3000).
        raw: Return raw API response dict instead of rows list.

    Returns:
        List of case dicts, or raw API response if raw=True.

    API: POST /threat-center/v1/search/cases
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
        "orderBy": order_by if order_by is not None else ["caseCreationTimestamp DESC"],
        "startTime": t_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "endTime": t_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if filter is not None:
        body["filter"] = filter

    response = client.post("/threat-center/v1/search/cases", json=body)

    if raw:
        return response

    return response.get("rows", [])


def get_case(client: ExaClient, case_id: str) -> dict[str, Any]:
    """Get details for a specific case.

    Args:
        client: Authenticated ExaClient.
        case_id: UUID of the case.

    Returns:
        Case attribute dict.

    API: GET /threat-center/v1/cases/{caseId}
    """
    return client.get(f"/threat-center/v1/cases/{case_id}")


def update_case(
    client: ExaClient,
    case_id: str,
    *,
    name: str | None = None,
    description: str | None = None,
    stage: str | None = None,
    closed_reason: str | None = None,
    queue: str | None = None,
    assignee: str | None = None,
    priority: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Update attributes of a specific case.

    Only provided (non-None) fields are included in the request body.

    Args:
        client: Authenticated ExaClient.
        case_id: UUID of the case.
        name: New case name (API field: alertName).
        description: New case description (API field: alertDescription).
        stage: Case stage, e.g. "OPEN", "IN PROGRESS", "CLOSED".
        closed_reason: Required when setting stage to CLOSED.
        queue: Queue to assign the case to.
        assignee: Assignee username or ID.
        priority: "LOW", "MEDIUM", "HIGH", or "CRITICAL".
        tags: List of tag strings.

    Returns:
        Updated case attribute dict.

    API: POST /threat-center/v1/cases/{caseId}
    Updatable fields: alertName, alertDescription, stage, closedReason,
                      queue, assignee, priority, tags
    """
    body: dict[str, Any] = {}
    if name is not None:
        body["alertName"] = name
    if description is not None:
        body["alertDescription"] = description
    if stage is not None:
        body["stage"] = stage
    if closed_reason is not None:
        body["closedReason"] = closed_reason
    if queue is not None:
        body["queue"] = queue
    if assignee is not None:
        body["assignee"] = assignee
    if priority is not None:
        body["priority"] = priority
    if tags is not None:
        body["tags"] = tags

    return client.post(f"/threat-center/v1/cases/{case_id}", json=body)


def create_case(
    client: ExaClient,
    alert_id: str,
    *,
    stage: str | None = None,
    priority: str | None = None,
    queue: str | None = None,
    assignee: str | None = None,
    closed_reason: str | None = None,
) -> dict[str, Any]:
    """Create a new case associated with an alert.

    Args:
        client: Authenticated ExaClient.
        alert_id: UUID of the alert to associate with the new case.
        stage: Initial case stage.
        priority: "LOW", "MEDIUM", "HIGH", or "CRITICAL".
        queue: Queue to assign the case to.
        assignee: Assignee username or ID.
        closed_reason: Required when stage is CLOSED.

    Returns:
        Created case attribute dict.

    API: POST /threat-center/v1/cases
    """
    body: dict[str, Any] = {"alertId": alert_id}
    if stage is not None:
        body["stage"] = stage
    if priority is not None:
        body["priority"] = priority
    if queue is not None:
        body["queue"] = queue
    if assignee is not None:
        body["assignee"] = assignee
    if closed_reason is not None:
        body["closedReason"] = closed_reason

    return client.post("/threat-center/v1/cases", json=body)

"""Threat Center case operations.

API endpoints:
  POST /threat-center/v1/search/cases   — search cases (verified 200, SA, 2026-05-28)
  GET  /threat-center/v1/cases/{id}     — get case details (verified 200, SA, 2026-05-28)
  POST /threat-center/v2/cases/{id}     — update case (v1 DEPRECATED, see below)
  POST /threat-center/v2/cases          — create case (v1 DEPRECATED, see below)

v1 create/update were deprecated 2025-10-15 and scheduled for REMOVAL 2026-04-15
(developers.exabeam.com/exabeam/changelog/legacy-threat-center-endpoints). Both
write paths — v1 and v2 — are `skipped: write` in api-verification-results.json
and have NEVER been probed against a live tenant, so v2 is documented but not
proven. Until a live test says otherwise, v2 is tried first and v1 is the
fallback. Remove the fallback once v2 is confirmed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from exa.exceptions import ExaAPIError

if TYPE_CHECKING:
    from exa.client import ExaClient

# Statuses that prove the request never reached a handler, so retrying the legacy
# path cannot double-write. 500 is deliberately EXCLUDED: this API is documented
# (CLAUDE.md, the EXA-* register) to return success for writes that have not
# landed and to fail after doing work, so a retry on 500 risks creating a second
# case. Prefer a loud failure over a silent duplicate.
_ENDPOINT_ABSENT_STATUS = frozenset({404, 405, 501})


def _post_case_write(
    client: ExaClient,
    v2_path: str,
    v1_path: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    """POST a case write to v2, falling back to v1 only when v2 is absent.

    Falls back ONLY on a status proving no handler was reached. Any other error
    — 400, 401, 403, 409, 500 — means v2 exists and the request itself was
    rejected, so it propagates rather than being retried against a deprecated
    path that may double-write.
    """
    try:
        return client.post(v2_path, json=body)
    except ExaAPIError as exc:
        if exc.status_code not in _ENDPOINT_ABSENT_STATUS:
            raise
    return client.post(v1_path, json=body)


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
    # Always include filter key — some tenants return 400 if it's absent entirely
    body["filter"] = filter if filter is not None else ""

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

    API: POST /threat-center/v2/cases/{caseId}, falling back to v1 while v2 is
         unproven. v1 was scheduled for removal 2026-04-15.
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

    return _post_case_write(
        client,
        f"/threat-center/v2/cases/{case_id}",
        f"/threat-center/v1/cases/{case_id}",
        body,
    )


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

    API: POST /threat-center/v2/cases, falling back to v1 while v2 is unproven.
         v1 was scheduled for removal 2026-04-15.
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

    return _post_case_write(
        client,
        "/threat-center/v2/cases",
        "/threat-center/v1/cases",
        body,
    )

"""Search Exabeam events using Exabeam Query Language (EQL).

API endpoint: POST /search/v2/events
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

_DEFAULT_FIELDS = ["user", "host", "src_ip", "dest_ip", "activity_type", "outcome"]


def search_events(
    client: ExaClient,
    filter: str,
    *,
    fields: list[str] | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    lookback_hours: int | None = None,
    lookback_days: int | None = None,
    limit: int = 10000,
    distinct: bool = False,
    group_by: list[str] | None = None,
    order_by: list[str] | None = None,
    raw: bool = False,
) -> list[dict[str, Any]] | dict[str, Any]:
    """Search Exabeam events.

    Args:
        client: Authenticated ExaClient.
        filter: EQL filter string.
        fields: CIM field names to return.
        start_time/end_time: Absolute time range.
        lookback_hours/lookback_days: Relative time range from now.
        limit: Max events (default 10000, max 1000000).
        distinct: Return only distinct events.
        raw: Return raw API response instead of flattened rows.
    """
    req_fields = list(fields or _DEFAULT_FIELDS)
    # approxLogTime is invalid in GROUP BY queries (not grouped, not aggregated)
    if "approxLogTime" not in req_fields and not group_by:
        req_fields.append("approxLogTime")

    # Resolve time range
    now = datetime.now(UTC)
    if start_time:
        resolved_start = start_time if start_time.tzinfo else start_time.replace(tzinfo=UTC)
        resolved_end = (end_time or now)
        if resolved_end.tzinfo is None:
            resolved_end = resolved_end.replace(tzinfo=UTC)
    elif lookback_days:
        resolved_start = now - timedelta(days=lookback_days)
        resolved_end = now
    elif lookback_hours:
        resolved_start = now - timedelta(hours=lookback_hours)
        resolved_end = now
    else:
        resolved_start = now - timedelta(hours=24)
        resolved_end = now

    body: dict[str, Any] = {
        "limit": limit,
        "distinct": distinct,
        # EQL goes in BOTH fields. Measured 2026-08-12 on baystate.use1 (US-East)
        # and csnsafusion (SA): sending EQL only in `query` returns the UNFILTERED
        # result set, byte-identical to sending no filter at all — no error, no
        # warning, just every event. `filter` is the field both tenants honour.
        #
        # Sending it in both is deliberate rather than switching outright. If a
        # tenant honours `query`, it filters; if it honours `filter`, it filters;
        # if it ANDs them, the same EQL twice is the same result. Verified to
        # return the correct single-value result on both tenants above.
        #
        # `filter` must also never be absent — the endpoint returns 400
        # "Mandatory filter field missing" (EXA-SEARCH-FILTER-400), which is why
        # the empty-string default stayed even when it was doing nothing else.
        "query": filter,
        "filter": filter,
        "startTime": resolved_start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "endTime": resolved_end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "fields": req_fields,
    }
    if group_by:
        body["groupBy"] = group_by
    if order_by:
        body["orderBy"] = order_by

    response = client.post("/search/v2/events", json=body)

    if raw:
        return response

    rows = response.get("rows", [])

    # Convert approxLogTime (microseconds) to ISO timestamp
    for row in rows:
        approx = row.get("approxLogTime")
        if approx:
            try:
                epoch_seconds = int(approx) // 1_000_000
                row["timestamp"] = datetime.fromtimestamp(
                    epoch_seconds, tz=UTC
                ).isoformat()
            except (ValueError, OSError):
                pass

    return rows

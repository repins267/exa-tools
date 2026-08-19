"""Search Exabeam events using Exabeam Query Language (EQL).

API endpoint: POST /search/v2/events
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

# The API returns ONLY the fields asked for. A field that was not requested is
# absent from the response, and absent is indistinguishable from null -- so a
# field-population analysis built on the default set reports every unrequested
# field as 0% populated, confidently and silently.
#
# Measured 2026-08-13 on lvcva: 50,000 dns-response events read with these
# defaults showed dns_domain "0% populated", supporting a conclusion that the
# Cisco Umbrella parser was dropping the queried domain. Requesting the field
# explicitly returned it on 99.2% of the same events, 1,035 distinct domains.
# The parser was fine; the default hid the data.
#
# Fields named in the EQL filter are now added automatically (see
# _fields_in_filter), which covers the common case. It does NOT cover inspecting
# a field you never filtered on -- for that, pass `fields` explicitly.
_DEFAULT_FIELDS = ["user", "host", "src_ip", "dest_ip", "activity_type", "outcome"]

# CIM field names appearing as `field:` or `field :` at the start of an EQL term.
_EQL_FIELD_RE = re.compile(r"(?:^|[\s(!])([a-z_][a-z0-9_]{2,})\s*:")

# EQL operators and functions that _EQL_FIELD_RE would otherwise treat as fields.
_EQL_NON_FIELDS = frozenset({"and", "or", "not", "wldi", "rgxi", "in", "true", "false"})


def _fields_in_filter(eql: str) -> list[str]:
    """CIM field names referenced by an EQL filter string.

    Filtering on a field and then not getting it back is the sharp edge of the
    request-only-what-you-name contract, so those fields ride along by default.
    """
    if not eql:
        return []
    seen: dict[str, None] = {}
    for name in _EQL_FIELD_RE.findall(eql):
        if name.lower() not in _EQL_NON_FIELDS:
            seen.setdefault(name, None)
    return list(seen)


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
        fields: CIM field names to return. **The API returns ONLY these.** A field
            you do not name is ABSENT from the rows, which is indistinguishable
            from it being null -- so never conclude a field is unpopulated
            without having requested it. Fields named in `filter` are added
            automatically; anything else you intend to READ must be listed here.
        start_time/end_time: Absolute time range.
        lookback_hours/lookback_days: Relative time range from now.
        limit: Max events (default 10000, max 1000000).
        distinct: Return only distinct events.
        raw: Return raw API response instead of flattened rows.
    """
    req_fields = list(fields or _DEFAULT_FIELDS)
    # Anything filtered on comes back (filtering on a field then finding it
    # missing reads as null) -- EXCEPT in a GROUP BY query, where a selected
    # column that is neither grouped nor aggregated is a hard 400. In aggregate
    # mode the SELECT must be exactly the grouped columns plus aggregates, so do
    # NOT auto-append filter fields there.
    if not group_by:
        for name in _fields_in_filter(filter):
            if name not in req_fields:
                req_fields.append(name)
    # approxLogTime is invalid in GROUP BY queries AND in pure-aggregate queries
    # (a count()-only select has no per-event row to carry a timestamp) -- either
    # way it is a column that is neither grouped nor aggregated -> 400.
    _has_plain_field = any("(" not in str(f) for f in req_fields)
    if "approxLogTime" not in req_fields and not group_by and _has_plain_field:
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

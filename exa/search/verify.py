"""Live verification of documented Search/EQL behavior.

Every claim in the vault note `50-Product-Docs/search-and-eql.md` is distilled from
vendor documentation, which makes it guidance and not evidence. This module turns
each claim into a live probe against a tenant and returns a verdict.

Design rule -- **every probe is differential and preconditioned.**

This API's habit is to return a plausible number rather than an error
(EXA-SEARCH-QUERY-VS-FILTER, EXA-RULE-ISENABLED-FIELD, EXA-TABLE-KEY-ATTR all have
that shape). So a single call proves nothing: 3,000 rows coming back is equally
consistent with "a default was applied", "a hard cap was hit" and "only 3,000
events exist". Each probe therefore does two things:

1. **Differential** -- two or more calls whose results MUST differ if the claim is
   true. A claim that cannot be made to produce a difference is not testable here.
2. **Preconditioned** -- a separate measurement proving the tenant's data could
   have shown that difference. If the precondition fails the verdict is
   INCONCLUSIVE, never CONFIRMED.

Verdicts are CONFIRMED / REFUTED / INCONCLUSIVE. INCONCLUSIVE is mandatory when the
precondition fails -- a probe that cannot distinguish the two outcomes must say so
rather than reporting the reading it happened to get.

Read-only. Nothing here writes, creates or deletes. The one exception to "safe to
run unattended" is the pipe probe, which SPENDS from a shared deployment-wide quota
of 1,000 pipe queries per month -- it is opt-in and must never be scheduled.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from exa.exceptions import ExaAPIError

if TYPE_CHECKING:
    from exa.client import ExaClient

_VERIFY_DIR = Path.home() / ".exa" / "search-verify"

CONFIRMED = "CONFIRMED"
REFUTED = "REFUTED"
INCONCLUSIVE = "INCONCLUSIVE"

_SEARCH_PATH = "/search/v2/events"

# The documented API default when no limit is set (245604 p.57, 407948 p.338).
_DOCUMENTED_DEFAULT_LIMIT = 3000

# Sentinel meaning "send the same EQL in `query` as in `filter`" -- the shape
# EXA-SEARCH-QUERY-VS-FILTER requires. None means "omit the key entirely".
_SAME = object()

# An unaliased aggregation column is documented as `f0_` (245604 p.164).
_AGG_COL_RE = re.compile(r"^f\d+_")

# Fields sampled when a probe needs to find one that is null on some rows but not
# others. All verified CIM2 names (see 40-Reference/cim2-fields.md).
#
# STRING-TYPED FIRST, and typed fields last. `field:"null"` on an ipv4/ipv6-typed
# field is rejected with a TYPE error -- measured on sademodev22 2026-08-17:
# `src_ip:"null"` returned 400 AAA_ESA_1000_400 'Field src_ip has value "null",
# incompatible for type ipv4/ipv6'. That rejection says nothing about whether
# quoting changes matching semantics, which is the actual claim under test, so a
# typed field cannot settle it.
_NULLABLE_CANDIDATES = [
    "user",
    "host",
    "src_host",
    "dest_host",
    "web_domain",
    "process_name",
    "activity_type",
    # Typed fields, kept last and only as evidence of the type-rejection behavior.
    "src_ip",
    "dest_ip",
]
_TYPED_CANDIDATES = {"src_ip", "dest_ip"}


# ---------------------------------------------------------------------------
# Probe record
# ---------------------------------------------------------------------------


@dataclass
class Probe:
    """One claim under test, with everything needed to re-read it later."""

    probe: str
    claim: str
    source: str
    method: str = ""
    expected: str = ""
    precondition: str = ""
    precondition_met: bool | None = None
    verdict: str = INCONCLUSIVE
    reason: str = ""
    observed: dict[str, Any] = field(default_factory=dict)
    calls: list[dict[str, Any]] = field(default_factory=list)

    def settle(self, verdict: str, reason: str) -> Probe:
        self.verdict = verdict
        self.reason = reason
        return self

    def inconclusive(self, reason: str) -> Probe:
        return self.settle(INCONCLUSIVE, reason)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Low-level call plumbing
# ---------------------------------------------------------------------------


def _ts(moment: datetime) -> str:
    """Format a datetime the way the search endpoint accepts it."""
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _build_body(
    eql: str,
    start: datetime,
    end: datetime,
    *,
    fields: list[str] | None = None,
    limit: int | None = _DOCUMENTED_DEFAULT_LIMIT,
    omit_limit: bool = False,
    group_by: list[str] | None = None,
    order_by: list[str] | None = None,
    query: Any = _SAME,
) -> dict[str, Any]:
    """Build a search request body with full control over every key.

    `filter` is ALWAYS present, even when empty -- omitting it returns 400
    "Mandatory filter field missing" (EXA-SEARCH-FILTER-400), which would mask
    whatever the probe was actually testing.
    """
    body: dict[str, Any] = {}
    if not omit_limit and limit is not None:
        body["limit"] = limit
    body["distinct"] = False
    if query is _SAME:
        body["query"] = eql
    elif query is not None:
        body["query"] = query
    body["filter"] = eql
    body["startTime"] = _ts(start)
    body["endTime"] = _ts(end)
    body["fields"] = list(fields or ["activity_type"])
    if group_by:
        body["groupBy"] = group_by
    if order_by:
        body["orderBy"] = order_by
    return body


def _call(
    client: ExaClient,
    probe: Probe,
    label: str,
    body: dict[str, Any],
    *,
    count_values_of: str | None = None,
    agg_totals: bool = False,
    keep_sample: bool = False,
) -> dict[str, Any]:
    """POST a search body, record the outcome on the probe, and return it.

    Never raises. A rejected call is a measurement, not an accident -- probe 4
    exists precisely to capture rejection status codes and bodies.

    Rows themselves are NOT stored unless `keep_sample` is set: the artifact is a
    record of behavior, not a copy of tenant event data. Column names and value
    counts for one requested field are always kept, which is what the verdicts
    need.
    """
    outcome: dict[str, Any] = {"label": label, "request": body}
    try:
        response = client.post(_SEARCH_PATH, json=body)
    except ExaAPIError as exc:
        outcome.update(
            ok=False,
            status=exc.status_code,
            error=str(exc.detail)[:1000],
            row_count=None,
        )
        # The whole diagnosis lives in the error body, not the status code. The
        # first run of this battery returned three different 4xx for three
        # unrelated reasons, and only the codes told them apart.
        outcome.update(**_parse_error(exc.detail))
        probe.calls.append(outcome)
        return outcome
    except Exception as exc:  # transport failure, JSON decode failure
        outcome.update(ok=False, status=None, error=repr(exc)[:1000], row_count=None)
        probe.calls.append(outcome)
        return outcome

    rows = response.get("rows", []) if isinstance(response, dict) else []
    outcome.update(
        ok=True,
        status=200,
        row_count=len(rows),
        columns=sorted({key for row in rows[:50] for key in row}),
        # Any total/count key the endpoint volunteers. Recorded but never trusted
        # as a precondition -- a reported total is exactly the kind of plausible
        # number this module exists to distrust.
        totals_reported={
            key: response[key]
            for key in ("totalHits", "totalCount", "total", "recordCount", "hits")
            if isinstance(response, dict) and key in response
        },
        response_keys=sorted(response) if isinstance(response, dict) else [],
    )
    if count_values_of:
        counts = Counter(
            "<null>" if row.get(count_values_of) in (None, "") else str(row[count_values_of])
            for row in rows
        )
        outcome["distinct_values"] = len(counts)
        outcome["value_counts"] = dict(counts.most_common(25))
    if agg_totals:
        # Summed over EVERY row, not the retained sample -- probe 3's whole
        # argument is that a total can be short, and a total computed from two
        # kept rows would be short for a reason that has nothing to do with the
        # API.
        total = 0
        used: list[str] = []
        for row in rows:
            for key, value in row.items():
                if (_AGG_COL_RE.match(key) or key.lower() in ("count", "count(*)", "total")) \
                        and isinstance(value, (int, float)) and not isinstance(value, bool):
                    total += int(value)
                    if key not in used:
                        used.append(key)
        outcome["agg_total"] = total if used else None
        outcome["agg_columns"] = used
    if keep_sample:
        outcome["sample_rows"] = rows[:2]
    probe.calls.append(outcome)
    return outcome


def _parse_error(detail: Any) -> dict[str, Any]:
    """Pull the Exabeam error code and message out of a rejection body.

    The status code alone is not a diagnosis. The first live run of this battery
    produced three different 4xx for three unrelated reasons -- a context-table
    column that did not exist, a time range past a documented boundary, and a field
    type mismatch -- and only the `AAA_ESA_*` codes told them apart. Two of those
    messages named a limit verbatim, which is stronger evidence than any row count
    this module can compute.
    """
    body: Any = detail
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except (ValueError, TypeError):
            return {"error_code": None, "error_message": body[:500]}
    if not isinstance(body, dict):
        return {"error_code": None, "error_message": str(body)[:500]}

    # Observed shapes: {"errors": [{"id": ..., "message": ...}]} and a flat
    # {"code"/"errorCode": ..., "message": ...}. Accept either.
    entry: dict[str, Any] = body
    errors = body.get("errors")
    if isinstance(errors, list) and errors and isinstance(errors[0], dict):
        entry = errors[0]

    code = entry.get("id") or entry.get("code") or entry.get("errorCode")
    message = entry.get("message") or entry.get("detail") or entry.get("error")
    return {
        "error_code": str(code) if code is not None else None,
        "error_message": str(message)[:500] if message is not None else None,
    }


def _error_text(outcome: dict[str, Any]) -> str:
    """Everything a rejection said, lowercased, for substring matching."""
    return " ".join(
        str(outcome.get(key) or "")
        for key in ("error_code", "error_message", "error")
    ).lower()


def _ok(*outcomes: dict[str, Any]) -> bool:
    return all(o.get("ok") for o in outcomes)


def _rows(outcome: dict[str, Any]) -> int:
    return outcome.get("row_count") or 0


def _discriminating_filter(
    client: ExaClient,
    probe: Probe,
    start: datetime,
    end: datetime,
) -> tuple[str, str, dict[str, int]] | None:
    """Find an `activity_type` value that matches SOME but not ALL events.

    A filter that matches everything cannot demonstrate filtering, so this is the
    precondition for the query-vs-filter regression: pick the LEAST common value in
    an unfiltered sample. If only one distinct value exists on this tenant, no
    filter can produce a visible difference and the caller must go INCONCLUSIVE.
    """
    sample = _call(
        client,
        probe,
        "precondition: unfiltered sample",
        _build_body("", start, end, fields=["activity_type"], limit=200),
        count_values_of="activity_type",
    )
    if not sample.get("ok") or _rows(sample) == 0:
        return None
    counts: dict[str, int] = sample.get("value_counts", {})
    usable = {k: v for k, v in counts.items() if k != "<null>"}
    if len(counts) < 2 or not usable:
        return None
    value = min(usable, key=lambda k: usable[k])
    return f'activity_type:"{value}"', value, counts


# ---------------------------------------------------------------------------
# Probe 0 -- the EXA-SEARCH-QUERY-VS-FILTER regression assertion
# ---------------------------------------------------------------------------


def probe_query_vs_filter(client: ExaClient, *, now: datetime, lookback_days: int = 7) -> Probe:
    """EQL sent only in `query` returns the UNFILTERED result set.

    This is the register's Tier 1 defect and the reason every search in this repo
    sends the EQL twice. It runs on every verification pass as a permanent
    regression assertion: if it ever flips to REFUTED, the double-send in
    `exa/search/events.py` can be simplified -- and until then it must not be.
    """
    probe = Probe(
        probe="P0-query-vs-filter-regression",
        claim=(
            "EQL in the `query` body field alone is IGNORED -- the endpoint returns the "
            "unfiltered result set. Only `filter` narrows the search."
        ),
        source="EXA-SEARCH-QUERY-VS-FILTER (measured 2026-08-12, baystate.use1 + csnsafusion)",
        method=(
            "Pick the least common activity_type in an unfiltered sample, then run it "
            "three ways over one window: (a) in both query+filter, (b) in query only with "
            "filter empty, (c) neither. Compare row counts AND the number of distinct "
            "activity_type values returned."
        ),
        expected=(
            "CONFIRMED when (b) returns more than one distinct activity_type -- i.e. it "
            "behaves like (c) rather than (a). REFUTED when (b) matches (a)."
        ),
        precondition=(
            "The unfiltered sample must contain at least 2 distinct activity_type values, "
            "otherwise no filter can produce a visible difference."
        ),
    )
    start, end = now - timedelta(days=lookback_days), now

    picked = _discriminating_filter(client, probe, start, end)
    if picked is None:
        probe.precondition_met = False
        return probe.inconclusive(
            "Could not find an activity_type value matching some-but-not-all events in the "
            f"last {lookback_days}d (empty tenant, or a single activity_type). No filter "
            "can be shown to narrow anything here."
        )
    eql, value, counts = picked
    probe.precondition_met = True
    probe.observed["filter_used"] = eql
    probe.observed["sample_activity_types"] = counts

    both = _call(
        client, probe, "a: EQL in query AND filter",
        _build_body(eql, start, end, fields=["activity_type"], limit=5000),
        count_values_of="activity_type",
    )
    query_only = _call(
        client, probe, "b: EQL in query only, filter empty",
        _build_body("", start, end, fields=["activity_type"], limit=5000, query=eql),
        count_values_of="activity_type",
    )
    neither = _call(
        client, probe, "c: no EQL in either field",
        _build_body("", start, end, fields=["activity_type"], limit=5000),
        count_values_of="activity_type",
    )

    if not _ok(both, query_only, neither):
        return probe.inconclusive("One or more calls did not return 200 -- see calls[].")

    probe.observed.update(
        rows_both=_rows(both),
        rows_query_only=_rows(query_only),
        rows_unfiltered=_rows(neither),
        distinct_both=both.get("distinct_values"),
        distinct_query_only=query_only.get("distinct_values"),
        distinct_unfiltered=neither.get("distinct_values"),
    )

    if (neither.get("distinct_values") or 0) < 2:
        probe.precondition_met = False
        return probe.inconclusive(
            "The unfiltered call returned a single distinct activity_type, so (b) and (c) "
            "are indistinguishable from (a) whatever the endpoint does."
        )

    if (both.get("distinct_values") or 0) > 1:
        return probe.inconclusive(
            f"NEW FINDING -- `filter` did not narrow either: (a) returned "
            f"{both.get('distinct_values')} distinct activity_type values while asking only "
            f"for {value!r}. The register describes `query` being ignored, not `filter`. "
            "Do not trust ANY filtered search on this tenant until this is understood."
        )

    if (query_only.get("distinct_values") or 0) > 1:
        return probe.settle(
            CONFIRMED,
            f"`query` alone did not filter: it returned "
            f"{query_only.get('distinct_values')} distinct activity_type values "
            f"({_rows(query_only)} rows) against {value!r}'s "
            f"{both.get('distinct_values')} value / {_rows(both)} rows. The double-send in "
            "exa/search/events.py is still required.",
        )

    return probe.settle(
        REFUTED,
        f"`query` alone filtered correctly -- 1 distinct value, {_rows(query_only)} rows, "
        f"matching the both-fields call ({_rows(both)} rows). The defect appears fixed on "
        "this tenant. Re-run on the other region before changing events.py: this defect "
        "was region-dependent once already.",
    )


# ---------------------------------------------------------------------------
# Probe 1 -- 3,000 is a default, not a cap
# ---------------------------------------------------------------------------


def probe_limit_default(client: ExaClient, *, now: datetime, lookback_days: int = 7) -> Probe:
    """3,000 results is the API's default when no limit is set, not a ceiling."""
    probe = Probe(
        probe="P1-limit-default-3000",
        claim=(
            "3,000 is the API's DEFAULT when no limit is set, not a hard ceiling. "
            "Higher values can be set."
        ),
        source="245604 p.57 (2026-07-14); 407948 p.338 NGS-4653 (Feb 2025)",
        method=(
            "Same window, five ways: no `limit` key at all, then limit 3000 / 5000 / 10000, "
            "then a `LIMIT 10000` EQL clause instead of a body key. Precondition comes "
            "from splitting the window into two halves and summing their row counts, which "
            "proves more than 3,000 events exist WITHOUT relying on a reported total."
        ),
        expected=(
            "CONFIRMED when limit=10000 returns more than 3,000 rows. REFUTED when it "
            "returns exactly 3,000 while the two halves sum to more -- that is a real cap."
        ),
        precondition="The two half-windows must together return more than 3,000 rows.",
    )
    start, end = now - timedelta(days=lookback_days), now
    mid = start + (end - start) / 2
    small = ["activity_type"]

    first = _call(
        client, probe, "precondition: first half, limit 10000",
        _build_body("", start, mid, fields=small, limit=10000),
    )
    second = _call(
        client, probe, "precondition: second half, limit 10000",
        _build_body("", mid, end, fields=small, limit=10000),
    )
    if not _ok(first, second):
        return probe.inconclusive("A precondition half-window call failed -- see calls[].")

    halves_total = _rows(first) + _rows(second)
    probe.observed["halves_total"] = halves_total
    probe.observed["half_rows"] = [_rows(first), _rows(second)]
    if halves_total <= _DOCUMENTED_DEFAULT_LIMIT:
        probe.precondition_met = False
        return probe.inconclusive(
            f"Only {halves_total} rows exist across both halves of the last {lookback_days}d. "
            "With fewer than 3,000 events available, a 3,000-row answer proves nothing -- "
            "widen --lookback or run against a busier tenant."
        )
    probe.precondition_met = True

    no_limit = _call(
        client, probe, "a: no limit key",
        _build_body("", start, end, fields=small, omit_limit=True),
    )
    at_3000 = _call(
        client, probe, "b: limit 3000",
        _build_body("", start, end, fields=small, limit=3000),
    )
    at_5000 = _call(
        client, probe, "c: limit 5000",
        _build_body("", start, end, fields=small, limit=5000),
    )
    at_10000 = _call(
        client, probe, "d: limit 10000",
        _build_body("", start, end, fields=small, limit=10000),
    )
    # A bare `LIMIT 10000` is invalid by the guide's own clause rule -- "a query using
    # advanced operators must contain at least one SELECT or one WHERE" (245604 p.150).
    # The first run of this battery sent it bare, got a 400, and would have been read as
    # "EQL LIMIT is rejected" when the request was simply malformed. Send a well-formed
    # query so a rejection is attributable to the LIMIT clause and nothing else.
    eql_limit_query = f"SELECT {small[0]} WHERE {small[0]}:* LIMIT 10000"
    eql_limit = _call(
        client, probe, "e: well-formed EQL LIMIT 10000 clause, no limit key",
        _build_body(eql_limit_query, start, end, fields=small, omit_limit=True),
    )
    # Same query without the LIMIT clause: if this is rejected too, the rejection is
    # about advanced-operator support in `filter`, not about LIMIT.
    eql_control = _call(
        client, probe, "f: same EQL without the LIMIT clause (control)",
        _build_body(f"SELECT {small[0]} WHERE {small[0]}:*", start, end,
                    fields=small, omit_limit=True),
    )

    probe.observed.update(
        rows_no_limit_key=_rows(no_limit) if no_limit.get("ok") else None,
        rows_limit_3000=_rows(at_3000) if at_3000.get("ok") else None,
        rows_limit_5000=_rows(at_5000) if at_5000.get("ok") else None,
        rows_limit_10000=_rows(at_10000) if at_10000.get("ok") else None,
        eql_limit_query=eql_limit_query,
        rows_eql_limit_clause=_rows(eql_limit) if eql_limit.get("ok") else None,
        eql_limit_clause_status=eql_limit.get("status"),
        eql_limit_clause_error=eql_limit.get("error_message"),
        eql_control_status=eql_control.get("status"),
        eql_control_error=eql_control.get("error_message"),
        # True only when LIMIT is the difference between accepted and rejected.
        eql_limit_clause_is_the_cause=(
            bool(eql_control.get("ok")) and not eql_limit.get("ok")
        ),
    )

    default_note = ""
    if no_limit.get("ok"):
        observed_default = _rows(no_limit)
        probe.observed["default_matches_3000"] = observed_default == _DOCUMENTED_DEFAULT_LIMIT
        default_note = (
            f" Omitting `limit` returned {observed_default} rows"
            + (
                " -- exactly the documented default."
                if observed_default == _DOCUMENTED_DEFAULT_LIMIT
                else f" -- NOT the documented default of {_DOCUMENTED_DEFAULT_LIMIT}."
            )
        )

    if not at_10000.get("ok"):
        return probe.inconclusive(
            f"limit=10000 was rejected (HTTP {at_10000.get('status')}). That is neither the "
            "documented default nor a documented cap -- record it as a new finding."
            + default_note
        )

    if _rows(at_10000) > _DOCUMENTED_DEFAULT_LIMIT:
        return probe.settle(
            CONFIRMED,
            f"limit=10000 returned {_rows(at_10000)} rows, above 3,000, so 3,000 is not a "
            f"ceiling.{default_note} Treat any run returning exactly 3,000 as suspect.",
        )

    return probe.settle(
        REFUTED,
        f"limit=10000 returned {_rows(at_10000)} rows while the two half-windows sum to "
        f"{halves_total}, so more data existed and was not returned. 3,000 behaves as a HARD "
        f"CAP on this tenant, not a default.{default_note} Paging code must not assume it "
        "can raise the limit.",
    )


# ---------------------------------------------------------------------------
# Probe 2 -- the context-table lookup window
# ---------------------------------------------------------------------------


_WINDOW_LOOKBACKS = [7, 29, 31, 60, 89, 91, 120]


def probe_context_table_window(
    client: ExaClient,
    *,
    now: datetime,
    table_name: str = "Public AI Domains and Risk",
    table_id: str | None = None,
    table_column: str | None = None,
    event_field: str = "web_domain",
    sample_values: int = 20,
) -> Probe:
    """Context-table lookups are limited to a 90-day sliding window (was 30)."""
    probe = Probe(
        probe="P2-context-table-90-day-window",
        claim=(
            "A context-table lookup in a search matches only within a 90-day sliding "
            "window. Raised from 30 days in the Jul 2026 edition."
        ),
        source="245604 p.75 (2026-07-14); 2025 edition said 30",
        method=(
            "Run the SAME match two ways at 7/29/31/60/89/91/120 days: once via "
            "`field IN \"table\".\"column\"`, once as a literal OR-list of the same values "
            "read from the table. The literal form has no context-table window, so it is "
            "the control. The window is real only where the table form goes to zero and the "
            "literal form does not."
        ),
        expected=(
            "CONFIRMED when the table form returns rows at <=89d and zero at 91d/120d while "
            "the literal control still returns rows there. REFUTED when the table form "
            "returns rows at 120d."
        ),
        precondition=(
            "The table must be populated, the table form must return rows at 30d (proving "
            "the lookup works at all), and the literal control must return rows beyond 90d "
            "(proving matchable events exist out there)."
        ),
    )

    # Pin the table by ID. Name resolution is deliberately strict: sademodev22
    # carries both "Public AI Domains and Risk" and "...Risks", and a prefix match
    # would silently probe the wrong one.
    from exa.context.tables import get_all_records_keyed, get_tables

    resolved_id = table_id
    resolved_name = table_name
    if resolved_id is None:
        try:
            tables = get_tables(client) or []
        except ExaAPIError as exc:
            return probe.inconclusive(f"Could not list context tables: HTTP {exc.status_code}.")
        wanted = table_name.strip().lower()
        # EXA-DISPLAYNAME-UNDOCUMENTED: displayName is null on most tenants.
        matches = [
            t for t in tables
            if ((t.get("displayName") or t.get("name") or "").strip().lower() == wanted)
        ]
        probe.observed["name_matches"] = len(matches)
        if not matches:
            near = [
                (t.get("displayName") or t.get("name") or "")
                for t in tables
                if wanted[:12] in (t.get("displayName") or t.get("name") or "").lower()
            ]
            return probe.inconclusive(
                f"No context table is named exactly {table_name!r} on this tenant."
                + (f" Near misses: {near}. Pass --table-id to pin one." if near else "")
            )
        if len(matches) > 1:
            return probe.inconclusive(
                f"{len(matches)} tables are named {table_name!r} -- ambiguous. Pass "
                "--table-id so the probe cannot silently read the wrong one."
            )
        resolved_id = matches[0].get("id")
        resolved_name = matches[0].get("displayName") or matches[0].get("name") or table_name

    # EXA-TABLE-KEY-ATTR: never assume the key attribute is called "key".
    try:
        key_attr, records, _ = get_all_records_keyed(client, resolved_id)
    except ExaAPIError as exc:
        return probe.inconclusive(
            f"Could not read records from table {resolved_id}: HTTP {exc.status_code}."
        )
    column = table_column or key_attr
    values = [
        str(r[column]).strip()
        for r in records
        if r.get(column) not in (None, "")
    ][:sample_values]
    probe.observed.update(
        table_id=resolved_id,
        table_name=resolved_name,
        key_attribute=key_attr,
        column_used=column,
        record_count=len(records),
        control_values_used=len(values),
    )
    if not values:
        probe.precondition_met = False
        return probe.inconclusive(
            f"Table {resolved_name!r} yielded no values in column {column!r} "
            f"({len(records)} records read). A context lookup against an empty column "
            "returns no results by design (245604 p.75), so nothing can be measured."
        )

    # Two spellings of the same lookup. The qualified form names the column; the
    # unqualified form is documented to search the table's key column. On the first
    # live run the qualified form 404'd with "Context table non-key field :
    # aillm_domain not found" against the column the context-management API reports
    # as the KEY -- so the two APIs disagree about what the key is, and probing only
    # the qualified form measures that disagreement instead of the window.
    qualified_eql = f'{event_field} IN "{resolved_name}"."{column}"'
    unqualified_eql = f'{event_field} IN "{resolved_name}"'
    control_eql = "(" + " OR ".join(f'{event_field}:"{v}"' for v in values) + ")"
    probe.observed["table_eql"] = qualified_eql
    probe.observed["table_eql_unqualified"] = unqualified_eql
    probe.observed["control_value_count"] = len(values)

    # Settle on a spelling first, at a lookback well inside every documented window,
    # so the window sweep is not fighting a column-resolution error at every point.
    probe_q = _call(
        client, probe, "spelling: qualified table.column, 7d",
        _build_body(qualified_eql, now - timedelta(days=7), now,
                    fields=[event_field], limit=1000),
    )
    probe_u = _call(
        client, probe, "spelling: unqualified table (key column), 7d",
        _build_body(unqualified_eql, now - timedelta(days=7), now,
                    fields=[event_field], limit=1000),
    )
    probe.observed["qualified_status_7d"] = probe_q.get("status")
    probe.observed["qualified_error_7d"] = probe_q.get("error_message")
    probe.observed["unqualified_status_7d"] = probe_u.get("status")
    probe.observed["unqualified_error_7d"] = probe_u.get("error_message")

    if probe_q.get("ok"):
        table_eql, spelling = qualified_eql, "qualified"
    elif probe_u.get("ok"):
        table_eql, spelling = unqualified_eql, "unqualified"
    else:
        table_eql, spelling = qualified_eql, "qualified (both spellings rejected)"
    probe.observed["spelling_used"] = spelling

    table_rows: dict[int, int | None] = {}
    control_rows: dict[int, int | None] = {}
    table_status: dict[int, int | None] = {}
    table_errors: dict[int, str | None] = {}
    for days in _WINDOW_LOOKBACKS:
        start = now - timedelta(days=days)
        t = _call(
            client, probe, f"table form ({spelling}), {days}d",
            _build_body(table_eql, start, now, fields=[event_field], limit=1000),
        )
        c = _call(
            client, probe, f"literal control, {days}d",
            _build_body(control_eql, start, now, fields=[event_field], limit=1000),
        )
        # None means the call FAILED. 0 means it succeeded and matched nothing. The
        # first version of this probe collapsed both to falsy and reported "returned
        # no rows" for a window where every single call had 404'd.
        table_rows[days] = _rows(t) if t.get("ok") else None
        control_rows[days] = _rows(c) if c.get("ok") else None
        table_status[days] = t.get("status")
        table_errors[days] = t.get("error_code") or (
            str(t.get("error_message"))[:120] if t.get("error_message") else None
        )

    probe.observed["table_rows_by_lookback"] = table_rows
    probe.observed["control_rows_by_lookback"] = control_rows
    probe.observed["table_status_by_lookback"] = table_status
    probe.observed["table_error_by_lookback"] = table_errors

    # --- The endpoint may simply state the limit -------------------------------
    # A rejection naming the boundary is better evidence than any row count: it is
    # the vendor's own implementation talking, it cannot be a data artifact, and it
    # means the limit is enforced LOUDLY rather than by silent truncation.
    def _table_call(days: int) -> dict[str, Any]:
        label = f"table form ({spelling}), {days}d"
        for call in probe.calls:
            if call.get("label") == label:
                return call
        return {}

    range_rejected = {
        d for d in _WINDOW_LOOKBACKS if "time range" in _error_text(_table_call(d))
    }
    stated = [
        c for c in probe.calls
        if "context table does not support time range" in _error_text(c)
    ]
    if stated:
        message = stated[0].get("error_message") or ""
        rejected_at = sorted(range_rejected)
        accepted_at = sorted(set(_WINDOW_LOOKBACKS) - range_rejected)
        probe.observed["range_error_message"] = message
        probe.observed["range_rejected_at"] = rejected_at
        probe.observed["range_not_rejected_at"] = accepted_at
        probe.precondition_met = True
        return probe.settle(
            CONFIRMED,
            f"The endpoint states the limit itself: {message!r} (HTTP "
            f"{stated[0].get('status')}, {stated[0].get('error_code')}). Rejected at "
            f"{rejected_at}d, not rejected at {accepted_at}d. Enforced LOUDLY, not by "
            "silent truncation -- so a context-table search spanning the boundary errors "
            "rather than quietly returning less. Note the wording is 'x days or more', "
            "making the boundary EXCLUSIVE: the documented '90 day window' means 89 days "
            "is the widest accepted span, not 90.",
        )

    if table_rows.get(29) is None:
        probe.precondition_met = False
        return probe.inconclusive(
            f"The table form did not merely return zero rows at 29 days -- the CALL FAILED "
            f"(HTTP {table_status.get(29)}, {table_errors.get(29)}). Nothing about the window "
            f"can be read from this. Qualified spelling: HTTP {probe_q.get('status')}; "
            f"unqualified: HTTP {probe_u.get('status')}. If both are 404 on a column the "
            f"context API reports as the key ({key_attr!r}), that is a finding in its own "
            "right and belongs in the defect register, not here."
        )
    if not table_rows.get(29):
        probe.precondition_met = False
        return probe.inconclusive(
            f"The table form returned 200 but zero rows at 29 days, so the lookup matches "
            f"nothing on this tenant -- there is no window to measure. Check that "
            f"{event_field!r} carries values present in {resolved_name!r}."
        )
    if not control_rows.get(120):
        probe.precondition_met = False
        return probe.inconclusive(
            "The literal control returned no rows at 120 days, so no matchable events exist "
            "beyond the window. A zero from the table form out there would prove nothing "
            "about the window."
        )
    probe.precondition_met = True

    beyond = [d for d in (91, 120) if (table_rows.get(d) or 0) > 0]
    if beyond:
        detail = ", ".join(f"{d}d={table_rows[d]}" for d in beyond)
        return probe.settle(
            REFUTED,
            f"The table form still returned rows past 90 days ({detail}). Either the "
            "documented window is not enforced here or it is larger than 90 days.",
        )

    inside_29 = table_rows.get(29) or 0
    inside_89 = table_rows.get(89) or 0
    boundary = (
        "and 29d/89d both returned rows, so the old 30-day window is NOT in force"
        if inside_89 >= inside_29 and inside_89 > 0
        else f"but 89d returned {inside_89} against 29d's {inside_29} -- lower at the wider "
        "window, which would be the OLD 30-day behavior. Check the tenant's version"
    )
    return probe.settle(
        CONFIRMED,
        f"The table form returned zero past 90 days (91d and 120d) while the literal control "
        f"returned {control_rows.get(120)} rows at 120d, so the cut-off is the context-table "
        f"window and not the data. Rows inside: 7d={table_rows.get(7)}, 29d={inside_29}, "
        f"31d={table_rows.get(31)}, 60d={table_rows.get(60)}, 89d={inside_89} -- {boundary}.",
    )


# ---------------------------------------------------------------------------
# Probe 3 -- aggregations are limited to a 7-day window
# ---------------------------------------------------------------------------


def _agg_total(outcome: dict[str, Any]) -> tuple[int | None, list[str]]:
    """Read back the aggregation total `_call(agg_totals=True)` computed.

    The count column's name is itself under test in probe 5 -- documented as `f0_`
    when unaliased -- so the summing never assumes `count`.
    """
    return outcome.get("agg_total"), outcome.get("agg_columns") or []


def _agg_eql_candidates(group_field: str) -> list[str]:
    """Candidate EQL spellings for "count events per value of a field".

    The body's `groupBy` key returns the grouped column and NOTHING ELSE -- no count
    column at all, measured on sademodev22 2026-08-17. So a count has to come from an
    EQL aggregation, and the clause spelling is not something to guess: the guide
    renders it inconsistently across pages. Probe the spellings and record which one
    the endpoint actually accepts.
    """
    return [
        f"SELECT {group_field}, COUNT(*) GROUP-BY {group_field}",
        f"SELECT {group_field}, COUNT(*) GROUP BY {group_field}",
        f"SELECT {group_field}, COUNT() GROUP-BY {group_field}",
        f"SELECT COUNT(*) GROUP-BY {group_field}",
    ]


def probe_aggregation_window(
    client: ExaClient, *, now: datetime, group_field: str = "activity_type"
) -> Probe:
    """Aggregations are limited to a 7-day sliding window."""
    probe = Probe(
        probe="P3-aggregation-7-day-window",
        claim="Search aggregations are limited to a 7 day sliding window.",
        source="245604 p.106 (2026-07-14)",
        method=(
            "Find an EQL COUNT() spelling the endpoint accepts, then aggregate at 6d, 8d "
            "and 30d and cross-check: the 8d total must equal the sum of two adjacent 4d "
            "totals over exactly the same span. All windows derive from one pinned `now`, "
            "so the halves tile the whole exactly and any shortfall is truncation rather "
            "than clock drift. The body's `groupBy` key cannot be used for this -- it "
            "returns no count column -- so it is recorded only as a shape observation."
        ),
        expected=(
            "CONFIRMED when the 8d aggregation is rejected, or returns a total short of the "
            "two 4d totals summed. REFUTED when 8d and 30d aggregate correctly and the "
            "cross-check reconciles."
        ),
        precondition=(
            "An EQL COUNT() spelling must be accepted AND yield a summable count column at "
            "6 days, or there is no total to compare across windows."
        ),
    )
    six_start = now - timedelta(days=6)

    # Shape observation first: what does the body's groupBy key actually return?
    body_group = _call(
        client, probe, "shape: body groupBy key, 6 days",
        _build_body("", six_start, now, fields=[group_field], limit=1000,
                    group_by=[group_field]),
        agg_totals=True,
    )
    probe.observed["body_groupby_columns"] = body_group.get("columns")
    probe.observed["body_groupby_rows"] = _rows(body_group) if body_group.get("ok") else None
    probe.observed["body_groupby_has_count_column"] = bool(body_group.get("agg_columns"))

    # Now find an EQL spelling that produces a countable column.
    agg_eql: str | None = None
    spelling_results: dict[str, Any] = {}
    for candidate in _agg_eql_candidates(group_field):
        outcome = _call(
            client, probe, f"spelling: {candidate}",
            _build_body(candidate, six_start, now, fields=[group_field], limit=1000),
            agg_totals=True,
        )
        spelling_results[candidate] = {
            "status": outcome.get("status"),
            "rows": _rows(outcome) if outcome.get("ok") else None,
            "columns": outcome.get("columns"),
            "count_columns": outcome.get("agg_columns"),
            "error": outcome.get("error_message"),
        }
        if outcome.get("ok") and outcome.get("agg_columns") and _rows(outcome):
            agg_eql = candidate
            break
    probe.observed["eql_aggregation_spellings"] = spelling_results
    probe.observed["eql_aggregation_used"] = agg_eql

    if agg_eql is None:
        probe.precondition_met = False
        return probe.inconclusive(
            "No EQL aggregation spelling produced a summable count column, and the body's "
            f"`groupBy` key returns {body_group.get('columns')} -- the grouped column and no "
            "count. Without a total there is nothing to compare across windows, so the 7-day "
            "claim is UNTESTED here rather than refuted. Spellings tried and what each "
            f"returned: {spelling_results}."
        )

    def agg(label: str, start: datetime, end: datetime) -> dict[str, Any]:
        return _call(
            client, probe, label,
            _build_body(agg_eql, start, end, fields=[group_field], limit=1000),
            agg_totals=True,
        )

    six = agg("a: 6 days", six_start, now)
    if not six.get("ok"):
        return probe.inconclusive(
            f"The 6-day aggregation itself failed (HTTP {six.get('status')}); nothing "
            "narrower is available to compare against."
        )
    total_6, cols_6 = _agg_total(six)
    probe.observed["aggregation_columns"] = cols_6
    probe.observed["columns_returned_6d"] = six.get("columns")
    probe.observed["group_rows_6d"] = _rows(six)
    if not _rows(six) or not total_6:
        probe.precondition_met = False
        return probe.inconclusive(
            f"The 6-day aggregation returned {_rows(six)} group rows totalling {total_6} -- "
            "no data to aggregate in the window where aggregation is supposed to work."
        )
    probe.precondition_met = True

    eight = agg("b: 8 days", now - timedelta(days=8), now)
    thirty = agg("c: 30 days", now - timedelta(days=30), now)
    half_a = agg("d: days 8-4 (first 4d slice)", now - timedelta(days=8), now - timedelta(days=4))
    half_b = agg("e: days 4-0 (second 4d slice)", now - timedelta(days=4), now)

    total_8, _ = _agg_total(eight)
    total_30, _ = _agg_total(thirty)
    total_a, _ = _agg_total(half_a)
    total_b, _ = _agg_total(half_b)

    probe.observed.update(
        group_rows_8d=_rows(eight) if eight.get("ok") else None,
        group_rows_30d=_rows(thirty) if thirty.get("ok") else None,
        status_8d=eight.get("status"),
        status_30d=thirty.get("status"),
        total_6d=total_6,
        total_8d=total_8,
        total_30d=total_30,
        total_4d_slices=[total_a, total_b],
    )

    if not eight.get("ok"):
        return probe.settle(
            CONFIRMED,
            f"The 8-day aggregation was rejected (HTTP {eight.get('status')}) while 6 days "
            "succeeded. The window is enforced, and enforced loudly.",
        )

    if total_8 is not None and total_a is not None and total_b is not None:
        slices_sum = total_a + total_b
        probe.observed["slices_sum"] = slices_sum
        if slices_sum > total_8:
            return probe.settle(
                CONFIRMED,
                f"The 8-day aggregation returned 200 but totalled {total_8}, while the two "
                f"4-day slices covering the identical span total {slices_sum}. It is "
                f"truncating silently -- {slices_sum - total_8} events counted in the "
                "halves went uncounted in the whole. This is the dangerous form of the "
                "limit: no error, just a smaller number.",
            )
        return probe.settle(
            REFUTED,
            f"The 8-day aggregation reconciles with its two 4-day slices "
            f"({total_8} vs {slices_sum}) and the 30-day call returned "
            f"{_rows(thirty)} group rows (HTTP {thirty.get('status')}). No 7-day "
            "aggregation window is being enforced on this tenant.",
        )

    return probe.inconclusive(
        "Could not extract a comparable total from the aggregation responses -- no "
        f"count-shaped column was found (columns seen: {six.get('columns')}). The 7-day "
        "claim is untested; fix the total extraction against this response shape first."
    )


# ---------------------------------------------------------------------------
# Probe 4 -- the query time-range limit is license-specific
# ---------------------------------------------------------------------------


_RANGE_LOOKBACKS = [7, 30, 90, 180, 365, 400]


def probe_time_range_limit(client: ExaClient, *, now: datetime) -> Probe:
    """The query time range limit is per-license and its value is not published."""
    probe = Probe(
        probe="P4-query-time-range-license-limit",
        claim=(
            "Search does not permit unlimited query time ranges. The limit is "
            "license-specific and the number is not published, so tooling cannot "
            "precompute a safe range -- it has to handle the rejection."
        ),
        source="245604 p.82 (2026-07-14)",
        method=(
            "Escalate the window 7 -> 30 -> 90 -> 180 -> 365 -> 400 days with limit 1 and "
            "capture the exact status and body of the FIRST call that is not 200."
        ),
        expected=(
            "CONFIRMED when some window is rejected, recording the rejection shape. "
            "REFUTED when 400 days is accepted."
        ),
        precondition=(
            "The 7-day call must return 200, proving a rejection later is about the range "
            "and not about the request being malformed."
        ),
    )
    outcomes: dict[int, dict[str, Any]] = {}
    first_failure: int | None = None
    for days in _RANGE_LOOKBACKS:
        outcome = _call(
            client, probe, f"{days}d window, limit 1",
            _build_body("", now - timedelta(days=days), now, fields=["activity_type"], limit=1),
        )
        outcomes[days] = outcome
        if not outcome.get("ok") and first_failure is None:
            first_failure = days
            break

    probe.observed["status_by_lookback"] = {d: o.get("status") for d, o in outcomes.items()}
    probe.observed["rows_by_lookback"] = {
        d: (_rows(o) if o.get("ok") else None) for d, o in outcomes.items()
    }

    if not outcomes[7].get("ok"):
        probe.precondition_met = False
        return probe.inconclusive(
            f"Even the 7-day call failed (HTTP {outcomes[7].get('status')}), so nothing here "
            "can be attributed to the range."
        )
    probe.precondition_met = True

    if first_failure is None:
        return probe.settle(
            REFUTED,
            f"Every window up to {_RANGE_LOOKBACKS[-1]} days returned 200. No range limit is "
            "observable on this tenant's license -- which does NOT mean a customer's license "
            "has none. The rejection-handling path stays.",
        )

    failure = outcomes[first_failure]
    return probe.settle(
        CONFIRMED,
        f"The {first_failure}-day window was rejected with HTTP {failure.get('status')} "
        f"while {_RANGE_LOOKBACKS[_RANGE_LOOKBACKS.index(first_failure) - 1]} days "
        f"succeeded. Error body: {str(failure.get('error'))[:200]!r}. Only the REJECTION "
        "SHAPE transfers to a customer -- the boundary number is this tenant's license, not "
        "theirs, so never hard-code it.",
    )


# ---------------------------------------------------------------------------
# Probe 5 -- result shape and `f0_` aggregation column naming
# ---------------------------------------------------------------------------


def probe_result_shape(
    client: ExaClient, *, now: datetime, group_field: str = "activity_type"
) -> Probe:
    """Unaliased aggregation columns are named `f0_`, and projection changes shape."""
    probe = Probe(
        probe="P5-result-shape-and-f0-columns",
        claim=(
            "An unaliased aggregation column comes back named `f0_`, not `count` and not "
            "the field name. Separately, the projection (`SELECT *` vs `SELECT field`) "
            "changes the result shape, so a parser must branch on it."
        ),
        source="245604 pp.150-168 (2026-07-14)",
        method=(
            "Four calls over one window, comparing the COLUMN NAMES that come back: fields "
            "omitted entirely, fields ['*'], an explicit two-field list, and a groupBy "
            "aggregation. Column names are the observable -- no row data is needed."
        ),
        expected=(
            "CONFIRMED when the aggregation response carries a column matching `f<n>_`. "
            "REFUTED when its aggregation column has a readable name."
        ),
        precondition="The aggregation call must return at least one row to have columns.",
    )
    start = now - timedelta(days=1)

    omitted = _call(
        client, probe, "a: fields key omitted",
        {
            "limit": 5, "distinct": False, "query": "", "filter": "",
            "startTime": _ts(start), "endTime": _ts(now),
        },
    )
    star = _call(
        client, probe, "b: fields ['*']",
        _build_body("", start, now, fields=["*"], limit=5),
    )
    explicit = _call(
        client, probe, "c: explicit field list",
        _build_body("", start, now, fields=["user", group_field], limit=5),
    )
    # Body groupBy, then EQL COUNT(): the `f0_` claim is about an unaliased EQL
    # aggregation column, and the body's groupBy key produces no aggregation column at
    # all, so it cannot refute the naming. Measuring only groupBy is how the first run
    # of this probe reported REFUTED for a claim it had never tested.
    aggregated = _call(
        client, probe, "d: body groupBy key",
        _build_body("", start, now, fields=[group_field], limit=50, group_by=[group_field]),
        agg_totals=True,
    )
    eql_agg_results: dict[str, Any] = {}
    eql_agg: dict[str, Any] = {}
    for candidate in _agg_eql_candidates(group_field):
        outcome = _call(
            client, probe, f"e: EQL aggregation -- {candidate}",
            _build_body(candidate, start, now, fields=[group_field], limit=50),
            agg_totals=True,
        )
        eql_agg_results[candidate] = {
            "status": outcome.get("status"),
            "columns": outcome.get("columns"),
            "error": outcome.get("error_message"),
        }
        if outcome.get("ok") and _rows(outcome):
            eql_agg = outcome
            break

    probe.observed.update(
        columns_fields_omitted=omitted.get("columns"),
        columns_star=star.get("columns"),
        columns_explicit=explicit.get("columns"),
        columns_body_groupby=aggregated.get("columns"),
        body_groupby_count_columns=aggregated.get("agg_columns"),
        columns_eql_aggregation=eql_agg.get("columns"),
        eql_aggregation_spellings=eql_agg_results,
        status_fields_omitted=omitted.get("status"),
        status_star=star.get("status"),
        row_counts={
            "omitted": _rows(omitted) if omitted.get("ok") else None,
            "star": _rows(star) if star.get("ok") else None,
            "explicit": _rows(explicit) if explicit.get("ok") else None,
            "body_groupby": _rows(aggregated) if aggregated.get("ok") else None,
            "eql_aggregation": _rows(eql_agg) if eql_agg.get("ok") else None,
        },
    )

    # --- Projection finding (separate from the `f0_` claim) ---------------------
    star_cols = set(star.get("columns") or [])
    explicit_cols = set(explicit.get("columns") or [])
    omitted_cols = set(omitted.get("columns") or [])
    probe.observed["star_widens_projection"] = (
        len(star_cols) > len(explicit_cols) if star.get("ok") and explicit.get("ok") else None
    )
    # Measured on sademodev22 2026-08-17: omitting `fields` returns 18 metadata-only
    # columns and NO CIM fields, while fields:["*"] returns 56 including activity_type.
    # Omitting the key is not a synonym for "*", which is what a caller would assume.
    cim_in_star = sorted(star_cols - omitted_cols)
    probe.observed["omitted_is_metadata_only"] = (
        bool(omitted.get("ok")) and bool(star.get("ok")) and group_field not in omitted_cols
        and group_field in star_cols
    )
    probe.observed["fields_only_in_star"] = cim_in_star[:40]
    projection_note = (
        f" PROJECTION: omitting `fields` returned {len(omitted_cols)} columns without "
        f"{group_field!r}, while fields:['*'] returned {len(star_cols)} including it -- "
        "omitting the key is NOT equivalent to '*'; it yields metadata only."
        if probe.observed["omitted_is_metadata_only"]
        else f" PROJECTION: omitted={len(omitted_cols)} cols, star={len(star_cols)}, "
        f"explicit={len(explicit_cols)}."
    )

    # --- The `f0_` claim -------------------------------------------------------
    if not eql_agg:
        probe.precondition_met = False
        return probe.inconclusive(
            "The `f<n>_` naming is UNTESTED, not refuted: no EQL aggregation spelling was "
            f"accepted, and the body `groupBy` key returned {aggregated.get('columns')} with "
            f"no aggregation column at all ({aggregated.get('agg_columns')}), so there was "
            "never a column name to inspect. Spellings tried: "
            f"{list(eql_agg_results)}." + projection_note
        )
    probe.precondition_met = True

    agg_cols = [c for c in (eql_agg.get("columns") or []) if _AGG_COL_RE.match(c)]
    probe.observed["f_pattern_columns"] = agg_cols

    if agg_cols:
        return probe.settle(
            CONFIRMED,
            f"The EQL aggregation response carries {agg_cols} -- unaliased aggregation "
            f"columns do come back as `f<n>_`. Full column set: {eql_agg.get('columns')}. Any "
            "parser keying on `count` gets nothing and reads as 'no results'; always alias."
            + projection_note,
        )

    return probe.settle(
        REFUTED,
        f"No `f<n>_` column appeared in an accepted EQL aggregation. It returned "
        f"{eql_agg.get('columns')}. The documented naming does not describe this response "
        "shape -- record the real column names before writing anything that parses "
        "aggregations." + projection_note,
    )


# ---------------------------------------------------------------------------
# Probe 6 -- limit: -1 is rejected
# ---------------------------------------------------------------------------


def probe_limit_negative(client: ExaClient, *, now: datetime) -> Probe:
    """`limit: -1` used to mean unlimited; it now requires a positive integer."""
    probe = Probe(
        probe="P6-limit-negative-one-rejected",
        claim=(
            "The Search API `limit` parameter once accepted -1; it now requires a positive "
            "integer."
        ),
        source="407948 p.338, NGS-4653 (February 2025 section, 2026-08-05 doc)",
        method=(
            "Send limit: -1 over a 1-day window and record the status. Then send limit: 0 "
            "and limit: 1 as controls -- 1 must succeed, or a rejection of -1 says nothing "
            "about the sign."
        ),
        expected=(
            "CONFIRMED when -1 is rejected with a 4xx. REFUTED when it returns 200 -- and "
            "then the row count matters more than the status: a silent coercion to the "
            "3,000 default is worse than an error, and 200-with-zero-rows is worse still."
        ),
        precondition=(
            "limit: 1 must return 200 with at least one row, proving matchable events exist "
            "in the window -- otherwise a zero-row answer to limit: -1 means nothing."
        ),
    )
    start = now - timedelta(days=1)
    control = _call(
        client, probe, "control: limit 1",
        _build_body("", start, now, fields=["activity_type"], limit=1),
    )
    # A second control at a plain positive limit, so the "0 rows" case can be shown to
    # be about the value -1 and not about an empty window.
    control_many = _call(
        client, probe, "control: limit 10",
        _build_body("", start, now, fields=["activity_type"], limit=10),
    )
    negative = _call(
        client, probe, "a: limit -1",
        _build_body("", start, now, fields=["activity_type"], limit=-1),
    )
    zero = _call(
        client, probe, "b: limit 0",
        _build_body("", start, now, fields=["activity_type"], limit=0),
    )
    probe.observed.update(
        status_limit_1=control.get("status"),
        rows_limit_1=_rows(control) if control.get("ok") else None,
        status_limit_10=control_many.get("status"),
        rows_limit_10=_rows(control_many) if control_many.get("ok") else None,
        status_limit_negative_1=negative.get("status"),
        status_limit_0=zero.get("status"),
        rows_limit_negative_1=_rows(negative) if negative.get("ok") else None,
        rows_limit_0=_rows(zero) if zero.get("ok") else None,
        error_limit_negative_1=negative.get("error_message")
        or str(negative.get("error", ""))[:300],
    )

    if not control.get("ok"):
        probe.precondition_met = False
        return probe.inconclusive(
            f"The limit=1 control failed (HTTP {control.get('status')}), so a rejection of "
            "-1 cannot be attributed to the value."
        )
    if not _rows(control_many):
        probe.precondition_met = False
        return probe.inconclusive(
            f"limit=10 returned {_rows(control_many)} rows, so the window has no matchable "
            "events. A zero-row answer to limit=-1 would be about the data, not the value."
        )
    probe.precondition_met = True

    if not negative.get("ok"):
        return probe.settle(
            CONFIRMED,
            f"limit: -1 was rejected with HTTP {negative.get('status')} "
            f"({negative.get('error_code')}) while limit: 1 returned 200. Error: "
            f"{str(negative.get('error_message') or negative.get('error'))[:200]!r}. "
            f"limit: 0 returned {zero.get('status')}.",
        )

    coerced = _rows(negative)

    # 200 with zero rows is the worst of the three outcomes and deserves its own
    # wording. Measured on sademodev22 2026-08-17: limit -1 and limit 0 both returned
    # 200 with 0 rows while limit 10 returned rows over the identical window. Not
    # rejected, not coerced to the default -- an EMPTY result set that a caller reads
    # as "no matching events". This is the exact failure shape the defect register
    # exists for, and it is a defect candidate, not merely undocumented behavior.
    if coerced == 0:
        return probe.settle(
            REFUTED,
            f"WORSE THAN DOCUMENTED -- limit: -1 returned HTTP 200 with ZERO rows while "
            f"limit: 10 returned {_rows(control_many)} rows over the identical window "
            f"(limit: 0 returned {zero.get('status')} / {_rows(zero) if zero.get('ok') else None}"
            " rows). It is neither rejected as documented nor coerced to the default: the "
            "caller gets an empty result set indistinguishable from 'no matching events'. "
            "Any code passing a computed limit must reject non-positive values BEFORE the "
            "call -- the API will not. Open a defect-register entry for this.",
        )

    return probe.settle(
        REFUTED,
        f"limit: -1 returned HTTP 200 with {coerced} rows"
        + (
            " -- exactly the documented 3,000 default, so it is being silently coerced "
            "rather than rejected. That is worse than an error: a caller asking for "
            "everything gets a truncated set that looks complete."
            if coerced == _DOCUMENTED_DEFAULT_LIMIT
            else ". The documented rejection is not happening on this tenant."
        ),
    )


# ---------------------------------------------------------------------------
# Probe 7 -- `null` vs `"null"`
# ---------------------------------------------------------------------------


def probe_null_quoting(client: ExaClient, *, now: datetime, lookback_days: int = 7) -> Probe:
    """`field: null` tests emptiness; `field: "null"` matches the literal string."""
    probe = Probe(
        probe="P7-null-vs-quoted-null",
        claim=(
            'Quoting changes the meaning: `field: null` matches EMPTY values, '
            '`field: "null"` matches the literal string "null". Same query shape, '
            "different results, no warning."
        ),
        source="245604 p.246-253 region (2026-07-14); UI Empty (null) checkbox p.31",
        method=(
            "Find a field that is null on some rows and populated on others in an "
            "unfiltered sample, then compare row counts for `field:null`, `field:\"null\"` "
            "and `NOT field:*` over the same window."
        ),
        expected=(
            "CONFIRMED when the quoted and unquoted forms return different counts. REFUTED "
            "when they are identical -- which would mean quoting is ignored and the UI "
            "checkbox and hand-typed form agree."
        ),
        precondition=(
            "The sample must contain a field with BOTH null and non-null values, otherwise "
            "an emptiness test cannot differ from a string match."
        ),
    )
    start, end = now - timedelta(days=lookback_days), now

    sample = _call(
        client, probe, "precondition: unfiltered sample",
        _build_body("", start, end, fields=list(_NULLABLE_CANDIDATES), limit=200),
    )
    if not sample.get("ok") or not _rows(sample):
        probe.precondition_met = False
        return probe.inconclusive(
            f"The unfiltered sample returned nothing (HTTP {sample.get('status')})."
        )

    # Re-read null-ness per candidate field with one extra count-only pass each,
    # rather than keeping 200 rows of tenant data in the artifact.
    usable: list[str] = []
    mixedness: dict[str, dict[str, int]] = {}
    for candidate in _NULLABLE_CANDIDATES:
        counts = _call(
            client, probe, f"precondition: null-ness of {candidate}",
            _build_body("", start, end, fields=[candidate], limit=200),
            count_values_of=candidate,
        )
        if not counts.get("ok"):
            continue
        values = counts.get("value_counts", {})
        nulls = values.get("<null>", 0)
        populated = sum(v for k, v in values.items() if k != "<null>")
        mixedness[candidate] = {"null": nulls, "populated": populated}
        if nulls and populated:
            usable.append(candidate)
    probe.observed["field_nullness"] = mixedness
    probe.observed["usable_fields"] = usable

    if not usable:
        probe.precondition_met = False
        return probe.inconclusive(
            f"No sampled field had both null and non-null values ({mixedness}). An "
            "emptiness test cannot be distinguished from a string match here."
        )
    probe.precondition_met = True

    # Try candidates in order. A type rejection on the quoted form is a dead end for
    # this claim -- it proves the field is typed, not that quoting changes matching --
    # so move to the next field rather than settling on it.
    type_rejections: dict[str, str] = {}
    attempts: list[str] = []
    for chosen in usable:
        attempts.append(chosen)
        unquoted = _call(
            client, probe, f"a: {chosen}:null (unquoted)",
            _build_body(f"{chosen}:null", start, end, fields=[chosen], limit=1000),
            count_values_of=chosen,
        )
        quoted = _call(
            client, probe, f'b: {chosen}:"null" (quoted)',
            _build_body(f'{chosen}:"null"', start, end, fields=[chosen], limit=1000),
            count_values_of=chosen,
        )
        negated = _call(
            client, probe, f"c: NOT {chosen}:* (control)",
            _build_body(f"NOT {chosen}:*", start, end, fields=[chosen], limit=1000),
            count_values_of=chosen,
        )

        probe.observed.update(
            field_used=chosen,
            field_used_is_typed=chosen in _TYPED_CANDIDATES,
            fields_attempted=attempts,
            rows_unquoted_null=_rows(unquoted) if unquoted.get("ok") else None,
            rows_quoted_null=_rows(quoted) if quoted.get("ok") else None,
            rows_not_wildcard=_rows(negated) if negated.get("ok") else None,
            status_unquoted=unquoted.get("status"),
            status_quoted=quoted.get("status"),
            status_negated=negated.get("status"),
            values_unquoted=unquoted.get("value_counts"),
            values_quoted=quoted.get("value_counts"),
            error_quoted=quoted.get("error_message"),
        )

        is_type_error = "incompatible for type" in _error_text(quoted)
        if is_type_error:
            type_rejections[chosen] = str(quoted.get("error_message"))[:200]
            probe.observed["type_rejections"] = type_rejections
            continue

        if not unquoted.get("ok"):
            return probe.inconclusive(
                f"The unquoted form was rejected on {chosen!r} (HTTP "
                f"{unquoted.get('status')}, {unquoted.get('error_code')}): "
                f"{str(unquoted.get('error_message'))[:200]!r}. The emptiness test itself is "
                "unavailable, so the comparison cannot be made."
            )

        if not quoted.get("ok"):
            # A 400 for one spelling and a 200 for the other IS a difference in meaning,
            # and the strongest form of it -- one query is not merely narrower, it is
            # invalid. Settle it, but say what the mechanism was.
            return probe.settle(
                CONFIRMED,
                f"On {chosen!r} the two spellings are not interchangeable in the strongest "
                f"way: unquoted `null` returned 200 with {_rows(unquoted)} rows while quoted "
                f'`"null"` was REJECTED (HTTP {quoted.get("status")}, '
                f"{quoted.get('error_code')}): "
                f"{str(quoted.get('error_message'))[:200]!r}. `NOT {chosen}:*` returned "
                f"{_rows(negated)} as a cross-check. Note the MECHANISM is a rejection, not "
                "the documented difference in matching -- the claim that quoting changes "
                "meaning holds, but 'matches the literal string \"null\"' is not what was "
                "demonstrated here.",
            )

        if _rows(unquoted) != _rows(quoted):
            return probe.settle(
                CONFIRMED,
                f"On {chosen!r}: unquoted `null` returned {_rows(unquoted)} rows, quoted "
                f'`"null"` returned {_rows(quoted)}. Quoting changes the meaning, exactly as '
                f"documented. `NOT {chosen}:*` returned {_rows(negated)} as a cross-check.",
            )

        return probe.settle(
            REFUTED,
            f"Both forms returned {_rows(unquoted)} rows on {chosen!r}, so quoting made no "
            f"difference here (`NOT {chosen}:*` returned {_rows(negated)}). Either the tenant "
            "has no literal-'null' strings to separate the two, or the distinction is not "
            "enforced -- check the value counts in observed before trusting either reading.",
        )

    probe.precondition_met = False
    return probe.inconclusive(
        f"Every usable field was type-rejected on the quoted form ({type_rejections}). That "
        "is a real finding -- `field:\"null\"` against a typed field is refused outright "
        "rather than treated as a string -- but it does not test whether quoting changes "
        "MATCHING semantics, which needs a string-typed field carrying both null and "
        f"non-null values. Fields attempted: {attempts}."
    )


# ---------------------------------------------------------------------------
# Probe 8 -- pipe quota and pipe date range (OPT-IN: this SPENDS quota)
# ---------------------------------------------------------------------------


def probe_pipe_quota(
    client: ExaClient,
    *,
    now: datetime,
    pipe_eql: str = 'SELECT activity_type WHERE activity_type:"authentication" | LIMIT 5',
) -> Probe:
    """Pipe queries: 1,000/month enforced, 7-day maximum range, 5 pipes per query.

    OPT-IN ONLY. Every call here consumes from a quota that is shared across the
    whole deployment and, as far as anything measured so far shows, is not exposed
    by any endpoint. Two calls per run, and never on a schedule.
    """
    probe = Probe(
        probe="P8-pipe-quota-and-range",
        claim=(
            "Pipe queries are capped at 1,000 per month (enforced, shared deployment-wide) "
            "and 7 days of date range, with 5 pipe operators per query."
        ),
        source="245604 p.58 (2026-07-14)",
        method=(
            "Two calls only, because each one SPENDS quota: the same pipe query at 6 days "
            "and at 8 days. Record every key of both responses, to see whether a remaining "
            "quota counter is exposed anywhere."
        ),
        expected=(
            "CONFIRMED when the 8-day pipe query is rejected and the 6-day one is not. "
            "REFUTED when 8 days is accepted."
        ),
        precondition="The 6-day pipe query must be accepted, or pipes are unavailable here.",
    )
    probe.observed["pipe_eql"] = pipe_eql
    probe.observed["quota_cost_of_this_probe"] = "2 pipe queries"

    inside = _call(
        client, probe, "a: pipe query, 6 days",
        _build_body(pipe_eql, now - timedelta(days=6), now, fields=["activity_type"], limit=10),
    )
    outside = _call(
        client, probe, "b: pipe query, 8 days",
        _build_body(pipe_eql, now - timedelta(days=8), now, fields=["activity_type"], limit=10),
    )
    probe.observed.update(
        status_6d=inside.get("status"),
        status_8d=outside.get("status"),
        rows_6d=_rows(inside) if inside.get("ok") else None,
        rows_8d=_rows(outside) if outside.get("ok") else None,
        response_keys_6d=inside.get("response_keys"),
        response_keys_8d=outside.get("response_keys"),
        quota_counter_exposed=any(
            "quota" in key.lower() or "remaining" in key.lower()
            for key in (inside.get("response_keys") or [])
        ),
    )

    if not inside.get("ok"):
        probe.precondition_met = False
        return probe.inconclusive(
            f"The 6-day pipe query was rejected (HTTP {inside.get('status')}): "
            f"{str(inside.get('error'))[:200]!r}. Either the pipe syntax in --pipe-eql is "
            "wrong for this API surface, or pipes are not available on this license. Fix "
            "the syntax before spending more quota."
        )
    probe.precondition_met = True

    if not outside.get("ok"):
        return probe.settle(
            CONFIRMED,
            f"The 8-day pipe query was rejected with HTTP {outside.get('status')} while 6 "
            f"days returned {_rows(inside)} rows. Error: "
            f"{str(outside.get('error'))[:200]!r}. Quota counter exposed in the response: "
            f"{probe.observed['quota_counter_exposed']}.",
        )

    return probe.settle(
        REFUTED,
        f"The 8-day pipe query returned 200 with {_rows(outside)} rows, so the documented "
        "7-day pipe range is not enforced here. The quota itself is NOT tested by this "
        "probe -- proving a 1,000/month limit means spending 1,000 queries, which is not a "
        f"reasonable thing to do. Quota counter exposed in the response: "
        f"{probe.observed['quota_counter_exposed']}.",
    )


# ---------------------------------------------------------------------------
# Battery
# ---------------------------------------------------------------------------

# Names accepted by --probe, in run order. P0 first: if `filter` is not filtering,
# every probe after it is measuring something other than what it thinks.
PROBE_NAMES = [
    "query-vs-filter",
    "limit-default",
    "context-window",
    "aggregation-window",
    "time-range",
    "result-shape",
    "limit-negative",
    "null-quoting",
]
PIPE_PROBE_NAME = "pipe-quota"


def run_verification(
    client: ExaClient,
    *,
    lookback_days: int = 7,
    table_name: str = "Public AI Domains and Risk",
    table_id: str | None = None,
    table_column: str | None = None,
    event_field: str = "web_domain",
    include_pipe_probes: bool = False,
    pipe_eql: str | None = None,
    only: list[str] | None = None,
    on_progress: Any = None,
) -> dict[str, Any]:
    """Run the probe battery and return a full artifact dict.

    `now` is pinned once, here, and every window in every probe derives from it.
    That is not tidiness: probe 3 compares an 8-day aggregation against two 4-day
    slices, and if each call computed its own `now` the slices would not tile the
    whole window and ordinary clock drift would read as silent truncation.
    """
    now = datetime.now(UTC)
    wanted = set(only) if only else set(PROBE_NAMES)

    plan: list[tuple[str, Any]] = [
        ("query-vs-filter", lambda: probe_query_vs_filter(
            client, now=now, lookback_days=lookback_days)),
        ("limit-default", lambda: probe_limit_default(
            client, now=now, lookback_days=lookback_days)),
        ("context-window", lambda: probe_context_table_window(
            client, now=now, table_name=table_name, table_id=table_id,
            table_column=table_column, event_field=event_field)),
        ("aggregation-window", lambda: probe_aggregation_window(client, now=now)),
        ("time-range", lambda: probe_time_range_limit(client, now=now)),
        ("result-shape", lambda: probe_result_shape(client, now=now)),
        ("limit-negative", lambda: probe_limit_negative(client, now=now)),
        ("null-quoting", lambda: probe_null_quoting(
            client, now=now, lookback_days=lookback_days)),
    ]
    if include_pipe_probes:
        pipe_kwargs = {"pipe_eql": pipe_eql} if pipe_eql else {}
        plan.append((
            PIPE_PROBE_NAME,
            lambda: probe_pipe_quota(client, now=now, **pipe_kwargs),
        ))
        wanted.add(PIPE_PROBE_NAME)

    selected = [(name, fn) for name, fn in plan if name in wanted]
    probes: list[dict[str, Any]] = []
    for index, (name, fn) in enumerate(selected, 1):
        if on_progress:
            on_progress(index, len(selected), name)
        try:
            probes.append(fn().to_dict())
        except Exception as exc:  # a broken probe must not lose the others
            probes.append(
                Probe(
                    probe=name,
                    claim="(probe raised before it could settle)",
                    source="",
                    verdict=INCONCLUSIVE,
                    reason=f"Probe raised {type(exc).__name__}: {exc}",
                ).to_dict()
            )

    return {
        "tenant": client.tenant or "unknown",
        "base_url": getattr(client, "base_url", ""),
        "run_at": now.isoformat(),
        "now_pinned": _ts(now),
        "lookback_days": lookback_days,
        "include_pipe_probes": include_pipe_probes,
        "probes": probes,
        "summary": summarize(probes),
    }


def summarize(probes: list[dict[str, Any]]) -> dict[str, int]:
    """Count verdicts. INCONCLUSIVE is a first-class outcome, not a failure."""
    counts = Counter(p.get("verdict", INCONCLUSIVE) for p in probes)
    return {
        "confirmed": counts.get(CONFIRMED, 0),
        "refuted": counts.get(REFUTED, 0),
        "inconclusive": counts.get(INCONCLUSIVE, 0),
        "total": len(probes),
    }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def save_verification(
    artifact: dict[str, Any],
    tenant: str,
    *,
    output_path: Path | None = None,
) -> Path:
    """Save a run to ~/.exa/search-verify/{tenant}-{timestamp}.json."""
    _VERIFY_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    path = output_path or (_VERIFY_DIR / f"{tenant}-{stamp}.json")
    path.write_text(json.dumps(artifact, indent=2, default=str), encoding="utf-8")
    return path


def load_last_verification(tenant: str) -> dict[str, Any] | None:
    """Load the most recent verification artifact for a tenant."""
    if not _VERIFY_DIR.exists():
        return None
    files = sorted(_VERIFY_DIR.glob(f"{tenant}-*.json"), reverse=True)
    if not files:
        return None
    return json.loads(files[0].read_text(encoding="utf-8"))


def vault_rows(artifact: dict[str, Any]) -> str:
    """Render a run as the markdown table rows the vault test section expects.

    The vault section is the durable record; the JSON artifact is the evidence
    behind it. This exists so the two cannot drift apart through retyping.
    """
    tenant = artifact.get("tenant", "unknown")
    date = str(artifact.get("run_at", ""))[:10]
    lines = [
        "| Probe | Claim | Verdict | Tenant | Date | Why |",
        "|---|---|---|---|---|---|",
    ]
    for probe in artifact.get("probes", []):
        claim = " ".join(str(probe.get("claim", "")).split())
        reason = " ".join(str(probe.get("reason", "")).split())
        if len(claim) > 90:
            claim = claim[:87] + "..."
        lines.append(
            f"| `{probe.get('probe','')}` | {claim} | **{probe.get('verdict','')}** | "
            f"{tenant} | {date} | {reason} |"
        )
    return "\n".join(lines)

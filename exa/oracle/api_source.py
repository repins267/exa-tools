"""Build the Field Oracle live from the Log Stream Public API.

Instead of a manually-exported ``Parser_Update.zip``, pull the tenant's parsers
straight from ``GET /log-stream/v1/parsers`` (and event builders from
``GET /log-stream/v1/event-builders``) and build the Oracle from what the tenant
is running right now. Self-updating, no export step, always current.

The API returns each parser's ``fields`` as a list of extraction strings — the
same forms the export/pC builds parse (capture groups ``({field}…)`` and explicit
``exa_json_path=…,exa_field_name=…`` mappings) — so the resulting Oracle is
byte-compatible with the other builders. Because the API commonly carries the
explicit mappings, its ``raw_to_cim2`` is typically higher-confidence than the
regex-only export.

All requests go through ExaClient (never raw HTTP), so auth, retries, and token
refresh are handled the same as every other call.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from exa.oracle.export_builder import build_oracle_from_records

if TYPE_CHECKING:
    from exa.client import ExaClient

_PARSERS_PATH = "/log-stream/v1/parsers"
_EVENT_BUILDERS_PATH = "/log-stream/v1/event-builders"


def _as_list(resp: Any) -> list[dict]:
    """Normalise an ExaClient response (httpx.Response or already-parsed) to a list."""
    data = resp.json() if hasattr(resp, "json") else resp
    if isinstance(data, dict):
        # tolerate a wrapped payload, e.g. {"parsers": [...]} / {"items": [...]}
        for key in ("parsers", "items", "data", "results"):
            if isinstance(data.get(key), list):
                return data[key]
        return []
    return data if isinstance(data, list) else []


def fetch_parsers(client: ExaClient, state: str | None = "Enabled") -> list[dict]:
    """Every parser the tenant runs, from the Log Stream Public API."""
    path = f"{_PARSERS_PATH}?state={state}" if state else _PARSERS_PATH
    return _as_list(client.get(path))


def fetch_event_builders(client: ExaClient) -> list[dict]:
    """Every event builder the tenant runs (activity-type/event-type source)."""
    return _as_list(client.get(_EVENT_BUILDERS_PATH))


def _parser_records(parsers: list[dict]):
    """Yield (name, vendor, product, fields_text) for the shared aggregation core."""
    for p in parsers:
        if not isinstance(p, dict):
            continue
        name = p.get("parserName") or ""
        vendor = p.get("vendor") or ""
        product = p.get("product") or ""
        fields = p.get("fields")
        text = "\n".join(fields) if isinstance(fields, list) else (fields or "")
        yield name, vendor, product, text


def build_oracle_from_api(client: ExaClient, *, state: str | None = "Enabled") -> dict[str, Any]:
    """Build the Field Oracle from the tenant's live parsers via the API.

    Same schema as the export/pC builds. ``state`` filters the parser set
    (default ``Enabled`` — what is actually parsing on the tenant).
    """
    parsers = fetch_parsers(client, state=state)
    oracle = build_oracle_from_records(
        _parser_records(parsers),
        source="log-stream-api",
        note="from /log-stream/v1/parsers (explicit exa_json_path mappings when present)",
    )
    # Record the event-builder count as provenance (activity_type is still derived
    # from parser names for drop-in parity; event builders are captured for future
    # enrichment and as a freshness signal).
    try:
        oracle["stats"]["event_builders"] = len(fetch_event_builders(client))
    except Exception:  # noqa: BLE001 - event builders are provenance, not required
        pass
    oracle["stats"]["parser_state"] = state or "all"
    return oracle

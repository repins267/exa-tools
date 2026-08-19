"""Parser health — classify parsing errors and recommend fixes.

The classification taxonomy, recommendations and offending-field extraction are
ported from the ExaSight tenant-config collector. Pure functions here (no API);
the collector that queries the SIEM and aggregates lives in collect_parser_health.

Queries used by the collector:
  parsed:true   count(id)     -> parsed volume
  parsed:false  count(id)     -> unparsed volume
  error_detail present         -> per-error records (error_detail, msg_type, src_vendor)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

# High-level operational categories a parser error falls into.
PARSER_ERROR_TYPES = (
    "Date/Time Parsing",
    "Regex / Extraction",
    "Type Conversion",
    "Field Validation",
    "JSON Parsing",
    "Other",
)

_RECOMMENDATIONS = {
    "Date/Time Parsing": "Review raw log time extraction and accepted time formats for the "
    "affected parser. Normalize source timezone and timestamp pattern.",
    "Regex / Extraction": "Review parser regex capture groups, named group reuse, and "
    "extraction boundaries. Validate sample raw logs with spaces and optional fields.",
    "Type Conversion": "Review CIM field type mapping. Ensure numeric, boolean, IP, and list "
    "fields are extracted as expected before analytics processing.",
    "Field Validation": "Review CIM validation failures such as email or IP fields. Confirm "
    "the field contains only normalized values expected by Exabeam.",
    "JSON Parsing": "Review JSON path expressions and null or primitive array handling. Add "
    "guards for missing objects and inconsistent structures.",
    "Other": "Review parser error_detail and associated msg_type for unsupported or uncommon "
    "parser failure behavior.",
}


def classify_parser_error(reason: str, message: str = "", field_name: str = "") -> str:
    """Map a parser error (reason + message + field) to a PARSER_ERROR_TYPES bucket."""
    reason_u = (reason or "").strip().upper()
    combined = f"{reason} {message} {field_name}".lower()
    if reason_u == "DATETIME_FIELD_PARSING" or any(
        k in combined for k in ("datetime", "date", "time format")
    ):
        return "Date/Time Parsing"
    if reason_u == "REGEX_EXTRACTION_ERROR" or any(
        k in combined for k in ("regex", "pattern", "group redeclaration", "extract")
    ):
        return "Regex / Extraction"
    if reason_u == "DATA_TYPE_MISMATCH" or any(
        k in combined for k in ("type mismatch", "cimtype", "number", "integer", "boolean")
    ):
        return "Type Conversion"
    if reason_u == "FIELD_DATA_VALIDATION" or any(
        k in combined for k in ("validation", "email", "ipv4", "ipv6")
    ):
        return "Field Validation"
    if reason_u == "JSON_FIELD_PARSING_ERROR" or any(
        k in combined for k in ("json", "jsonpath", "current context")
    ):
        return "JSON Parsing"
    return "Other"


def parser_error_recommendation(error_type: str) -> str:
    """Actionable remediation for a parser error category."""
    return _RECOMMENDATIONS.get(error_type, _RECOMMENDATIONS["Other"])


def extract_offending_field(error: dict[str, Any]) -> str:
    """Best-effort extraction of the field a parser error is about."""
    field_v = str(error.get("field") or "").strip()
    if field_v:
        return field_v
    message = str(error.get("msg") or error.get("message") or "").strip()
    pattern = str(error.get("pattern") or "").strip()
    for rx in (
        r"Datetime field\s+([^=\s]+)=",
        r"group redeclaration\s+([A-Za-z0-9_\-.]+)",
        r"field\s+([A-Za-z0-9_\-.]+)",
    ):
        m = re.search(rx, message, flags=re.I)
        if m:
            return m.group(1)
    m = re.search(r"\(\{([A-Za-z0-9_\-.]+)\}", pattern)
    if m:
        return m.group(1)
    return "Unknown"


@dataclass
class ParserErrorGroup:
    """Aggregated parser errors sharing a category."""

    category: str
    count: int = 0
    recommendation: str = ""
    top_fields: list[tuple[str, int]] = field(default_factory=list)
    top_sources: list[tuple[str, int]] = field(default_factory=list)


@dataclass
class ParserHealth:
    """Parser-health snapshot for a tenant."""

    tenant: str | None = None
    lookback_days: int = 7
    parsed: int = 0
    unparsed: int = 0
    errors_examined: int = 0
    groups: list[ParserErrorGroup] = field(default_factory=list)
    by_source: list[tuple[str, int]] = field(default_factory=list)
    truncated: bool = False
    note: str = ""

    @property
    def total(self) -> int:
        return self.parsed + self.unparsed

    @property
    def unparsed_pct(self) -> float:
        return round(100 * self.unparsed / self.total, 2) if self.total else 0.0


def _iter_errors(error_detail: Any):
    """Yield each {reason, field, msg, pattern} dict from an error_detail value.

    error_detail is a JSON string (or already-parsed value) shaped like
    [{"stage": "Parsing", "errors": [{"reason": ..., "field": ..., ...}]}].
    """
    import json

    if not error_detail:
        return
    data = error_detail
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            return
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return
    for stage in data:
        if isinstance(stage, dict):
            for e in stage.get("errors") or []:
                if isinstance(e, dict):
                    yield e


def collect_parser_health(
    client: "ExaClient", *, lookback_days: int = 7, error_limit: int = 5000
) -> ParserHealth:
    """Query parsed/unparsed counts and parser errors, classify and aggregate.

    Read-only. parsed vs unparsed comes from a grouped count(id); errors come
    from `NOT error_detail:null` (up to error_limit records). msg_type carries
    the parser name, so it is used as the source when src_vendor is absent.
    """
    from collections import Counter, defaultdict

    from exa.search.events import search_events

    health = ParserHealth(
        tenant=getattr(client, "tenant", None), lookback_days=lookback_days
    )

    # parsed vs unparsed
    try:
        rows = search_events(
            client, "", fields=["parsed", "count(id)"], group_by=["parsed"],
            lookback_days=lookback_days, limit=100,
        )
        for r in rows or []:
            n = int(r.get("f0_") or r.get("count(id)") or 0)
            pv = r.get("parsed")
            if pv is True or str(pv).lower() in ("true", "yes"):
                health.parsed = n
            elif pv is False or str(pv).lower() in ("false", "no"):
                health.unparsed = n
    except Exception as exc:
        health.note = f"parsed/unparsed count unavailable: {exc}"

    # parser errors
    cat_counts: Counter = Counter()
    cat_fields: dict = defaultdict(Counter)
    cat_sources: dict = defaultdict(Counter)
    all_sources: Counter = Counter()
    try:
        erows = search_events(
            client, "NOT error_detail:null",
            fields=["error_detail", "msg_type", "src_vendor"],
            lookback_days=lookback_days, limit=error_limit,
        )
        health.truncated = isinstance(erows, list) and len(erows) >= error_limit
        for row in erows or []:
            source = row.get("src_vendor") or row.get("msg_type") or "Unknown"
            for err in _iter_errors(row.get("error_detail")):
                health.errors_examined += 1
                reason = str(err.get("reason") or "")
                fld = str(err.get("field") or "")
                msg = str(err.get("msg") or err.get("message") or "")
                cat = classify_parser_error(reason, msg, fld)
                cat_counts[cat] += 1
                off = fld or extract_offending_field(
                    {"msg": msg, "pattern": err.get("pattern", "")}
                )
                cat_fields[cat][off] += 1
                cat_sources[cat][source] += 1
                all_sources[source] += 1
    except Exception as exc:
        health.note = (health.note + " | " if health.note else "") + f"error query failed: {exc}"

    for cat, cnt in cat_counts.most_common():
        health.groups.append(ParserErrorGroup(
            category=cat, count=cnt,
            recommendation=parser_error_recommendation(cat),
            top_fields=cat_fields[cat].most_common(5),
            top_sources=cat_sources[cat].most_common(5),
        ))
    health.by_source = all_sources.most_common(10)
    return health


def render_parser_health(health: ParserHealth) -> str:
    """Render a ParserHealth snapshot as a branded self-contained HTML report."""
    from exa.report import coverage_bar, data_table, page, panel, stat_card

    up = health.unparsed_pct
    up_status = "good" if up < 1 else "warn" if up < 5 else "bad"
    cards = "".join([
        stat_card("Tenant", health.tenant or "—", "", f"last {health.lookback_days}d"),
        stat_card("Unparsed", f"{up}%", up_status, f"{health.unparsed:,} of {health.total:,} logs"),
        stat_card("Parsed", f"{health.parsed:,}", "good"),
        stat_card("Error categories", len([g for g in health.groups if g.count]), "warn" if health.groups else "good"),
        stat_card("Errors examined", f"{health.errors_examined:,}", "", "sampled" if health.truncated else "complete"),
        stat_card("Top failing parser", (health.by_source[0][0] if health.by_source else "—"), "",
                  f"{health.by_source[0][1]:,} errors" if health.by_source else ""),
    ])
    unparsed_panel = panel(
        "Parsed vs Unparsed",
        coverage_bar(100 - up) +
        f'<div class="footer-note">{health.parsed:,} parsed, {health.unparsed:,} unparsed '
        f'({up}%) in the last {health.lookback_days} days. Unparsed logs carry no fields and '
        'are invisible to analytics — chase the parser, not the volume.</div>',
        "Unparsed volume is the headline.",
    )
    cat_rows = [{
        "Category": g.category, "Errors": g.count,
        "Top field": (g.top_fields[0][0] if g.top_fields else "—"),
        "Top parser": (g.top_sources[0][0] if g.top_sources else "—"),
        "Recommendation": g.recommendation,
    } for g in health.groups]
    cat_panel = panel(
        f"Parser errors by category ({len(cat_rows)})",
        data_table(cat_rows, "tblCats") if cat_rows
        else '<div class="footer-note">No parser errors found in the window.</div>',
        "Classified from error_detail, with a fix per category.",
    )
    src_rows = [{"Parser / source": s, "Errors": n} for s, n in health.by_source]
    src_panel = panel(
        "Top failing parsers / sources",
        data_table(src_rows, "tblSrc") if src_rows
        else '<div class="footer-note">None.</div>',
        "msg_type identifies the parser; fix these first.",
    )
    meta = (f"<div>{health.tenant or '—'}</div><div>last {health.lookback_days}d</div>"
            "<div>exa-tools · read-only</div>")
    return page(
        "exa-tools · Parser Health", f"Parsing & unparsed analysis · {health.tenant or ''}",
        cards, unparsed_panel + cat_panel + src_panel, meta, initial_theme="dark",
    )

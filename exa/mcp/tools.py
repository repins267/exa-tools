"""MCP tool definitions and dispatch for exa-tools.

Each tool wraps an existing exa-tools function. Read tools are marked safe for
autonomous use; write tools include an approval warning in their description so
Claude knows to request human confirmation before executing.
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import TYPE_CHECKING, Any

from mcp.types import TextContent, Tool

if TYPE_CHECKING:
    from exa.client import ExaClient


# Claude Desktop caps a single tool result at 1 MB and the stdio client's read
# buffer at 32 MB; a raw aillm table dump blows past both and kills the transport
# (ReadBuffer exceeded -> Server disconnected). Bound every result: keep the
# computed summary fields (overlap, status, counts are scalars) and cap long
# arrays to the first N with an explicit _omitted count, so a verdict still gets
# through and the model can see the list was truncated.
_MAX_RESULT_BYTES = 800_000
_MAX_LIST_ITEMS = 50


def _truncate_lists(obj: Any, max_items: int) -> Any:
    """Recursively cap any list longer than max_items, tagging what was dropped."""
    if isinstance(obj, dict):
        return {k: _truncate_lists(v, max_items) for k, v in obj.items()}
    if isinstance(obj, list):
        if len(obj) > max_items:
            head = [_truncate_lists(x, max_items) for x in obj[:max_items]]
            head.append(
                {"_truncated": True, "_omitted": len(obj) - max_items, "_total": len(obj)}
            )
            return head
        return [_truncate_lists(x, max_items) for x in obj]
    return obj


def _ok(data: Any) -> list[TextContent]:
    from exa.mcp.guardrails import scrub_result

    # Canonicalize telemetry the model is about to read: strip invisible smuggling
    # (zero-width, bidi overrides, tag chars) and NFC-normalize. "Do no harm" — a
    # legitimate value is left intact; only obvious injection code points are removed.
    data = scrub_result(data)
    text = json.dumps(data, default=str)
    if len(text.encode("utf-8")) > _MAX_RESULT_BYTES:
        for cap in (_MAX_LIST_ITEMS, 10, 0):
            text = json.dumps(_truncate_lists(data, cap), default=str)
            if len(text.encode("utf-8")) <= _MAX_RESULT_BYTES:
                break
        else:
            text = json.dumps(
                {
                    "error": "Result exceeded the size limit even after truncation. "
                    "Narrow the request (shorter lookback, a name/status filter, or a "
                    "single table) and retry.",
                    "_size_capped": True,
                }
            )
    return [TextContent(type="text", text=text)]


def _err(message: str) -> list[TextContent]:
    # Canonicalize the error text too: an exception can carry a raw tenant response
    # body, which must not reach the model unfiltered (PRAX-2026-08-19-003).
    from exa.mcp.guardrails import scrub_result

    return [TextContent(type="text", text=json.dumps({"error": scrub_result(str(message))}))]


def _ok_obj(data: Any) -> list[TextContent]:
    """Serialise dataclass results before handing them to _ok.

    _ok uses json.dumps(default=str). A dataclass is not JSON-serialisable, so
    default=str turns the whole report into its repr -- one long useless string
    instead of a structured result, with no error raised. Every aillm report
    (SourceInventory, RuleReport, RiskReport, GapReport, TableValidation) is a
    dataclass, so they must be converted rather than stringified.
    """
    if is_dataclass(data) and not isinstance(data, type):
        return _ok(asdict(data))
    if isinstance(data, list) and data and is_dataclass(data[0]):
        return _ok([asdict(d) for d in data])
    return _ok(data)


def _safe_seg(s: Any) -> str:
    """Filesystem-safe path segment."""
    seg = "".join(c if (c.isalnum() or c in "-_.") else "-" for c in str(s)).strip("-. ")
    return seg or "x"


def _reports_root():
    """The single, stable containment root for all rendered reports.

    Defaults to ``<cwd>/reports`` (on Claude Desktop the CWD is the app dir), but
    ``EXA_REPORTS_DIR`` pins it to a fixed absolute location so the root does not move
    with the process working directory (PRAX-2026-08-20-009). Resolved to an absolute
    path so every caller shares the identical boundary.
    """
    import os
    from pathlib import Path

    d = os.environ.get("EXA_REPORTS_DIR", "").strip()
    return (Path(d) if d else Path("reports")).resolve()


def _report_path(client: Any, filename: str):
    """Default save path for a rendered report: {reports-root}/{kind}/{tenant}/{filename}.

    Sorts output by tenant kind (demo/customer, or 'untagged') and tenant nickname so
    reports stay organized per account. Intermediate directories are created here, so a
    brand-new tenant/kind folder never causes a save to fail. Root is `_reports_root()`
    (CWD/reports by default, or EXA_REPORTS_DIR). Pass an explicit output_path to override.
    """
    tenant = getattr(client, "tenant", None) or "tenant"
    kind = "untagged"
    try:
        from exa.config import list_tenants

        kind = (list_tenants().get(tenant, {}) or {}).get("kind") or "untagged"
    except Exception:
        pass
    p = _reports_root() / _safe_seg(kind) / _safe_seg(tenant) / filename
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _contained_output_path(candidate: str):
    """Resolve a caller-supplied output_path UNDER reports/, refusing any escape.

    A model-supplied output_path is untrusted: absolute paths, `..` traversal, or a
    drive-letter root would let a rendered (model-influenced) HTML file be written
    anywhere on the host (PRAX-2026-08-19-001). Joining under the reports/ root and
    checking is_relative_to rejects all three in one test.
    """
    base = _reports_root()
    target = (base / str(candidate)).resolve()
    if not target.is_relative_to(base):
        raise ValueError(f"output_path must stay under the reports root (got {candidate!r})")
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


# The tools that mutate live tenant data. In read-only mode these are neither
# advertised (see visible_tools) nor dispatched (see dispatch_tool) -- a HARD
# gate, unlike the in-prompt SOFT gate carried in each tool's description.
WRITE_TOOLS: frozenset[str] = frozenset(
    {"create_case", "update_case", "update_alert", "add_case_note"}
)


TOOL_DEFS: list[Tool] = [
    Tool(
        name="search_alerts",
        description=(
            "Search Threat Center alerts by EQL filter. Safe for autonomous use. "
            "Returns alerts sorted by risk score descending."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "description": 'EQL expression e.g. \'priority:"HIGH"\' or \'NOT stage:"CLOSED"\'',
                    "default": "",
                },
                "lookback_days": {
                    "type": "integer",
                    "description": "Days to look back [default: 7]",
                    "default": 7,
                },
                "limit": {
                    "type": "integer",
                    "description": "Max alerts to return [default: 50]",
                    "default": 50,
                },
            },
        },
    ),
    Tool(
        name="get_alert",
        description="Get details for a specific alert by UUID. Safe for autonomous use.",
        inputSchema={
            "type": "object",
            "required": ["alert_id"],
            "properties": {
                "alert_id": {"type": "string", "description": "Alert UUID"},
            },
        },
    ),
    Tool(
        name="search_cases",
        description=(
            "Search Threat Center cases by EQL filter. Safe for autonomous use. "
            "Returns cases sorted by creation time descending."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "description": 'EQL expression e.g. \'stage:"OPEN"\' or \'priority:"HIGH"\'',
                    "default": "",
                },
                "lookback_days": {
                    "type": "integer",
                    "description": "Days to look back [default: 7]",
                    "default": 7,
                },
                "limit": {
                    "type": "integer",
                    "description": "Max cases to return [default: 50]",
                    "default": 50,
                },
            },
        },
    ),
    Tool(
        name="get_case",
        description="Get full details for a specific case by UUID. Safe for autonomous use.",
        inputSchema={
            "type": "object",
            "required": ["case_id"],
            "properties": {
                "case_id": {"type": "string", "description": "Case UUID"},
            },
        },
    ),
    Tool(
        name="search_events",
        description=(
            "Search raw security events using EQL. Safe for autonomous use. "
            "Use for investigation pivots — e.g. search events for a user/host/IP. AGGREGATE with group_by plus a count in fields (e.g. fields=[vendor,product,count(id)], group_by=[vendor,product]) to get volume-by-source; the count lands in field f0_. Use parsed:\"No\" for unparsed logs."
        ),
        inputSchema={
            "type": "object",
            "required": ["filter"],
            "properties": {
                "filter": {
                    "type": "string",
                    "description": 'EQL expression e.g. \'user:"jsmith"\' or \'src_ip:"10.0.0.1"\'',
                },
                "fields": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "CIM fields to return; include an aggregate like count(id) for counts.",
                },
                "group_by": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Fields to group by (for aggregation).",
                },
                "lookback_days": {
                    "type": "integer",
                    "description": "Days to look back [default: 1]",
                    "default": 1,
                },
                "limit": {
                    "type": "integer",
                    "description": "Max events to return [default: 100]",
                    "default": 100,
                },
            },
        },
    ),
    Tool(
        name="create_case",
        description=(
            "Create a new Threat Center case from an alert. "
            "MODIFIES LIVE DATA. STOP and ask the analyst, then wait for an "
            "explicit yes, before calling this. Do not infer approval from the "
            "surrounding request. This is a SOFT gate -- the only hard technical "
            "control is the server's --allow-writes flag; this in-prompt "
            "confirmation is the layer on top of it."
        ),
        inputSchema={
            "type": "object",
            "required": ["alert_id"],
            "properties": {
                "alert_id": {"type": "string", "description": "UUID of the alert to associate"},
                "priority": {
                    "type": "string",
                    "description": "LOW, MEDIUM, HIGH, or CRITICAL [default: MEDIUM]",
                    "default": "MEDIUM",
                },
                "queue": {"type": "string", "description": "Queue name to assign"},
                "assignee": {"type": "string", "description": "Assignee username"},
            },
        },
    ),
    Tool(
        name="update_case",
        description=(
            "Update Threat Center case attributes. "
            "MODIFIES LIVE DATA. STOP and ask the analyst, then wait for an "
            "explicit yes, before calling this. Do not infer approval from the "
            "surrounding request. This is a SOFT gate -- the only hard technical "
            "control is the server's --allow-writes flag; this in-prompt "
            "confirmation is the layer on top of it."
        ),
        inputSchema={
            "type": "object",
            "required": ["case_id"],
            "properties": {
                "case_id": {"type": "string", "description": "Case UUID"},
                "stage": {
                    "type": "string",
                    "description": "OPEN, IN PROGRESS, or CLOSED",
                },
                "priority": {
                    "type": "string",
                    "description": "LOW, MEDIUM, HIGH, or CRITICAL",
                },
                "assignee": {"type": "string", "description": "Assignee username"},
                "queue": {"type": "string", "description": "Queue name"},
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Replacement tag list (replaces all existing tags)",
                },
                "closed_reason": {
                    "type": "string",
                    "description": "Required when stage=CLOSED",
                },
            },
        },
    ),
    Tool(
        name="update_alert",
        description=(
            "Update a Threat Center alert's priority or tags. "
            "MODIFIES LIVE DATA. STOP and ask the analyst, then wait for an "
            "explicit yes, before calling this. Do not infer approval from the "
            "surrounding request. This is a SOFT gate -- the only hard technical "
            "control is the server's --allow-writes flag; this in-prompt "
            "confirmation is the layer on top of it."
        ),
        inputSchema={
            "type": "object",
            "required": ["alert_id"],
            "properties": {
                "alert_id": {"type": "string", "description": "Alert UUID"},
                "priority": {
                    "type": "string",
                    "description": "LOW, MEDIUM, HIGH, or CRITICAL",
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Replacement tag list (replaces all existing tags)",
                },
            },
        },
    ),
    Tool(
        name="add_case_note",
        description=(
            "Add an investigation note to a case. "
            "MODIFIES LIVE DATA. STOP and ask the analyst, then wait for an "
            "explicit yes, before calling this. Do not infer approval from the "
            "surrounding request. This is a SOFT gate -- the only hard technical "
            "control is the server's --allow-writes flag; this in-prompt "
            "confirmation is the layer on top of it."
        ),
        inputSchema={
            "type": "object",
            "required": ["case_id", "content"],
            "properties": {
                "case_id": {"type": "string", "description": "Case UUID"},
                "content": {"type": "string", "description": "Note text to add"},
            },
        },
    ),
    # -- Read-only platform + AI/LLM tools ---------------------------------
    # The CLI has 87 commands; this server exposed 9, all search/cases/alerts.
    # A health-check or TAM-report skill had no tools to call at all. These are
    # the read paths those skills need. Deliberately NOT a generic "run any exa
    # command" tool -- that is arbitrary execution and bypasses per-tool gating.
    Tool(
        name="get_license_consumption",
        description=(
            "Licence entitlement and consumption: entitled vs consumed ingest, "
            "long-term search and storage. Read-only, safe for autonomous use."
        ),
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="get_app_status",
        description=(
            "Platform application/service health status. Read-only, safe for "
            "autonomous use."
        ),
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="list_collectors",
        description=(
            "Cloud Collector configurations, including type and last log received "
            "-- the field that reveals a stale collector. Read-only, safe for "
            "autonomous use."
        ),
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="aillm_sources",
        description=(
            "What this tenant actually sends: vendor, product, role (proxy/dns/dlp/"
            "edr/agent/audit) and activity types, plus collector state. The correct "
            "FIRST call of any AI/LLM engagement -- populating tables for a source "
            "that does not exist produces nothing and nothing about it looks wrong. "
            "Reports which sources exist, never how much they send. Read-only."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "lookback_days": {
                    "type": "integer",
                    "description": "Days to look back [default: 7]",
                    "default": 7,
                },
            },
        },
    ),
    Tool(
        name="aillm_validate",
        description=(
            "Health of the AI/LLM context tables, measured as OVERLAP WITH LIVE "
            "VALUES -- never record count. A table with 57 records and zero overlap "
            "is dead and a count-based check passes it. Read-only."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "lookback_days": {
                    "type": "integer",
                    "description": "Days to look back [default: 30]",
                    "default": 30,
                },
            },
        },
    ),
    Tool(
        name="aillm_rules",
        description=(
            "AI-scoped analytics rules: how many exist, how many are reachable "
            "(required fields present on this tenant), and how many are enabled. "
            "Read isEnabled, never enabled. Read-only."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "lookback_days": {
                    "type": "integer",
                    "description": "Days to look back [default: 30]",
                    "default": 30,
                },
            },
        },
    ),
    Tool(
        name="aillm_risk",
        description=(
            "High-risk AI domains this tenant has reached, joined against the risk "
            "table. CAUTION: a CLEAR result on a tenant with no proxy/DNS egress "
            "telemetry is a NO-VISIBILITY result, not an all-clear -- check "
            "aillm_sources before reporting it as reassurance. Read-only."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "lookback_days": {
                    "type": "integer",
                    "description": "Days to look back [default: 30]",
                    "default": 30,
                },
            },
        },
    ),
    Tool(
        name="aillm_gaps",
        description=(
            "Live values this tenant emits that the AI/LLM context tables are "
            "missing, classified as proposed or withheld with a reason per value. "
            "This is the populate payload. READ-ONLY -- it proposes, it never "
            "writes; applying is a separate deliberate step."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "lookback_days": {
                    "type": "integer",
                    "description": "Days to look back [default: 30]",
                    "default": 30,
                },
            },
        },
    ),
    Tool(
        name="list_detection_rules",
        description=(
            "Analytics (detection) rules on the tenant, optionally filtered by name or "
            "status. Returns a compact projection per rule (name, isEnabled, severity, "
            "type, activity_types, required_fields, families, mitre) -- not the full "
            "config. Read-only, safe for autonomous use."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Filter by rule name"},
                "status": {"type": "string", "description": "Filter by status"},
                "limit": {"type": "integer", "description": "Max rules to return"},
            },
        },
    ),
    Tool(
        name="get_active_tenant",
        description=(
            "Which tenant is this connector bound to RIGHT NOW. Returns the active "
            "tenant nickname, api_server, region, kind (demo/customer if tagged), "
            "whether writes are enabled, and token time-to-live. Call this before "
            "reporting on a tenant or performing any write, and state the tenant in "
            "the reply -- the analyst cannot otherwise see which tenant you are on. "
            "Read-only, safe for autonomous use."
        ),
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="list_tenants",
        description=(
            "The tenants configured on THIS machine (nickname, fqdn, region, kind, "
            "and which is active/default). Credentials are never returned -- they "
            "live in the OS credential store. Use to offer the analyst a choice "
            "before set_active_tenant. Read-only, safe for autonomous use."
        ),
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="set_active_tenant",
        description=(
            "Switch which configured tenant every subsequent tool call runs against, "
            "and refresh its token (runs the equivalent of 'exa auth' for the chosen "
            "tenant, loading its client credentials from the OS credential store -- no "
            "secret passes through you). Only tenants already configured on this "
            "machine are accepted; pass a nickname from list_tenants. This is a "
            "CONTEXT change, not a data write, but it can point you at a CUSTOMER "
            "tenant: after switching, state the new tenant and its kind before doing "
            "anything, and never write to a customer tenant without an explicit yes."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "tenant": {
                    "type": "string",
                    "description": "Tenant nickname to switch to (must be configured).",
                },
            },
            "required": ["tenant"],
        },
    ),
    Tool(
        name="set_tenant_kind",
        description=(
            "Tag a configured tenant as 'demo' or 'customer' so the demo/customer "
            "guardrail can see it. Writes non-secret metadata to the LOCAL exa-tools "
            "config -- it does NOT touch tenant data. If 'tenant' is omitted, tags the "
            "currently active tenant. Only 'demo' or 'customer' are accepted."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "tenant": {
                    "type": "string",
                    "description": "Tenant nickname to tag [default: the active tenant].",
                },
                "kind": {
                    "type": "string",
                    "enum": ["demo", "customer"],
                    "description": "'demo' or 'customer'.",
                },
            },
            "required": ["kind"],
        },
    ),
    Tool(
        name="parser_health",
        description=(
            "Parsing health for the active tenant: parsed vs unparsed volume, and parser "
            "errors classified into categories (Date/Time, Regex/Extraction, Type "
            "Conversion, Field Validation, JSON) with a remediation per category, plus the "
            "top failing parsers by msg_type. Read-only, safe for autonomous use. Errors are "
            "sampled -- 'sampled': true means more exist than were examined."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "lookback_days": {
                    "type": "integer",
                    "description": "Days to look back [default: 7]",
                    "default": 7,
                },
            },
        },
    ),
    Tool(
        name="render_report",
        description=(
            "Render a report as a branded, self-contained HTML file (the Exabeam house "
            "style: dark by default with a light toggle, logo, KPI cards, tables) and save "
            "it to disk. USE THIS FOR EVERY REPORT so output is on-brand -- do not hand-write "
            "HTML/CSS. Pass a spec: {title, subtitle?, cards:[{label,value,status?,hint?}] "
            "(status is good|warn|bad), sections:[{title, subtitle?, note?, coverage_pct?, "
            "table?:[{col:val,...}]}], meta?:[str], theme?}. Returns the saved file path; open "
            "it or print to PDF."
        ),
        inputSchema={
            "type": "object",
            "required": ["spec"],
            "properties": {
                "spec": {
                    "type": "object",
                    "description": "The report spec (title/cards/sections/meta).",
                },
                "output_path": {
                    "type": "string",
                    "description": "Where to save the HTML [default: reports/{kind}/{tenant}/<title-slug>.html, e.g. reports/customer/baystate/...]. Intermediate dirs are created automatically.",
                },
            },
        },
    ),
    Tool(
        name="ingest_value",
        description=(
            "Ingest value / overage analysis for the active tenant (read-only): entitled vs "
            "consumed license, top log sources by volume and % of ingest, unparsed % per source, "
            "whether each source feeds an ENABLED detection rule, and a mechanical Keep/Review/Trim "
            "recommendation per source. Use for an overage / cost-reduction assessment. Set "
            "render=true to also save a branded HTML report and get its path."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "lookback_days": {"type": "integer", "description": "Days to look back [default: 7]", "default": 7},
                "top_n": {"type": "integer", "description": "Top sources to return [default: 15]", "default": 15},
                "render": {"type": "boolean", "description": "Also save a branded HTML report [default: false]", "default": False},
            },
        },
    ),
    Tool(
        name="tuning_report",
        description=(
            "Detection-tuning insight for the active NSA tenant (read-only) -- the "
            "replacement for the legacy Mouton rules analysis. Ranks alert drivers by "
            "volume vs. how rarely they escalate to a case (high volume + low escalation "
            "+ low risk = noise to tune/disable -- the NSA stand-in for "
            "NotableReductionOnDeletion), with a per-driver Keep/Review/Tune recommendation. "
            "Set render=true to also save a branded HTML report."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "lookback_days": {"type": "integer", "description": "Days to look back [default: 30]", "default": 30},
                "top_n": {"type": "integer", "description": "Top alert drivers to return [default: 20]", "default": 20},
                "render": {"type": "boolean", "description": "Also save a branded HTML report [default: false]", "default": False},
            },
        },
    ),
    Tool(
        name="source_detail",
        description=(
            "Deep-dive one log source (by vendor, optionally product): top msg_types, action "
            "mix (e.g. Drop vs Accept), activity_types, unparsed %, and which ENABLED rules "
            "consume its activity_types (and their rule types). Read-only. Use to judge a "
            "source's value vs waste during an overage review -- one call instead of several "
            "manual aggregate searches. Set render=true to also save a branded HTML report."
        ),
        inputSchema={
            "type": "object",
            "required": ["vendor"],
            "properties": {
                "vendor": {"type": "string", "description": "Vendor, e.g. \"Check Point\"."},
                "product": {"type": "string", "description": "Product, e.g. \"Check Point NGFW\" [optional]."},
                "lookback_days": {"type": "integer", "description": "Days to look back [default: 7]", "default": 7},
                "render": {"type": "boolean", "description": "Also save a branded HTML report [default: false]", "default": False},
            },
        },
    ),
    Tool(
        name="identity_health",
        description=(
            "Detect AD/identity-resolution problems (read-only): (1) MERGED ENTITIES -- an "
            "identifier (email/UPN/SAMAccountName) in an identity/User context table that maps "
            "to 2+ distinct users, the smoking gun for two people collapsed into one entity "
            "(usually a recycled email); (2) GUID GHOST USERS -- logins whose username is a bare "
            "AD objectGUID, grouped by host (unresolved/orphaned AD accounts). Use when a "
            "customer reports users merged together or EXA-INTERNAL-ERROR on an entity. The FIX "
            "is a gated, human-confirmed remediation -- this tool only detects. Bounded for large "
            "tenants (caps records/table and table count, skips empty tables); if it times out, "
            "lower max_tables / max_records_per_table, pass table= or tables=[...] to focus, or set "
            "guid_scan=false (the event query is often the slow half). Set render=true for a report."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "lookback_days": {"type": "integer", "description": "Days to look back for GUID logins [default: 7]", "default": 7},
                "table": {"type": "string", "description": "Restrict the merge scan to ONE identity table by name/id [optional]."},
                "tables": {"type": "array", "items": {"type": "string"}, "description": "Restrict the merge scan to these identity tables by name/id [optional; e.g. [\"Email User\", \"User SID\"]]."},
                "max_records_per_table": {"type": "integer", "description": "Cap records read per table [default: 25000]", "default": 25000},
                "max_tables": {"type": "integer", "description": "Cap how many identity tables to scan (smallest first) [default: 8]", "default": 8},
                "guid_scan": {"type": "boolean", "description": "Also run the GUID-ghost login-event scan [default: true]; set false if the event query is timing out", "default": True},
                "render": {"type": "boolean", "description": "Also save a branded HTML report [default: false]", "default": False},
            },
        },
    ),
    Tool(
        name="context_table",
        description=(
            "Read Context Management tables directly (read-only) -- including User Entity Links, "
            "which is otherwise UI-only. With no arguments, lists all context tables (id, name, "
            "type, record count). With table set, reads that table's records; add contains to "
            "filter records whose values contain a string (e.g. a username or email) -- the "
            "manual 'search adam.reckamp, see every identifier mapped to the entity' lookup."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name (substring) or id. Omit to list all tables."},
                "contains": {"type": "string", "description": "Only return records with a value containing this string [optional]."},
                "limit": {"type": "integer", "description": "Max records to return [default: 200]", "default": 200},
            },
        },
    ),
    Tool(
        name="render_dashboard",
        description=(
            "Preview an Exabeam dashboard .config (JSON) as a branded HTML file for review "
            "BEFORE the manual UI import -- Exabeam dashboards import only via Dashboards -> "
            "Import, there is no API import. Pass config (the dashboard JSON object) or "
            "config_path (a .config file on this machine). Shows each panel's title, "
            "visualization, fields, filter and limit, grouped by section. Edit the config and "
            "re-render to iterate. Read-only."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "config": {"type": "object", "description": "The dashboard config JSON object."},
                "config_path": {"type": "string", "description": "Path to a .config file (if not passing config)."},
                "output_path": {"type": "string", "description": "Where to save the preview HTML [default: reports/{kind}/{tenant}/<title>-preview.html]. Intermediate dirs are created automatically."},
            },
        },
    ),
    Tool(
        name="render_abv",
        description=(
            "Render the Praxen Agent-Behavior-Verification (ABV) report for exa-tools as a "
            "branded HTML file: verdict banner, remit-coverage scorecard (each declared policy "
            "clause vs observed behavior), and the findings register. Describes the exa-tools "
            "MCP's own security posture (read-only default, guardrails, audit privacy) -- it "
            "does NOT scan the tenant. Read-only."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "output_path": {"type": "string", "description": "Where to save the HTML [default: reports/praxen-abv.html]. Intermediate dirs are created automatically."},
            },
        },
    ),
    Tool(
        name="ai_domain_lookup",
        description=(
            "Check one or more domains against the cached AI/LLM reference dataset (public "
            "AI/LLM domains with risk tier, web domains, AI applications) -- the ExabeamLabs / "
            "repins267 AI/LLM knowledge base. Use to answer 'is this a known AI domain / what "
            "risk?' or to enrich shadow-AI findings. Read-only; matches exact and parent domain."
        ),
        inputSchema={
            "type": "object",
            "required": ["domains"],
            "properties": {
                "domains": {"type": "array", "items": {"type": "string"},
                            "description": "Domains to look up."},
            },
        },
    ),
    Tool(
        name="soc_kpis",
        description=(
            "SOC KPI rollup for the active tenant (read-only): cases opened, closed, open "
            "backlog, close rate, MTTR (avg time to close) and avg open age, plus breakdowns "
            "by assignee (worked-by), priority, stage, queue, top firing rules, and notable "
            "users. For an analyst/SOC-manager view. Set render=true to also save a branded "
            "HTML report."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "lookback_days": {"type": "integer", "description": "Days to look back [default: 30]", "default": 30},
                "render": {"type": "boolean", "description": "Also save a branded HTML report [default: false]", "default": False},
            },
        },
    ),
]


def _active_tenant_info(client: "ExaClient", read_only: bool) -> dict:
    """Non-secret snapshot of the tenant a client is bound to."""
    import time

    exp = getattr(client, "_expires_at", 0.0) or 0.0
    ttl = max(0, int(exp - time.time())) if exp else None
    entry: dict = {}
    try:
        from exa.config import list_tenants

        entry = list_tenants().get(client.tenant or "", {})
    except Exception:
        entry = {}
    return {
        "active_tenant": client.tenant,
        "api_server": getattr(client, "base_url", None),
        "region": entry.get("region"),
        "fqdn": entry.get("fqdn"),
        "kind": entry.get("kind"),
        "writes_enabled": not read_only,
        "token_ttl_seconds": ttl,
    }


def visible_tools(*, read_only: bool) -> list[Tool]:
    """Tools to advertise to the MCP client.

    In read-only mode the four write tools are withheld entirely, so the model
    never sees them and cannot attempt a write. dispatch_tool enforces the same
    rule server-side as defense in depth.
    """
    if read_only:
        return [t for t in TOOL_DEFS if t.name not in WRITE_TOOLS]
    return list(TOOL_DEFS)


def _parser_health_summary(h) -> dict:
    """JSON-friendly, bounded summary of a ParserHealth snapshot."""
    return {
        "tenant": h.tenant,
        "lookback_days": h.lookback_days,
        "parsed": h.parsed,
        "unparsed": h.unparsed,
        "unparsed_pct": h.unparsed_pct,
        "errors_examined": h.errors_examined,
        "sampled": h.truncated,
        "categories": [
            {
                "category": g.category,
                "count": g.count,
                "top_field": (g.top_fields[0][0] if g.top_fields else None),
                "top_parser": (g.top_sources[0][0] if g.top_sources else None),
                "recommendation": g.recommendation,
            }
            for g in h.groups
        ],
        "top_failing_parsers": [{"parser": src, "errors": n} for src, n in h.by_source],
        # NGDV-07-style triage: which parsers to look at first (Red = a core/detection
        # field misparsed). A first-pass grade, not the DVE workbook's authoritative
        # field-class call -- final TP/FP is a manual raw-log review.
        "parsers_needing_action": [
            {
                "parser": a["source"],
                "grade": a["grade"],
                "errors": a["errors"],
                "core_fields": a["core_fields"],
            }
            for a in getattr(h, "parsers_needing_action", [])
            if a["grade"] in ("Red", "Yellow")
        ][:15],
        "grade_counts": {
            g: sum(1 for a in getattr(h, "parsers_needing_action", []) if a["grade"] == g)
            for g in ("Red", "Yellow")
        },
        "note": h.note or None,
    }


async def dispatch_tool(
    client: ExaClient,
    name: str,
    arguments: dict[str, Any],
    *,
    read_only: bool = False,
    session: "object | None" = None,
) -> list[TextContent]:
    """Route a tool call to the corresponding exa-tools function."""
    if read_only and name in WRITE_TOOLS:
        return _err(
            f"Refused: '{name}' modifies live tenant data and this MCP server is "
            "running in READ-ONLY mode. Restart the server with --allow-writes to "
            "enable write tools."
        )
    # Neutralize active content in free-text WRITE inputs before it persists: quote-prefix
    # spreadsheet formulas, defang links, redact secrets — so a payload planted in
    # telemetry can't fire when the case note / update is later exported.
    if name in WRITE_TOOLS:
        from exa.mcp.guardrails import neutralize_write_args

        arguments, _guardrail_notes = neutralize_write_args(arguments)
        # Surface to the audit layer whether the write guardrail actually acted
        # (PRAX-2026-08-20-007). Side-channel on the session; record_tool_call reads+clears it.
        if session is not None:
            try:
                session._guardrail_neutralized = bool(_guardrail_notes)
            except Exception:
                pass
    try:
        match name:
            case "search_alerts":
                from exa.case.alerts import search_alerts

                rows = search_alerts(
                    client,
                    filter=arguments.get("filter") or None,
                    lookback_days=arguments.get("lookback_days", 7),
                    limit=arguments.get("limit", 50),
                )
                return _ok(rows)

            case "get_alert":
                from exa.case.alerts import search_alerts

                alert_id = arguments["alert_id"]
                rows = search_alerts(
                    client,
                    filter=f'alertId:"{alert_id}"',
                    lookback_days=90,
                    limit=1,
                )
                if not rows:
                    return _err(f"Alert {alert_id} not found")
                return _ok(rows[0])

            case "search_cases":
                from exa.case.cases import search_cases

                rows = search_cases(
                    client,
                    filter=arguments.get("filter") or None,
                    lookback_days=arguments.get("lookback_days", 7),
                    limit=arguments.get("limit", 50),
                )
                return _ok(rows)

            case "get_case":
                from exa.case.cases import get_case

                return _ok(get_case(client, arguments["case_id"]))

            case "search_events":
                from exa.search.events import search_events

                rows = search_events(
                    client,
                    arguments["filter"],
                    fields=arguments.get("fields"),
                    group_by=arguments.get("group_by"),
                    lookback_days=arguments.get("lookback_days", 1),
                    limit=arguments.get("limit", 100),
                )
                return _ok(rows)

            case "create_case":
                from exa.case.cases import create_case

                return _ok(
                    create_case(
                        client,
                        arguments["alert_id"],
                        priority=arguments.get("priority", "MEDIUM"),
                        queue=arguments.get("queue"),
                        assignee=arguments.get("assignee"),
                    )
                )

            case "update_case":
                from exa.case.cases import update_case

                return _ok(
                    update_case(
                        client,
                        arguments["case_id"],
                        stage=arguments.get("stage"),
                        priority=arguments.get("priority"),
                        assignee=arguments.get("assignee"),
                        queue=arguments.get("queue"),
                        tags=arguments.get("tags"),
                        closed_reason=arguments.get("closed_reason"),
                    )
                )

            case "update_alert":
                from exa.case.alerts import update_alert

                return _ok(
                    update_alert(
                        client,
                        arguments["alert_id"],
                        priority=arguments.get("priority"),
                        tags=arguments.get("tags"),
                    )
                )

            case "add_case_note":
                # EXA-CASENOTES-UNVERIFIED: endpoint not confirmed live against sademodev22
                case_id = arguments["case_id"]
                content = arguments["content"]
                try:
                    result = client.post(
                        f"/threat-center/v1/cases/{case_id}/notes",
                        json={"content": content},
                    )
                    return _ok(result)
                except Exception as exc:
                    return _err(f"add_case_note failed (EXA-CASENOTES-UNVERIFIED): {exc}")

            case "get_license_consumption":
                from exa.health.consumption import get_license_details

                return _ok(get_license_details(client))

            case "get_app_status":
                from exa.health.consumption import get_app_status

                return _ok(get_app_status(client))

            case "list_collectors":
                return _ok(client.get("/cloud-collectors/v1/configs"))

            case "aillm_sources":
                from exa.aillm.sources import collect_sources

                return _ok_obj(
                    collect_sources(
                        client, lookback_days=arguments.get("lookback_days", 7)
                    )
                )

            case "aillm_validate":
                from exa.aillm.validate import validate_aillm_tables

                return _ok_obj(
                    validate_aillm_tables(
                        client, lookback_days=arguments.get("lookback_days", 30)
                    )
                )

            case "aillm_rules":
                # A COLD tenant field-profile is built by enumerating fields via
                # search_events; on a rule-heavy tenant that can exceed the MCP
                # client's timeout and read as a crash. Use the cached profile when
                # present (fast), and fail FAST with guidance when it is not --
                # never hang synchronously building it here.
                from exa.aillm.profile import load_cached_profile
                from exa.aillm.rules import analyze_ai_rules

                prof = load_cached_profile(client)
                if prof is None:
                    tenant = getattr(client, "tenant", None) or "<tenant>"
                    return _err(
                        "aillm_rules needs a tenant field-profile that is not cached "
                        "yet, and building it here can exceed the client timeout. Warm "
                        f"it once from the CLI: `exa aillm rules --tenant {tenant}` "
                        "(no timeout there), then retry -- subsequent calls are fast."
                    )
                return _ok_obj(
                    analyze_ai_rules(
                        client,
                        profile=prof,
                        lookback_days=arguments.get("lookback_days", 30),
                    )
                )

            case "aillm_risk":
                from exa.aillm.risk import build_risk_report

                return _ok_obj(
                    build_risk_report(
                        client, lookback_days=arguments.get("lookback_days", 30)
                    )
                )

            case "aillm_gaps":
                from exa.aillm.gaps import analyze_gaps

                # Read-only by construction: analyze_gaps proposes, it never writes.
                return _ok_obj(
                    analyze_gaps(
                        client, lookback_days=arguments.get("lookback_days", 30)
                    )
                )

            case "list_detection_rules":
                from exa.detection.rules import get_detection_rules

                rules = get_detection_rules(
                    client,
                    name=arguments.get("name"),
                    status=arguments.get("status"),
                    limit=arguments.get("limit"),
                )
                # Project to the fields a caller reasons over. The full rule
                # config (actOnCondition, templates, updatedRuleConfig) is huge
                # -- a no-filter list is ~500KB and unusable inline.
                slim = []
                for r in rules:
                    acts: list[str] = []
                    for ev in r.get("applicableEvents") or []:
                        acts += [str(a) for a in (ev.get("activity_type") or [])]
                    slim.append({
                        "name": r.get("name"),
                        "isEnabled": r.get("isEnabled"),
                        "severity": r.get("severity"),
                        "type": r.get("type"),
                        "activity_types": sorted(set(acts)),
                        "required_fields": r.get("requiredFields"),
                        "families": r.get("families"),
                        "mitre": [
                            m.get("techniqueKey")
                            for m in (r.get("mitre") or [])
                            if isinstance(m, dict)
                        ],
                    })
                return _ok(slim)

            case "get_active_tenant":
                return _ok(_active_tenant_info(client, read_only))

            case "list_tenants":
                from exa.config import get_default_tenant, list_tenants

                try:
                    default = get_default_tenant()
                except Exception:
                    default = None
                active = getattr(client, "tenant", None)
                rows = []
                for nick, e in sorted(list_tenants().items()):
                    rows.append(
                        {
                            "tenant": nick,
                            "fqdn": e.get("fqdn", f"{nick}.exabeam.cloud"),
                            "region": e.get("region"),
                            "api_server": e.get("api_server"),
                            "kind": e.get("kind"),
                            "active": nick == active,
                            "default": nick == default,
                        }
                    )
                return _ok({"tenants": rows, "active": active, "default": default})

            case "set_active_tenant":
                if session is None:
                    return _err(
                        "set_active_tenant is only available when running as the MCP "
                        "server (no mutable session in this context)."
                    )
                from exa.config import list_tenants

                target = arguments["tenant"]
                configured = list_tenants()
                if target not in configured:
                    return _err(
                        f"Unknown tenant '{target}'. Configured on this machine: "
                        f"{sorted(configured)}. Add one with 'exa configure'."
                    )
                try:
                    session.switch(target)
                except Exception as exc:
                    return _err(f"Failed to switch to '{target}': {exc}")
                # Persist the switch as the default tenant so it survives a server
                # respawn. Claude Desktop restarts the stdio server between sessions
                # (and on idle/error); without this, the next process reverts to its
                # launch tenant and the switch silently "reverts". Best-effort.
                persisted = False
                try:
                    from exa.config import set_default_tenant

                    set_default_tenant(target)
                    persisted = True
                except Exception:
                    pass
                info = _active_tenant_info(session.client, session.read_only)
                info["persisted_as_default"] = persisted
                if not persisted:
                    info["warning"] = ("switched in-memory but could not persist the default; "
                                       "a server restart may revert to the launch tenant")
                return _ok(info)

            case "set_tenant_kind":
                from exa.config import list_tenants, set_tenant_kind

                target = arguments.get("tenant") or getattr(client, "tenant", None)
                if not target:
                    return _err("No tenant given and no active tenant to tag.")
                try:
                    set_tenant_kind(target, arguments.get("kind", ""))
                except Exception as exc:
                    return _err(str(exc))
                entry = list_tenants().get(target, {})
                return _ok(
                    {"tenant": target, "kind": entry.get("kind"), "updated": True}
                )

            case "parser_health":
                from exa.health.parser import collect_parser_health

                h = collect_parser_health(
                    client,
                    lookback_days=arguments.get("lookback_days", 7),
                    error_limit=arguments.get("error_limit", 5000),
                )
                return _ok(_parser_health_summary(h))

            case "render_report":
                from exa.report import save_report

                spec = arguments.get("spec") or {}
                if not isinstance(spec, dict) or not spec.get("title"):
                    return _err("render_report needs a spec object with at least a title.")
                op = arguments.get("output_path")
                if op:
                    try:
                        op = str(_contained_output_path(op))
                    except ValueError as exc:
                        return _err(str(exc))
                else:
                    import re as _re

                    slug = _re.sub(r"[^a-z0-9]+", "-", str(spec.get("title", "report")).lower()).strip("-")[:60] or "report"
                    op = str(_report_path(client, f"{slug}.html"))
                path = save_report(spec, op)
                return _ok({
                    "saved": str(path.resolve()),
                    "note": "Branded HTML saved. Open it, or print to PDF (light theme prints cleanest).",
                })

            case "ingest_value":
                from exa.health.ingest_value import (
                    collect_ingest_value,
                    ingest_value_summary,
                )

                iv = collect_ingest_value(
                    client,
                    lookback_days=arguments.get("lookback_days", 7),
                    top_n=arguments.get("top_n", 15),
                )
                out = ingest_value_summary(iv)
                if arguments.get("render"):
                    from exa.health.ingest_value import render_ingest_value
                    from exa.report.build import save_report

                    spec_html = render_ingest_value(iv)
                    rp = _report_path(client, "ingest-value.html")
                    rp.write_text(spec_html, encoding="utf-8")
                    out["report_saved"] = str(rp.resolve())
                return _ok(out)

            case "source_detail":
                from exa.health.source_detail import (
                    collect_source_detail,
                    source_detail_summary,
                )

                vendor = arguments.get("vendor")
                if not vendor:
                    return _err("source_detail needs a vendor.")
                sd = collect_source_detail(
                    client, vendor, arguments.get("product", ""),
                    lookback_days=arguments.get("lookback_days", 7),
                )
                out = source_detail_summary(sd)
                if arguments.get("render"):
                    from exa.health.source_detail import render_source_detail

                    slug = _safe_seg((sd.source or "source").lower().replace(" · ", "-").replace(" ", "-"))
                    rp = _report_path(client, f"source-{slug}.html")
                    rp.write_text(render_source_detail(sd), encoding="utf-8")
                    out["report_saved"] = str(rp.resolve())
                return _ok(out)

            case "identity_health":
                from exa.health.identity import collect_identity_health, identity_summary

                ih = collect_identity_health(
                    client,
                    lookback_days=arguments.get("lookback_days", 7),
                    table=arguments.get("table") or None,
                    tables=arguments.get("tables") or None,
                    max_records_per_table=arguments.get("max_records_per_table", 25_000),
                    max_tables=arguments.get("max_tables", 8),
                    guid_scan=arguments.get("guid_scan", True),
                )
                out = identity_summary(ih)
                if arguments.get("render"):
                    from exa.health.identity import render_identity

                    rp = _report_path(client, "identity-health.html")
                    rp.write_text(render_identity(ih), encoding="utf-8")
                    out["report_saved"] = str(rp.resolve())
                return _ok(out)

            case "context_table":
                from exa.context.tables import get_all_records, get_tables

                table = arguments.get("table")
                if not table:
                    tables = get_tables(client)
                    return _ok([
                        {"id": t.get("id"), "name": t.get("name"),
                         "type": t.get("contextType"), "records": t.get("totalItems") or t.get("recordCount")}
                        for t in tables
                    ])
                t_l = str(table).lower()
                match = [t for t in get_tables(client)
                         if t_l in str(t.get("name", "")).lower() or t_l == str(t.get("id", ""))]
                if not match:
                    return _err(f"No context table matching '{table}'.")
                t = match[0]
                # Bound the read: a large customer table read unbounded can choke the
                # stdio pipe / stall the server. Read enough to filter, not the world.
                _cap = 50_000
                records = get_all_records(client, t["id"])[:_cap]
                truncated_scan = len(records) >= _cap
                contains = (arguments.get("contains") or "").strip().lower()
                if contains:
                    records = [r for r in records
                               if any(contains in str(v).lower() for v in r.values())]
                limit = arguments.get("limit", 200)
                out = {
                    "table": t.get("name"), "id": t.get("id"), "type": t.get("contextType"),
                    "matched_records": len(records), "records": records[:limit],
                }
                if truncated_scan:
                    out["note"] = f"scanned the first {_cap:,} records only; narrow with contains= for a full-fidelity match"
                return _ok(out)

            case "render_dashboard":
                import json as _json
                import re as _re
                from pathlib import Path as _P

                from exa.report.dashboard import dashboard_preview_html

                cfg = arguments.get("config")
                if not cfg and arguments.get("config_path"):
                    # config_path is model-supplied; refuse anything that isn't a small
                    # dashboard config file so it can't read arbitrary host files into an
                    # HTML artifact (PRAX-2026-08-19-002).
                    cp = _P(arguments["config_path"]).resolve()
                    # Contain the read to the operator's own files (home or CWD) so a
                    # model-supplied path can't reach system/other-user files
                    # (PRAX-2026-08-20-002).
                    _roots = (_P.home().resolve(), _P.cwd().resolve())
                    if not any(cp.is_relative_to(r) for r in _roots):
                        return _err("config_path must be under your home directory or the working directory.")
                    if cp.suffix.lower() not in (".json", ".config"):
                        return _err("config_path must be a .json or .config file.")
                    try:
                        if cp.stat().st_size > 5_000_000:
                            return _err("config_path file is too large to be a dashboard config (>5 MB).")
                        cfg = _json.loads(cp.read_text(encoding="utf-8"))
                    except Exception as exc:
                        return _err(f"could not read config_path: {exc}")
                if not isinstance(cfg, dict):
                    return _err("render_dashboard needs a config object or a config_path.")
                slug = _re.sub(r"[^a-z0-9]+", "-", str(cfg.get("title", "dashboard")).lower()).strip("-")[:60] or "dashboard"
                if arguments.get("output_path"):
                    try:
                        outp = _contained_output_path(arguments["output_path"])
                    except ValueError as exc:
                        return _err(str(exc))
                else:
                    outp = _report_path(client, f"{slug}-preview.html")
                outp.write_text(dashboard_preview_html(cfg, client=client), encoding="utf-8")
                panels = len([e for e in (cfg.get("dashboardElements") or []) if e.get("type") == "vis"])
                return _ok({
                    "saved": str(outp.resolve()),
                    "panels": panels,
                    "note": "Preview only. Edit the config and re-render to iterate; import the final .config via the Exabeam UI (Dashboards -> Import).",
                })

            case "render_abv":
                from pathlib import Path as _P

                from exa.report.abv import ABV, render_abv

                try:
                    outp = _contained_output_path(arguments.get("output_path") or "praxen-abv.html")
                except ValueError as exc:
                    return _err(str(exc))
                outp.write_text(render_abv(), encoding="utf-8")
                held = sum(1 for c in ABV["clauses"] if c["status"] == "HELD")
                return _ok({
                    "saved": str(outp.resolve()),
                    "clauses": len(ABV["clauses"]),
                    "held": held,
                    "findings": len(ABV["findings"]),
                    "note": "Branded Praxen ABV report for the exa-tools MCP's own posture (not a tenant scan). "
                            "Run the real Praxen plugin against security/praxen/WORKER_REMIT.md for an independent scan.",
                })

            case "ai_domain_lookup":
                from exa.aillm.reference import lookup_ai_domains

                domains = arguments.get("domains") or []
                if not isinstance(domains, list) or not domains:
                    return _err("ai_domain_lookup needs a non-empty 'domains' list.")
                rows = lookup_ai_domains([str(d) for d in domains])
                known = [r for r in rows if r["known_ai"]]
                return _ok({"results": rows, "known": len(known), "checked": len(rows)})

            case "soc_kpis":
                from exa.case.soc_kpis import collect_soc_kpis, soc_kpis_summary

                k = collect_soc_kpis(client, lookback_days=arguments.get("lookback_days", 30))
                out = soc_kpis_summary(k)
                if arguments.get("render"):
                    from exa.case.soc_kpis import render_soc_kpis

                    rp = _report_path(client, "soc-kpis.html")
                    rp.write_text(render_soc_kpis(k), encoding="utf-8")
                    out["report_saved"] = str(rp.resolve())
                return _ok(out)

            case "tuning_report":
                from exa.case.tuning import collect_tuning, tuning_summary

                tr = collect_tuning(client, lookback_days=arguments.get("lookback_days", 30),
                                    top_n=arguments.get("top_n", 20))
                out = tuning_summary(tr)
                if arguments.get("render"):
                    from exa.case.tuning import render_tuning

                    rp = _report_path(client, "tuning.html")
                    rp.write_text(render_tuning(tr), encoding="utf-8")
                    out["report_saved"] = str(rp.resolve())
                return _ok(out)

            case _:
                return _err(f"Unknown tool: {name}")

    except Exception as exc:
        return _err(str(exc))

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
    return [TextContent(type="text", text=json.dumps({"error": message}))]


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
            "Use for investigation pivots — e.g. search events for a specific user, host, or IP."
        ),
        inputSchema={
            "type": "object",
            "required": ["filter"],
            "properties": {
                "filter": {
                    "type": "string",
                    "description": 'EQL expression e.g. \'user:"jsmith"\' or \'src_ip:"10.0.0.1"\'',
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
            "surrounding request. This is a SOFT gate: in Claude Code the "
            "permission pack is the hard lock; in Claude Desktop this "
            "instruction is the only one."
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
            "surrounding request. This is a SOFT gate: in Claude Code the "
            "permission pack is the hard lock; in Claude Desktop this "
            "instruction is the only one."
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
            "surrounding request. This is a SOFT gate: in Claude Code the "
            "permission pack is the hard lock; in Claude Desktop this "
            "instruction is the only one."
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
            "surrounding request. This is a SOFT gate: in Claude Code the "
            "permission pack is the hard lock; in Claude Desktop this "
            "instruction is the only one."
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
            "Analytics (detection) rules on the tenant, optionally filtered by name "
            "or status. Read-only, safe for autonomous use."
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
                from exa.aillm.rules import analyze_ai_rules

                return _ok_obj(
                    analyze_ai_rules(
                        client, lookback_days=arguments.get("lookback_days", 30)
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

                return _ok(
                    get_detection_rules(
                        client,
                        name=arguments.get("name"),
                        status=arguments.get("status"),
                        limit=arguments.get("limit"),
                    )
                )

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
                return _ok(
                    _active_tenant_info(session.client, session.read_only)
                )

            case _:
                return _err(f"Unknown tool: {name}")

    except Exception as exc:
        return _err(str(exc))

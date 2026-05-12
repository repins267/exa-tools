"""MCP tool definitions and dispatch for exa-tools.

Each tool wraps an existing exa-tools function. Read tools are marked safe for
autonomous use; write tools include an approval warning in their description so
Claude knows to request human confirmation before executing.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from mcp.types import TextContent, Tool

if TYPE_CHECKING:
    from exa.client import ExaClient


def _ok(data: Any) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(data, default=str))]


def _err(message: str) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps({"error": message}))]


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
            "MODIFIES LIVE DATA — requires human approval before execution."
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
            "MODIFIES LIVE DATA — requires human approval before execution."
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
            "MODIFIES LIVE DATA — requires human approval before execution."
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
            "MODIFIES LIVE DATA — requires human approval before execution."
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
]


async def dispatch_tool(
    client: ExaClient, name: str, arguments: dict[str, Any]
) -> list[TextContent]:
    """Route a tool call to the corresponding exa-tools function."""
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

            case _:
                return _err(f"Unknown tool: {name}")

    except Exception as exc:
        return _err(str(exc))

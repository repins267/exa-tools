"""CLI commands for Threat Center cases and alerts.

  exa cases list       — search/list cases
  exa cases get        — get a specific case by ID
  exa cases update     — update case attributes
  exa alerts list      — search/list alerts
  exa alerts get       — get a specific alert by ID
  exa alerts update    — update alert attributes
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

cases_app = typer.Typer(
    name="cases",
    help="Threat Center case management.",
    no_args_is_help=True,
)

alerts_app = typer.Typer(
    name="alerts",
    help="Threat Center alert management.",
    no_args_is_help=True,
)

console = Console()

_TENANT_HELP = "Tenant nickname or FQDN [default: saved default]"
_PRIORITY_VALUES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
_FILTER_HINT = (
    '  Filter syntax: field:"value", NOT field:"value", field:"a" OR field:"b"\n'
    "  PowerShell: use single quotes around the filter value:\n"
    '    --filter \'NOT stage:"CLOSED"\'\n'
    '    --filter \'alertName:"Abnormal day of week"\''
)


def _make_client(tenant: str | None = None):
    from exa.client import ExaClient

    client = ExaClient(tenant=tenant)
    client.authenticate()
    return client


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

@cases_app.command("list")
def cases_list(
    filter: Annotated[
        str | None,
        typer.Option("--filter", "-f", help='EQL filter e.g. \'NOT stage:"CLOSED"\' or \'priority:"HIGH"\''),
    ] = None,
    lookback: Annotated[
        int,
        typer.Option("--lookback", help="Days to look back [default: 30]"),
    ] = 30,
    limit: Annotated[
        int,
        typer.Option("--limit", help="Max cases to return [default: 50]"),
    ] = 50,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
    json_out: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Output raw JSON [default: no-json]"),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write JSON to file (default: print to terminal)"),
    ] = None,
) -> None:
    """List and search Threat Center cases.

    Returns the most recent cases matching the optional EQL filter, ordered
    by creation timestamp descending. Use --filter for targeted queries or
    leave it empty to list all recent cases.

    \b
    Examples:
      uv run exa cases list
      uv run exa cases list --filter 'priority:"HIGH"' --lookback 7
      uv run exa cases list --filter 'NOT stage:"CLOSED"' --limit 25
      uv run exa cases list --json --tenant csnafusion
      uv run exa cases list --output cases.json
    """
    from exa.case import search_cases

    client = _make_client(tenant)
    try:
        try:
            rows = search_cases(
                client,
                filter=filter,
                lookback_days=lookback,
                limit=limit,
            )
        except Exception as e:
            from exa.exceptions import ExaAPIError as _ExaAPIError
            if isinstance(e, _ExaAPIError) and e.status_code == 400:
                console.print(f"  Filter error (HTTP 400): {e.detail}", style="red")
                if filter:
                    console.print(_FILTER_HINT, style="dim")
                raise typer.Exit(1)
            raise
    finally:
        client.close()

    if output is not None:
        import json as _json
        output.write_text(_json.dumps(rows, indent=2), encoding="utf-8")

    if json_out:
        import json
        console.print_json(json.dumps(rows))
        return

    if output is not None:
        console.print(f"  {len(rows)} case(s) written to {output}", style="dim")
        return

    if not rows:
        console.print("No cases found.", style="dim")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Case #", style="cyan", no_wrap=True)
    table.add_column("Name", max_width=40)
    table.add_column("Stage", no_wrap=True)
    table.add_column("Priority", no_wrap=True)
    table.add_column("Risk", no_wrap=True)
    table.add_column("Assignee", no_wrap=True)
    table.add_column("Case ID", style="dim", no_wrap=True)

    priority_colors = {
        "CRITICAL": "red",
        "HIGH": "yellow",
        "MEDIUM": "blue",
        "LOW": "green",
    }

    for row in rows:
        pri = str(row.get("priority", "")).upper()
        pri_style = priority_colors.get(pri, "")
        table.add_row(
            str(row.get("caseNumber", "")),
            str(row.get("alertName", row.get("caseName", ""))),
            str(row.get("stage", "")),
            f"[{pri_style}]{pri}[/{pri_style}]" if pri_style else pri,
            str(row.get("riskScore", "")),
            str(row.get("assignee", "")),
            str(row.get("caseId", "")),
        )

    console.print(table)
    console.print(f"\n  {len(rows)} case(s)", style="dim")


@cases_app.command("get")
def cases_get(
    case_id: Annotated[str, typer.Argument(help="Case UUID")],
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
    json_out: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Output raw JSON [default: no-json]"),
    ] = False,
) -> None:
    """Get full details and Nova threat summary for a case by UUID.

    Retrieves the case record including stage, priority, assigned queue,
    risk score, associated users/endpoints, and the Nova AI threat summary.

    \b
    Examples:
      uv run exa cases get <case-uuid>
      uv run exa cases get <case-uuid> --json
      uv run exa cases get <case-uuid> --tenant csnafusion
    """
    import json

    from exa.case import get_case

    client = _make_client(tenant)
    try:
        case = get_case(client, case_id)

        if json_out:
            console.print_json(json.dumps(case))
            return

        # Pretty print key fields
        console.print(f"\n[bold]Case {case.get('caseNumber', case_id)}[/bold]")
        console.print(f"  ID:          {case.get('caseId', case_id)}")
        console.print(f"  Name:        {case.get('alertName', '')}")
        console.print(f"  Stage:       {case.get('stage', '')}")
        console.print(f"  Priority:    {case.get('priority', '')}")
        console.print(f"  Risk Score:  {case.get('riskScore', '')}")
        console.print(f"  Queue:       {case.get('queue', '')}")
        console.print(f"  Assignee:    {case.get('assignee', '')}")
        console.print(f"  Created:     {case.get('creationTimestamp', '')}")
        console.print(f"  Updated:     {case.get('lastModifiedTimestamp', '')}")

        tags = case.get("tags", [])
        if tags:
            console.print(f"  Tags:        {', '.join(tags)}")

        users = case.get("users", [])
        if users:
            console.print(f"  Users:       {', '.join(str(u) for u in users)}")

        endpoints = case.get("endpoints", [])
        if endpoints:
            console.print(f"  Endpoints:   {', '.join(str(e) for e in endpoints)}")

        threat_summary = case.get("threatSummary", case.get("threat_summary", ""))
        if threat_summary:
            console.print("\n[bold]Threat Summary[/bold]")
            console.print(f"  {threat_summary}")
    finally:
        client.close()


@cases_app.command("update")
def cases_update(
    case_id: Annotated[str, typer.Argument(help="Case UUID")],
    name: Annotated[
        str | None,
        typer.Option("--name", help="New case name"),
    ] = None,
    description: Annotated[
        str | None,
        typer.Option("--description", help="New case description"),
    ] = None,
    stage: Annotated[
        str | None,
        typer.Option("--stage", help='New stage: OPEN, "IN PROGRESS", CLOSED'),
    ] = None,
    closed_reason: Annotated[
        str | None,
        typer.Option("--closed-reason", help="Reason for closing (required when stage=CLOSED)"),
    ] = None,
    queue: Annotated[
        str | None,
        typer.Option("--queue", help="Queue name"),
    ] = None,
    assignee: Annotated[
        str | None,
        typer.Option("--assignee", help="Assignee username"),
    ] = None,
    priority: Annotated[
        str | None,
        typer.Option("--priority", help="Priority: LOW, MEDIUM, HIGH, CRITICAL"),
    ] = None,
    tags: Annotated[
        str | None,
        typer.Option("--tags", help="Comma-separated replacement tag list (replaces all existing tags)"),
    ] = None,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Update one or more attributes of a Threat Center case.

    Supply any combination of --name, --stage, --priority, --queue,
    --assignee, and --tags. Stage transitions to CLOSED require
    --closed-reason. Tags are a replacement list (all existing tags removed).

    Valid stages: OPEN, IN PROGRESS, CLOSED
    Valid priorities: LOW, MEDIUM, HIGH, CRITICAL

    \b
    Examples:
      uv run exa cases update <case-uuid> --stage "IN PROGRESS" --assignee alice@example.com
      uv run exa cases update <case-uuid> --stage CLOSED --closed-reason "False Positive"
      uv run exa cases update <case-uuid> --priority HIGH --tags "escalated,reviewed"
    """
    from exa.case import update_case

    tag_list = [t.strip() for t in tags.split(",")] if tags else None

    if priority and priority.upper() not in _PRIORITY_VALUES:
        console.print(
            f"Invalid priority '{priority}'. Use: {', '.join(_PRIORITY_VALUES)}",
            style="red",
        )
        raise typer.Exit(1)

    client = _make_client(tenant)
    try:
        result = update_case(
            client,
            case_id,
            name=name,
            description=description,
            stage=stage,
            closed_reason=closed_reason,
            queue=queue,
            assignee=assignee,
            priority=priority.upper() if priority else None,
            tags=tag_list,
        )
        console.print("✓ Case updated", style="green")
        console.print(f"  Stage:    {result.get('stage', '')}")
        console.print(f"  Priority: {result.get('priority', '')}")
        console.print(f"  Assignee: {result.get('assignee', '')}")
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@alerts_app.command("list")
def alerts_list(
    filter: Annotated[
        str | None,
        typer.Option("--filter", "-f", help='EQL filter e.g. \'priority:"HIGH"\' or \'NOT stage:"CLOSED"\''),
    ] = None,
    lookback: Annotated[
        int,
        typer.Option("--lookback", help="Days to look back [default: 30]"),
    ] = 30,
    limit: Annotated[
        int,
        typer.Option("--limit", help="Max alerts to return [default: 50]"),
    ] = 50,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
    json_out: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Output raw JSON [default: no-json]"),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write JSON to file (default: print to terminal)"),
    ] = None,
) -> None:
    """List and search Threat Center alerts.

    Returns the most recent alerts matching the optional EQL filter. Alerts
    differ from cases: they have no stage/queue/assignee; use --filter with
    priority or alertId fields. Promote an alert to a case via the UI.

    \b
    Examples:
      uv run exa alerts list
      uv run exa alerts list --filter 'priority:"CRITICAL"' --lookback 1
      uv run exa alerts list --filter 'priority:"HIGH"' --limit 100 --json
      uv run exa alerts list --tenant csnafusion
      uv run exa alerts list --output alerts.json
    """
    from exa.case import search_alerts

    client = _make_client(tenant)
    try:
        try:
            rows = search_alerts(
                client,
                filter=filter,
                lookback_days=lookback,
                limit=limit,
            )
        except Exception as e:
            from exa.exceptions import ExaAPIError as _ExaAPIError
            if isinstance(e, _ExaAPIError) and e.status_code == 400:
                console.print(f"  Filter error (HTTP 400): {e.detail}", style="red")
                if filter:
                    console.print(_FILTER_HINT, style="dim")
                raise typer.Exit(1)
            raise
    finally:
        client.close()

    if output is not None:
        import json as _json
        output.write_text(_json.dumps(rows, indent=2), encoding="utf-8")

    if json_out:
        import json
        console.print_json(json.dumps(rows))
        return

    if output is not None:
        console.print(f"  {len(rows)} alert(s) written to {output}", style="dim")
        return

    if not rows:
        console.print("No alerts found.", style="dim")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Name", max_width=40)
    table.add_column("Priority", no_wrap=True)
    table.add_column("Risk", no_wrap=True)
    table.add_column("Case ID", no_wrap=True)
    table.add_column("Alert ID", style="dim", no_wrap=True)

    priority_colors = {
        "CRITICAL": "red",
        "HIGH": "yellow",
        "MEDIUM": "blue",
        "LOW": "green",
    }

    for row in rows:
        pri = str(row.get("priority", "")).upper()
        pri_style = priority_colors.get(pri, "")
        table.add_row(
            str(row.get("alertName", "")),
            f"[{pri_style}]{pri}[/{pri_style}]" if pri_style else pri,
            str(row.get("riskScore", "")),
            str(row.get("caseId", "")),
            str(row.get("alertId", "")),
        )

    console.print(table)
    console.print(f"\n  {len(rows)} alert(s)", style="dim")


@alerts_app.command("get")
def alerts_get(
    alert_id: Annotated[str, typer.Argument(help="Alert UUID")],
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
    json_out: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Output raw JSON [default: no-json]"),
    ] = False,
) -> None:
    """Get full details and Nova threat summary for a specific alert by UUID.

    Retrieves the alert record including priority, risk score, associated
    users, and the Nova AI threat summary. Note: the per-alert GET endpoint
    has a known defect on some tenants; this command falls back to a filtered
    search automatically.

    \b
    Examples:
      uv run exa alerts get <alert-uuid>
      uv run exa alerts get <alert-uuid> --json
      uv run exa alerts get <alert-uuid> --tenant csnafusion
    """
    import json

    from exa.case import get_alert

    client = _make_client(tenant)
    try:
        alert = get_alert(client, alert_id)

        if json_out:
            console.print_json(json.dumps(alert))
            return

        console.print(f"\n[bold]Alert: {alert.get('alertName', alert_id)}[/bold]")
        console.print(f"  ID:         {alert.get('alertId', alert_id)}")
        console.print(f"  Priority:   {alert.get('priority', '')}")
        console.print(f"  Risk Score: {alert.get('riskScore', '')}")
        console.print(f"  Case ID:    {alert.get('caseId', '')}")
        console.print(f"  Created:    {alert.get('alertCreationTimestamp', '')}")
        console.print(f"  Updated:    {alert.get('lastUpdateTimestamp', '')}")

        tags = alert.get("tags", [])
        if tags:
            console.print(f"  Tags:       {', '.join(tags)}")

        users = alert.get("users", [])
        if users:
            console.print(f"  Users:      {', '.join(str(u) for u in users)}")

        threat_summary = alert.get("threatSummary", alert.get("threat_summary", ""))
        if threat_summary:
            console.print("\n[bold]Threat Summary[/bold]")
            console.print(f"  {threat_summary}")
    finally:
        client.close()


@alerts_app.command("update")
def alerts_update(
    alert_id: Annotated[str, typer.Argument(help="Alert UUID")],
    name: Annotated[
        str | None,
        typer.Option("--name", help="New alert name"),
    ] = None,
    description: Annotated[
        str | None,
        typer.Option("--description", help="New alert description"),
    ] = None,
    priority: Annotated[
        str | None,
        typer.Option("--priority", help="Priority: LOW, MEDIUM, HIGH, CRITICAL"),
    ] = None,
    tags: Annotated[
        str | None,
        typer.Option("--tags", help="Comma-separated replacement tag list (replaces all existing tags)"),
    ] = None,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Update one or more attributes of a Threat Center alert.

    Supply any combination of --name, --priority, and --tags. Alerts do not
    have stage, queue, or assignee — those belong to cases. Tags are a
    replacement list (all existing tags removed and replaced).

    Valid priorities: LOW, MEDIUM, HIGH, CRITICAL

    \b
    Examples:
      uv run exa alerts update <alert-uuid> --priority HIGH
      uv run exa alerts update <alert-uuid> --tags "reviewed,escalated"
      uv run exa alerts update <alert-uuid> --name "Renamed Alert" --tenant csnafusion
    """
    from exa.case import update_alert

    tag_list = [t.strip() for t in tags.split(",")] if tags else None

    if priority and priority.upper() not in _PRIORITY_VALUES:
        console.print(
            f"Invalid priority '{priority}'. Use: {', '.join(_PRIORITY_VALUES)}",
            style="red",
        )
        raise typer.Exit(1)

    client = _make_client(tenant)
    try:
        result = update_alert(
            client,
            alert_id,
            name=name,
            description=description,
            priority=priority.upper() if priority else None,
            tags=tag_list,
        )
        console.print("✓ Alert updated", style="green")
        console.print(f"  Priority: {result.get('priority', '')}")
    finally:
        client.close()

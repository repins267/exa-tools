"""CLI commands for analyst case triage and qualification.

  exa case qualify <case-number>  — full qualification report
  exa case show    <case-number>  — case details + Nova summary
  exa case search                 — search cases with analyst filters
  exa case events  <case-number>  — event context around trigger
  exa case history <entity>       — entity's prior cases
"""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

case_app = typer.Typer(
    name="case",
    help="Analyst triage and case qualification.",
    no_args_is_help=True,
)

console = Console()

_TENANT_HELP = "Tenant nickname or FQDN (default: saved default)"

_VERDICT_STYLES = {
    "SUSPECTED_INCIDENT": ("red", "⚠"),
    "LIKELY_FP": ("green", "✓"),
    "LEARNING_PHASE_NOISE": ("yellow", "~"),
    "NEEDS_INVESTIGATION": ("yellow", "?"),
}


def _make_client(tenant: str | None = None):
    from exa.client import ExaClient

    client = ExaClient(tenant=tenant)
    client.authenticate()
    return client


# ---------------------------------------------------------------------------
# qualify
# ---------------------------------------------------------------------------


@case_app.command("qualify")
def qualify(
    case_number: Annotated[str, typer.Argument(help="Case number (e.g. 221)")],
    lookback: Annotated[
        int,
        typer.Option("--lookback", help="Days to search for prior entity cases"),
    ] = 30,
    window: Annotated[
        int,
        typer.Option("--window", help="Minutes around trigger to search events"),
    ] = 30,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Run full qualification analysis on a case. Outputs structured triage report."""
    from exa.case.qualify import run_qualification

    client = _make_client(tenant)
    try:
        with console.status(f"  Qualifying case {case_number}..."):
            report = run_qualification(
                client,
                case_number,
                lookback_days=lookback,
                event_window_minutes=window,
            )
    finally:
        client.close()

    _print_qualification_report(report)


def _print_qualification_report(report) -> None:
    from exa.case.qualify import QualificationReport

    r: QualificationReport = report
    style, icon = _VERDICT_STYLES.get(r.verdict, ("white", "?"))

    # Summary table
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", no_wrap=True)
    grid.add_column()

    score_line = str(r.risk_score)
    if r.score_delta is not None:
        score_line += f"  (trend: {r.score_trend}, delta {r.score_delta:+d} vs prior median)"
    else:
        score_line += f"  (trend: {r.score_trend})"

    grid.add_row("Risk Score", score_line)
    grid.add_row("Rule", r.rule_name or "(unknown)")
    grid.add_row("Rule Type", f"{r.rule_trigger_type}" + (
        f"  [{r.rule_threshold_desc}]" if r.rule_threshold_desc else ""
    ))
    if r.rule_group_by:
        grid.add_row("Rule Grouped", ", ".join(r.rule_group_by))
    grid.add_row("Entity", f"{r.entity_name}  ({r.entity_type})" if r.entity_name else "(unknown)")
    grid.add_row(
        "Context Tables",
        ", ".join(r.entity_in_context_tables) if r.entity_in_context_tables else "(none matched)",
    )
    prior_label = f"{r.prior_cases_30d} in last 30 days"
    if r.prior_scores:
        prior_label += f"  [scores: {', '.join(str(s) for s in r.prior_scores)}]"
    grid.add_row("Prior Cases", prior_label)

    console.print(Panel(grid, title=f"CASE {r.case_number} — Qualification Report", expand=True))

    # Nova summary
    if r.nova_summary:
        console.print(Panel(r.nova_summary, title="Nova Threat Summary", style="cyan"))

    # Event context
    context_table = Table.grid(padding=(0, 2))
    context_table.add_column(style="dim", no_wrap=True)
    context_table.add_column()
    context_table.add_row("Events ±window", str(r.event_context_count))

    if r.external_ips:
        for i, ip_info in enumerate(r.external_ips):
            label = f"{ip_info['ip']} ({ip_info['label']})"
            if ip_info.get("port_count"):
                label += f" — {ip_info['port_count']} distinct ports"
            context_table.add_row("External IPs" if i == 0 else "", label)
    else:
        context_table.add_row("External IPs", "(none detected)")

    console.print(Panel(context_table, title="Event Context", expand=True))

    # Verdict
    verdict_lines = [f"[bold {style}]{icon}  {r.verdict}[/bold {style}]", ""]
    for reason in r.verdict_reasons:
        verdict_lines.append(f"  • {reason}")
    verdict_lines.append("")
    verdict_lines.append(f"  [dim]Recommend:[/dim] {r.recommended_action}")

    console.print(Panel("\n".join(verdict_lines), title="VERDICT", border_style=style))


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


@case_app.command("show")
def show(
    case_number: Annotated[str, typer.Argument(help="Case number")],
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Show case details and Nova threat summary."""
    from exa.case.cases import search_cases

    client = _make_client(tenant)
    try:
        rows = search_cases(client, filter=f'caseNumber:"{case_number}"', limit=1)
        if not rows:
            console.print(f"Case {case_number!r} not found.", style="red")
            raise typer.Exit(1)
        case = rows[0]
    finally:
        client.close()

    console.print(f"\n[bold]Case {case.get('caseNumber', case_number)}[/bold]")
    console.print(f"  ID:          {case.get('caseId', '')}")
    console.print(f"  Name:        {case.get('alertName', '')}")
    console.print(f"  Stage:       {case.get('stage', '')}")
    console.print(f"  Priority:    {case.get('priority', '')}")
    console.print(f"  Risk Score:  {case.get('riskScore', '')}")
    console.print(f"  Assignee:    {case.get('assignee', '')}")
    console.print(f"  Created:     {case.get('caseCreationTimestamp', '')}")

    users = case.get("users") or []
    if users:
        console.print(f"  Users:       {', '.join(str(u) for u in users)}")

    endpoints = case.get("endpoints") or []
    if endpoints:
        console.print(f"  Endpoints:   {', '.join(str(e) for e in endpoints)}")

    nova = case.get("threatSummary") or case.get("threat_summary", "")
    if nova:
        console.print(Panel(nova, title="Nova Threat Summary", style="cyan"))


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------


@case_app.command("search")
def search(
    rule: Annotated[
        str | None,
        typer.Option("--rule", "-r", help="Filter by rule name (substring)"),
    ] = None,
    entity: Annotated[
        str | None,
        typer.Option("--entity", "-e", help="Filter by entity (user or hostname)"),
    ] = None,
    stage: Annotated[
        str | None,
        typer.Option("--stage", "-s", help='Filter by stage, e.g. "OPEN", "CLOSED"'),
    ] = None,
    lookback: Annotated[
        int,
        typer.Option("--lookback", help="Days to look back (default 7)"),
    ] = 7,
    limit: Annotated[
        int,
        typer.Option("--limit", help="Max results (default 20)"),
    ] = 20,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Search cases with analyst-friendly filters."""
    from exa.case.cases import search_cases

    # Build EQL filter
    clauses: list[str] = []
    if rule:
        clauses.append(f'alertName:WLDi("*{rule}*")')
    if entity:
        clauses.append(f'users:"{entity}"')
    if stage:
        clauses.append(f'stage:"{stage.upper()}"')
    eql_filter = " AND ".join(clauses) if clauses else None

    client = _make_client(tenant)
    try:
        rows = search_cases(client, filter=eql_filter, lookback_days=lookback, limit=limit)
    finally:
        client.close()

    if not rows:
        console.print("No cases found.", style="dim")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Case #", style="cyan", no_wrap=True)
    table.add_column("Rule/Name", max_width=40)
    table.add_column("Stage", no_wrap=True)
    table.add_column("Risk", no_wrap=True)
    table.add_column("Entity", no_wrap=True)

    for row in rows:
        users = row.get("users") or []
        entity_display = users[0] if users else ""
        risk = str(row.get("riskScore", ""))
        table.add_row(
            str(row.get("caseNumber", "")),
            str(row.get("alertName", "")),
            str(row.get("stage", "")),
            risk,
            entity_display,
        )

    console.print(table)
    console.print(f"\n  {len(rows)} result(s)", style="dim")


# ---------------------------------------------------------------------------
# events
# ---------------------------------------------------------------------------


@case_app.command("events")
def events(
    case_number: Annotated[str, typer.Argument(help="Case number")],
    window: Annotated[
        int,
        typer.Option("--window", help="Minutes around trigger (default 30)"),
    ] = 30,
    limit: Annotated[
        int,
        typer.Option("--limit", help="Max events (default 100)"),
    ] = 100,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Pull event context ±window minutes around a case trigger."""
    from datetime import timedelta

    from exa.case.cases import search_cases
    from exa.search.events import search_events

    client = _make_client(tenant)
    try:
        rows = search_cases(client, filter=f'caseNumber:"{case_number}"', limit=1)
        if not rows:
            console.print(f"Case {case_number!r} not found.", style="red")
            raise typer.Exit(1)
        case = rows[0]

        from datetime import UTC, datetime

        trigger_str = case.get("caseCreationTimestamp", "")
        try:
            t = datetime.fromisoformat(trigger_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            t = datetime.now(UTC)

        users = case.get("users") or []
        entity = users[0] if users else ""
        eql = f'user:"{entity}"' if entity else "*"

        events_rows = search_events(
            client,
            eql,
            fields=["user", "src_ip", "dest_ip", "dest_port", "activity_type", "action"],
            start_time=t - timedelta(minutes=window),
            end_time=t + timedelta(minutes=window),
            limit=limit,
        )
    finally:
        client.close()

    if not isinstance(events_rows, list) or not events_rows:
        console.print("No events found in window.", style="dim")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Activity Type", no_wrap=True)
    table.add_column("User", no_wrap=True)
    table.add_column("Src IP", no_wrap=True)
    table.add_column("Dest IP", no_wrap=True)
    table.add_column("Dest Port", no_wrap=True)
    table.add_column("Action", no_wrap=True)

    for row in events_rows:
        table.add_row(
            str(row.get("activity_type", "")),
            str(row.get("user", "")),
            str(row.get("src_ip", "")),
            str(row.get("dest_ip", "")),
            str(row.get("dest_port", "")),
            str(row.get("action", "")),
        )

    console.print(table)
    console.print(f"\n  {len(events_rows)} event(s) within ±{window} min of trigger", style="dim")


# ---------------------------------------------------------------------------
# history
# ---------------------------------------------------------------------------


@case_app.command("history")
def history(
    entity: Annotated[str, typer.Argument(help="Username or hostname")],
    lookback: Annotated[
        int,
        typer.Option("--lookback", help="Days to look back (default 30)"),
    ] = 30,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Show all cases for a specific entity in the lookback period."""
    from exa.case.entities import get_entity_cases

    client = _make_client(tenant)
    try:
        cases = get_entity_cases(client, entity, lookback_days=lookback)
    finally:
        client.close()

    if not cases:
        console.print(f"No cases found for {entity!r} in last {lookback} days.", style="dim")
        return

    table = Table(show_header=True, header_style="bold", title=f"Cases — {entity}")
    table.add_column("Case #", style="cyan", no_wrap=True)
    table.add_column("Rule/Name", max_width=40)
    table.add_column("Stage", no_wrap=True)
    table.add_column("Risk", no_wrap=True, justify="right")
    table.add_column("Created", no_wrap=True)

    for case in cases:
        table.add_row(
            str(case.get("caseNumber", "")),
            str(case.get("alertName", "")),
            str(case.get("stage", "")),
            str(case.get("riskScore", "")),
            str(case.get("caseCreationTimestamp", ""))[:10],
        )

    console.print(table)
    scores = [int(c.get("riskScore") or 0) for c in cases]
    console.print(f"\n  {len(cases)} case(s) | scores: {scores}", style="dim")

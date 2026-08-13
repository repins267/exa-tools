"""Health CLI commands -- licence entitlement and consumption.

The API reports consumption and entitlement side by side and never flags the
case that matters: consumption OVER entitlement returns HTTP 200 with no marker
of any kind. So this module does the comparison and says so loudly, because
"here are two numbers" is not an answer anyone acts on.
"""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

health_app = typer.Typer(
    name="health",
    help="Licence entitlement, consumption and platform uptime.",
    no_args_is_help=True,
)
console = Console()

_TENANT_HELP = "Tenant nickname or FQDN [default: saved default]"


def _make_client(tenant: str | None = None):
    from exa.client import ExaClient

    client = ExaClient(tenant=tenant)
    client.authenticate()
    return client


@health_app.command("license")
def license_cmd(
    days: Annotated[
        int,
        typer.Option("--days", help="Days of ingest history to show [default: 14]"),
    ] = 14,
    json_out: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Emit JSON to stdout [default: no-json]"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Show licence entitlement against actual consumption.

    READ-ONLY. Covers three separate entitlements, each with its own endpoint:
    log ingestion (GB/day), long-term search volume, and correlation rules.

    \b
    The API returns HTTP 200 whether a tenant is under or over its entitlement
    and marks the difference in no way at all, so being over licence is invisible
    unless the two numbers are compared. This command compares them and exits 1
    if any entitlement is exceeded, so it is usable in a scheduled check.

    \b
    Examples:
      uv run exa health license --tenant baystate
      uv run exa health license --days 30 --tenant baystate
      uv run exa health license --json --tenant baystate
    """
    import json as _json

    from exa.health.consumption import (
        get_correlation_rule_count,
        get_license_details,
        get_lts_consumption,
    )

    client = _make_client(tenant)
    try:
        lic = get_license_details(client)
        lts = get_lts_consumption(client)
        rules = get_correlation_rule_count(client)
    finally:
        client.close()

    ingest = lic.get("logIngestionDetails", lic)
    entitled = float(ingest.get("entitledIngestGbPerDay") or 0)
    today = float(ingest.get("consumedIngestGbForToday") or 0)
    history = ingest.get("historicalLogIngestionInGb") or []

    lts_used = float(lts.get("totalLTSearchVolumeUsed") or 0)
    lts_lic = float(lts.get("totalLTSearchVolumeLicensed") or 0)
    rules_used = int(rules.get("totalRuleUsed") or 0)
    rules_lic = int(rules.get("totalRuleLicensed") or 0)

    over_days = [d for d in history if float(d.get("ingestGb") or 0) > entitled] if entitled else []
    breaches = []
    if entitled and today > entitled:
        breaches.append("log ingestion")
    if lts_lic and lts_used > lts_lic:
        breaches.append("long-term search")
    if rules_lic and rules_used > rules_lic:
        breaches.append("correlation rules")

    if json_out:
        console.print_json(
            _json.dumps(
                {
                    "ingest": {
                        "entitled_gb_per_day": entitled,
                        "consumed_today_gb": today,
                        "over_today": bool(entitled and today > entitled),
                        "days_over_in_history": len(over_days),
                        "history": history[:days],
                    },
                    "long_term_search": {"used_gb": lts_used, "licensed_gb": lts_lic},
                    "correlation_rules": {"used": rules_used, "licensed": rules_lic},
                    "breaches": breaches,
                }
            )
        )
        raise typer.Exit(1 if breaches else 0)

    console.rule("Licence vs consumption")

    tbl = Table(show_header=True, header_style="bold")
    tbl.add_column("Entitlement", style="cyan", no_wrap=True)
    tbl.add_column("Licensed", justify="right")
    tbl.add_column("Used", justify="right")
    tbl.add_column("Status")

    def _row(name: str, licensed: float, used: float, unit: str) -> None:
        if not licensed:
            tbl.add_row(name, "-", f"{used:,.0f}{unit}", "[dim]not licensed[/]")
            return
        pct = used / licensed * 100
        style = "red" if used > licensed else ("yellow" if pct >= 80 else "green")
        state = "OVER" if used > licensed else f"{pct:.0f}%"
        tbl.add_row(name, f"{licensed:,.0f}{unit}", f"{used:,.0f}{unit}", f"[{style}]{state}[/]")

    _row("Log ingestion (today)", entitled, today, " GB")
    _row("Long-term search", lts_lic, lts_used, " GB")
    _row("Correlation rules", rules_lic, rules_used, "")
    console.print(tbl)

    if history:
        console.print(f"\n  Daily ingest, last {min(days, len(history))} day(s):", style="bold")
        for d in history[:days]:
            gb = float(d.get("ingestGb") or 0)
            over = entitled and gb > entitled
            console.print(
                f"    {d.get('date')}  {gb:8,.1f} GB"
                + (f"   [red]+{gb - entitled:,.1f} over[/]" if over else ""),
                style="red" if over else "dim",
            )

    if over_days:
        console.print(
            f"\n  {len(over_days)} of {len(history)} day(s) in history exceeded the "
            f"{entitled:,.0f} GB/day entitlement.",
            style="red",
        )

    if breaches:
        console.print(
            f"\n  OVER LICENCE: {', '.join(breaches)}.\n"
            "  The API reports this with HTTP 200 and no marker -- it is only "
            "visible by comparing\n  the two numbers, which is why nothing alerts "
            "on it.",
            style="red",
        )
        raise typer.Exit(1)
    console.print("\n  Within entitlement on all three.", style="green")


@health_app.command("uptime")
def uptime_cmd(
    json_out: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Emit JSON to stdout [default: no-json]"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Show per-application uptime and outage history.

    READ-ONLY.

    \b
    Examples:
      uv run exa health uptime --tenant baystate
      uv run exa health uptime --json --tenant baystate
    """
    import json as _json
    from collections import defaultdict

    from exa.health.consumption import get_app_status

    client = _make_client(tenant)
    try:
        rows = get_app_status(client)
    finally:
        client.close()

    if json_out:
        console.print_json(_json.dumps(rows))
        return

    agg: dict[str, list[float]] = defaultdict(list)
    outages: dict[str, int] = defaultdict(int)
    for r in rows:
        name = r.get("applicationName") or "-"
        agg[name].append(float(r.get("uptimeValue") or 0))
        outages[name] += int(r.get("majorOutageInSeconds") or 0)

    console.rule("Application uptime")
    tbl = Table(show_header=True, header_style="bold")
    tbl.add_column("Application", style="cyan", no_wrap=True)
    tbl.add_column("Days", justify="right")
    tbl.add_column("Mean uptime", justify="right")
    tbl.add_column("Major outage")
    for name, vals in sorted(agg.items()):
        mean = sum(vals) / len(vals) * 100
        secs = outages[name]
        tbl.add_row(
            name,
            str(len(vals)),
            f"[{'green' if mean >= 99.9 else 'yellow' if mean >= 99 else 'red'}]{mean:.2f}%[/]",
            f"{secs:,}s" if secs else "-",
        )
    console.print(tbl)

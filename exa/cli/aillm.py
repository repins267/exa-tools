"""AI/LLM CLI commands -- sync, sync-ruleset, and status.

Commands:
  exa aillm sync           -- Sync 6 AI/LLM context tables from reference data
  exa aillm sync-ruleset   -- Sync 'AI/LLM DLP Rulesets' from live alert history
  exa aillm status         -- Show live record counts for all 6 tables
"""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

aillm_app = typer.Typer(
    name="aillm",
    help="AI/LLM context table sync and status.",
    no_args_is_help=True,
)
console = Console()

_TENANT_HELP = "Tenant nickname or FQDN [default: saved default]"


def _make_client(tenant: str | None = None):
    """Create and authenticate an ExaClient from keyring."""
    from exa.client import ExaClient

    client = ExaClient(tenant=tenant)
    client.authenticate()
    return client


# -- sync ---------------------------------------------------------------------


@aillm_app.command("sync")
def sync_cmd(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview changes without writing to Exabeam"),
    ] = False,
    force: Annotated[
        bool,
        typer.Option("--force", help="Replace existing records instead of append"),
    ] = False,
    discover_from_logs: Annotated[
        bool,
        typer.Option(
            "--discover-from-logs",
            help="Query proxy/web logs for additional AI domains seen in your environment",
        ),
    ] = False,
    lookback: Annotated[
        int,
        typer.Option(
            "--lookback",
            help="Days to look back when discovering domains from logs [default: 30]",
        ),
    ] = 30,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Sync AI/LLM context tables from bundled reference data.

    Populates all 6 Exabeam AI/LLM context tables from the bundled
    reference dataset (596 records). Use --dry-run to preview first.
    Use --discover-from-logs to augment with AI domains actively seen
    in your environment's proxy/web logs.

    \b
    Examples:
      uv run exa aillm sync
      uv run exa aillm sync --dry-run
      uv run exa aillm sync --force
      uv run exa aillm sync --discover-from-logs --lookback 60 --tenant csnafusion
    """
    from exa.aillm import sync_aillm_context_tables

    client = _make_client(tenant)
    try:
        discovered_domains: list[str] | None = None

        if discover_from_logs:
            from exa.aillm.discover import search_logs_for_ai_domains

            console.print(
                f"Discovering domains from proxy/web logs "
                f"(lookback: {lookback} days)...",
                style="dim",
            )
            discovered_domains = search_logs_for_ai_domains(
                client, lookback_days=lookback
            )
            console.print(
                f"  Found {len(discovered_domains)} distinct domains in logs",
                style="dim",
            )

        sync_aillm_context_tables(
            client,
            discovered_domains=discovered_domains,
            force=force,
            dry_run=dry_run,
        )
    finally:
        client.close()


# -- sync-ruleset -------------------------------------------------------------


@aillm_app.command("sync-ruleset")
def sync_ruleset_cmd(
    lookback: Annotated[
        int,
        typer.Option(
            "--lookback",
            help="Days to search back for alert names [default: 90]",
        ),
    ] = 90,
    keywords: Annotated[
        str | None,
        typer.Option(
            "--keywords",
            help=(
                "Comma-separated keywords to filter alert names "
                "(default: built-in AI/LLM keyword list)"
            ),
        ),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", help="Max alerts to pull from Threat Center [default: 3000]"),
    ] = 3000,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview matched names without writing"),
    ] = False,
    force: Annotated[
        bool,
        typer.Option("--force", help="Replace all existing records instead of append"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Sync 'AI/LLM DLP Rulesets' table from live alert history.

    Pulls real Exabeam alert names from the Threat Center, filters for
    AI/LLM-related names, and writes them to the 'AI/LLM DLP Rulesets'
    context table. This makes the Looker/BigQuery AI/LLM dashboard tiles
    show data (they filter alert_name against this table).

    Run once per tenant after AI/LLM correlation rules are active.
    Use --dry-run to preview what would be added first.

    \b
    Examples:
      uv run exa aillm sync-ruleset --tenant csnafusion
      uv run exa aillm sync-ruleset --dry-run --tenant csnafusion
      uv run exa aillm sync-ruleset --lookback 180 --tenant csnafusion
      # Multiple tenants
      uv run exa aillm sync-ruleset -t tenant1 && uv run exa aillm sync-ruleset -t tenant2
    """
    from exa.aillm.ruleset import sync_dlp_ruleset

    kw_list: list[str] | None = None
    if keywords:
        kw_list = [k.strip() for k in keywords.split(",") if k.strip()]

    prefix = "[DRY RUN] " if dry_run else ""
    console.rule(f"{prefix}AI/LLM DLP Ruleset Sync")

    client = _make_client(tenant)
    try:
        result = sync_dlp_ruleset(
            client,
            lookback_days=lookback,
            keywords=kw_list,
            limit=limit,
            dry_run=dry_run,
            force=force,
        )
    finally:
        client.close()

    console.rule("Result", style="dim")
    console.print(f"  Alerts searched:   {result.alerts_searched}")
    console.print(f"  Unique names:      {result.alert_names_found}")
    console.print(f"  AI/LLM matched:    {result.keyword_matched}")
    if not dry_run:
        console.print(f"  Already present:   {result.already_present}")
        console.print(f"  Upserted:          {result.upserted}")

    if result.error:
        console.print(f"\n  x {result.error}", style="red")
        raise typer.Exit(1)
    elif result.keyword_matched == 0:
        console.print(
            "\n  No AI/LLM alert names found -- "
            "try --lookback 180 or --keywords to broaden the search.",
            style="yellow",
        )
    else:
        console.print("\n  Done", style="green")


# -- discover -----------------------------------------------------------------


@aillm_app.command("discover")
def discover_cmd(
    lookback: Annotated[
        int,
        typer.Option(
            "--lookback",
            help="Days to look back for alerts and proxy events [default: 30]",
        ),
    ] = 30,
    alert_limit: Annotated[
        int,
        typer.Option("--alert-limit", help="Max alerts to pull from Threat Center [default: 3000]"),
    ] = 3000,
    event_limit: Annotated[
        int,
        typer.Option(
            "--event-limit",
            help="Max proxy/agent events to pull per product query [default: 10000]",
        ),
    ] = 10000,
    add_rulesets: Annotated[
        bool,
        typer.Option(
            "--add-rulesets/--no-add-rulesets",
            help="Write matched alert names to AI/LLM DLP Rulesets table [default: no-add-rulesets]",
        ),
    ] = False,
    add_apps: Annotated[
        bool,
        typer.Option(
            "--add-apps/--no-add-apps",
            help="Write discovered app names to AI/LLM Applications table [default: no-add-apps]",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Output as JSON [default: no-json]"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Discover AI-related activity for context table enrichment.

    Runs two discovery passes and reports new candidates:

    \b
    Pass 1 -- Threat Center alert names:
      Pulls recent alerts, filters for AI/LLM keywords, and identifies
      names not yet in the bundled DLP reference data.

    \b
    Pass 2 -- AI proxy/agent app names:
      Queries for SentinelOne Prompt Security events (and similar) and
      extracts distinct application names actively seen in this environment.

    \b
    Use --add-rulesets / --add-apps to write candidates to their context tables.
    For web domain discovery, use: exa aillm sync --discover-from-logs

    \b
    Examples:
      uv run exa aillm discover --tenant csnafusion
      uv run exa aillm discover --lookback 60 --add-apps
      uv run exa aillm discover --json --tenant csnafusion
    """
    import json as json_mod

    from exa.aillm.discover_alerts import discover_ai_activity

    client = _make_client(tenant)
    try:
        if not json_output:
            console.rule("AI/LLM Activity Discovery")
            console.print(
                f"  Lookback: {lookback} days | "
                f"Alert limit: {alert_limit} | "
                f"Event limit: {event_limit}",
                style="dim",
            )
        result = discover_ai_activity(
            client,
            lookback_days=lookback,
            alert_limit=alert_limit,
            event_limit=event_limit,
            add_rulesets=add_rulesets,
            add_apps=add_apps,
        )
    finally:
        client.close()

    if json_output:
        import dataclasses

        console.print(json_mod.dumps(dataclasses.asdict(result), indent=2))
        return

    # -- Threat Center alert names -------------------------------------------
    console.rule("Pass 1: Threat Center Alert Names", style="dim")
    console.print(
        f"  Alerts searched: {result.alerts_searched} | "
        f"Unique names: {result.alert_names_found} | "
        f"AI-matched: {len(result.alert_names_matched)}"
    )
    if result.alert_names_new:
        console.print(
            f"\n  [yellow]{len(result.alert_names_new)} new DLP ruleset candidates[/yellow] "
            f"(not in bundled reference data):"
        )
        for name in result.alert_names_new:
            prefix = "  + " if add_rulesets else "  * "
            console.print(f"    {prefix}{name}")
        if add_rulesets:
            console.print(
                f"\n  Written to '{_RULESETS_LABEL}': {result.rulesets_written}",
                style="green",
            )
        else:
            console.print(
                "\n  Tip: re-run with --add-rulesets to write these to the DLP Rulesets table.",
                style="dim",
            )
    elif result.alert_names_matched:
        console.print(
            f"  All {len(result.alert_names_matched)} matched names already in reference data.",
            style="dim",
        )
    else:
        console.print(
            "  No AI/LLM alert names found. Try --lookback 90 or check that "
            "AI/LLM rules are enabled.",
            style="yellow",
        )

    # -- AI proxy/agent app names --------------------------------------------
    console.rule("Pass 2: AI Proxy/Agent App Names", style="dim")
    console.print(f"  Proxy/agent events searched: {result.proxy_events_searched}")
    if result.proxy_events_searched == 0:
        console.print(
            "  No SentinelOne Prompt Security events found in this window.\n"
            "  This pass requires a Prompt Security integration sending events to Exabeam.",
            style="yellow",
        )
    elif result.app_names_found:
        console.print(f"  App names found: {len(result.app_names_found)}")
        if result.app_names_new:
            console.print(
                f"\n  [yellow]{len(result.app_names_new)} new application candidates[/yellow] "
                f"(not in bundled reference data):"
            )
            for name in result.app_names_new:
                prefix = "  + " if add_apps else "  * "
                console.print(f"    {prefix}{name}")
            if add_apps:
                console.print(
                    f"\n  Written to 'AI/LLM Applications': {result.apps_written}",
                    style="green",
                )
            else:
                console.print(
                    "\n  Tip: re-run with --add-apps to write these to the Applications table.",
                    style="dim",
                )
        else:
            console.print(
                "  All app names already in reference data.",
                style="dim",
            )
    else:
        console.print(
            "  Events found but no app names extracted.\n"
            "  The `app` CIM2 field may not be populated for this data source.",
            style="yellow",
        )

    # -- Errors --------------------------------------------------------------
    if result.errors:
        console.print()
        for err in result.errors:
            console.print(f"  [red]x[/red] {err}")
        raise typer.Exit(1)


_RULESETS_LABEL = "AI/LLM DLP Rulesets"


# -- status -------------------------------------------------------------------


@aillm_app.command("status")
def status_cmd(
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Show live record counts for all 6 AI/LLM context tables.

    Fetches the current record counts from Exabeam and displays a status
    table. Tables showing "-" have not been synced yet — run 'exa aillm sync'
    to populate them.

    \b
    Examples:
      uv run exa aillm status
      uv run exa aillm status --tenant csnafusion
    """
    from exa.aillm.status import get_aillm_table_status

    client = _make_client(tenant)
    try:
        statuses = get_aillm_table_status(client)

        tbl = Table(show_header=True, header_style="bold")
        tbl.add_column("Table", style="cyan", no_wrap=True)
        tbl.add_column("Records", justify="right")
        tbl.add_column("Last Synced", style="dim")

        total = 0
        for s in statuses:
            if not s.found:
                tbl.add_row(s.table_name, "-", "Not found", style="dim")
            else:
                tbl.add_row(
                    s.table_name,
                    str(s.record_count),
                    s.last_updated,
                )
                total += s.record_count

        console.print(tbl)
        console.print(f"\n  Total records: {total}", style="dim")
    finally:
        client.close()

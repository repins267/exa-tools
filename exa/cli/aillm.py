"""AI/LLM CLI commands -- sync, sync-ruleset, discover, and status.

Commands:
  exa aillm sync           -- Sync 6 AI/LLM context tables from reference data
  exa aillm sync-ruleset   -- Sync 'AI/LLM DLP Rulesets' from live alert history
  exa aillm discover       -- Discover AI activity candidates for context tables
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
    risk_override: Annotated[
        str | None,
        typer.Option(
            "--risk-override",
            help=(
                "Path to a JSON file mapping domain -> risk level "
                '(e.g. {"all-hands.dev": "medium"}). '
                "Overrides the bundled risk rating for matching domains."
            ),
        ),
    ] = None,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Sync AI/LLM context tables from bundled reference data.

    Populates all 6 Exabeam AI/LLM context tables from the bundled
    reference dataset. Use --dry-run to preview first.
    Use --discover-from-logs to augment with AI domains actively seen
    in your environment's proxy/web logs.
    Use --risk-override to adjust risk ratings before syncing.

    \b
    Examples:
      exa aillm sync
      exa aillm sync --dry-run
      exa aillm sync --force
      exa aillm sync --discover-from-logs --lookback 60 --tenant csnafusion
      exa aillm sync --risk-override overrides.json --tenant csnafusion
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
            risk_override_path=risk_override,
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
            help="Write matched alert names to AI/LLM DLP Rulesets "
            "[default: no-add-rulesets]",
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


@aillm_app.command("validate")
def validate_cmd(
    lookback: Annotated[
        int,
        typer.Option("--lookback", help="Days of tenant history to sample [default: 30]"),
    ] = 30,
    refresh: Annotated[
        bool,
        typer.Option(
            "--refresh/--no-refresh",
            help="Re-collect the tenant profile instead of using today's cache "
            "[default: no-refresh]",
        ),
    ] = False,
    json_out: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Output as JSON [default: no-json]"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Verify AI/LLM context tables match values the tenant actually emits.

    Record count is not a health signal. A table can hold hundreds of entries,
    report Healthy, and match nothing -- silently starving every analytics rule
    that reads it via ContextListContains(). This measures real overlap.

    \b
    Status meanings:
      OK    -- entries match live values
      WEAK  -- few matches for the table size (often registered-domain vs host)
      DEAD  -- zero overlap; rules reading this table cannot fire
      EMPTY -- table has no records

    Exits non-zero if any rule-backed table is DEAD.

    \b
    Examples:
      uv run exa aillm validate --tenant geha
      uv run exa aillm validate --refresh --json --tenant geha
    """
    import json as _json

    from exa.aillm.profile import collect_tenant_profile
    from exa.aillm.validate import (
        STATUS_DEAD,
        STATUS_OK,
        STATUS_WEAK,
        has_dead_tables,
        validate_aillm_tables,
    )

    client = _make_client(tenant)
    try:
        profile = collect_tenant_profile(
            client, lookback_days=lookback, refresh=refresh
        )
        results = validate_aillm_tables(client, profile=profile)

        if json_out:
            console.print_json(
                _json.dumps(
                    {
                        "tenant": profile.tenant,
                        "collected_at": profile.collected_at,
                        "api_calls": profile.api_calls,
                        "tables": [
                            {
                                "table": r.table_name,
                                "records": r.records,
                                "live_field": r.live_field,
                                "live_values": r.live_values,
                                "overlap": r.overlap,
                                "status": r.status,
                                "read_by_rules": r.read_by_rules,
                                "note": r.note,
                            }
                            for r in results
                        ],
                    }
                )
            )
        else:
            tbl = Table(show_header=True, header_style="bold")
            tbl.add_column("Table", style="cyan", no_wrap=True)
            tbl.add_column("Records", justify="right")
            tbl.add_column("Live Field", style="dim")
            tbl.add_column("Live Values", justify="right")
            tbl.add_column("Overlap", justify="right")
            tbl.add_column("Rules", justify="center")
            tbl.add_column("Status")

            colours = {STATUS_OK: "green", STATUS_WEAK: "yellow", STATUS_DEAD: "red"}
            for r in results:
                tbl.add_row(
                    r.table_name,
                    str(r.records),
                    r.live_field,
                    str(r.live_values),
                    str(r.overlap),
                    "yes" if r.read_by_rules else "-",
                    f"[{colours.get(r.status, 'dim')}]{r.status}[/]",
                )
            console.print(tbl)

            for r in results:
                if r.note:
                    console.print(f"  {r.table_name}: {r.note}", style="dim")

            console.print(
                f"\n  Profile: {profile.api_calls} API call(s) this run "
                f"(0 = served from cache)",
                style="dim",
            )

        if has_dead_tables(results):
            console.print(
                "\n  One or more rule-backed tables are DEAD -- "
                "analytics rules reading them cannot fire.",
                style="red",
            )
            raise typer.Exit(code=1)
    finally:
        client.close()


@aillm_app.command("rules")
def rules_cmd(
    lookback: Annotated[
        int,
        typer.Option("--lookback", help="Days of tenant history to sample [default: 30]"),
    ] = 30,
    refresh: Annotated[
        bool,
        typer.Option("--refresh/--no-refresh", help="Re-collect the tenant profile "
                     "[default: no-refresh]"),
    ] = False,
    show_blocked: Annotated[
        bool,
        typer.Option("--show-blocked/--no-show-blocked",
                     help="List each blocked rule by name [default: show-blocked]"),
    ] = True,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Show which AI analytics rules can fire against this tenant's data.

    Every rule declares requiredFields. A rule whose required fields are absent
    or unpopulated is enabled, Active, and silently unable to fire. This compares
    declared requirements against the observed field inventory.

    Rules blocked ONLY by agent-only fields (llm_request, llm_response,
    ai_token_*, ai_function_name) are called out separately -- no proxy, DLP or
    context table can populate those. That set is the agent-telemetry case.

    \b
    Examples:
      uv run exa aillm rules --tenant geha
      uv run exa aillm rules --refresh --tenant geha
    """
    from exa.aillm.profile import collect_tenant_profile
    from exa.aillm.rules import analyze_ai_rules

    client = _make_client(tenant)
    try:
        profile = collect_tenant_profile(client, lookback_days=lookback, refresh=refresh)
        rep = analyze_ai_rules(client, profile=profile)

        console.print(f"\n  Analytics rules on tenant : {rep.total_rules}")
        console.print(f"  AI-scoped                 : {rep.ai_rules}")
        console.print(
            f"  Enabled / disabled        : {rep.enabled} / {rep.disabled}"
        )
        console.print(f"  [green]Reachable today           : {len(rep.reachable)}[/]")
        console.print(f"  [red]Blocked                   : {len(rep.blocked)}[/]")

        if rep.blockers:
            tbl = Table(show_header=True, header_style="bold", title="Blocking fields")
            tbl.add_column("Missing field", style="cyan")
            tbl.add_column("Rules blocked", justify="right")
            tbl.add_column("Agent-only", justify="center")
            from exa.aillm.rules import AGENT_ONLY_FIELDS

            for fname, names in rep.blockers.items():
                tbl.add_row(
                    fname,
                    str(len(names)),
                    "yes" if fname in AGENT_ONLY_FIELDS else "-",
                )
            console.print()
            console.print(tbl)

        agent_blocked = rep.agent_blocked
        if agent_blocked:
            console.print(
                f"\n  [yellow]{len(agent_blocked)} rule(s) are blocked solely by "
                f"agent-only telemetry.[/]"
            )
            console.print(
                "  No proxy, DLP or context table can populate those fields.",
                style="dim",
            )

        if show_blocked and rep.blocked:
            console.print("\n  Blocked rules:", style="dim")
            for r in rep.blocked:
                console.print(
                    f"    {r.name[:72]}", style="dim"
                )
                console.print(
                    f"      missing: {', '.join(r.missing_fields)}", style="dim"
                )

        if rep.context_consumers:
            console.print("\n  Context tables consumed by rules:", style="dim")
            for table_name, names in rep.context_consumers.items():
                console.print(f"    {table_name}: {len(names)} rule(s)", style="dim")

        console.print(
            f"\n  Profile: {profile.api_calls} API call(s) this run "
            f"(0 = served from cache)",
            style="dim",
        )
    finally:
        client.close()


@aillm_app.command("risk")
def risk_cmd(
    lookback: Annotated[
        int,
        typer.Option("--lookback", help="Days of tenant history to sample [default: 30]"),
    ] = 30,
    refresh: Annotated[
        bool,
        typer.Option("--refresh/--no-refresh", help="Re-collect the tenant profile "
                     "[default: no-refresh]"),
    ] = False,
    show_unlisted: Annotated[
        bool,
        typer.Option("--show-unlisted/--no-show-unlisted",
                     help="List AI-looking domains absent from reference data "
                          "[default: show-unlisted]"),
    ] = True,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Report the risk tiers of AI domains this tenant actually reaches.

    Joins observed web_domain values to the curated risk levels in
    'Public AI Domains and Risk'. Also maintains a high-risk watchlist: an empty
    watchlist is the good outcome and is itself a reportable finding.

    \b
    Examples:
      uv run exa aillm risk --tenant geha
      uv run exa aillm risk --refresh --no-show-unlisted --tenant geha
    """
    from exa.aillm.profile import collect_tenant_profile
    from exa.aillm.risk import build_risk_report

    client = _make_client(tenant)
    try:
        profile = collect_tenant_profile(client, lookback_days=lookback, refresh=refresh)
        rep = build_risk_report(client, profile=profile)

        colours = {"critical": "red", "high": "red", "medium": "yellow", "low": "green"}
        tbl = Table(show_header=True, header_style="bold")
        tbl.add_column("Risk", style="cyan")
        tbl.add_column("Domains", justify="right")
        tbl.add_column("Examples", style="dim")
        for tier, domains in rep.by_risk.items():
            tbl.add_row(
                f"[{colours.get(tier, 'dim')}]{tier.upper()}[/]",
                str(len(domains)),
                ", ".join(d.domain for d in domains[:4]),
            )
        console.print(tbl)

        if rep.watchlist_clear:
            console.print(
                f"\n  [green]High-risk watchlist CLEAR[/] — none of the "
                f"{rep.watchlist_total} high-risk domains were reached.",
            )
        else:
            console.print(
                f"\n  [red]High-risk watchlist: {len(rep.watchlist_hits)} hit(s)[/]"
            )
            for d in rep.watchlist_hits:
                console.print(f"    {d.domain}  ({d.provider} / {d.category})")

        if show_unlisted and rep.unlisted:
            console.print(
                f"\n  {len(rep.unlisted)} AI-looking domain(s) not in reference data "
                f"— candidates for the ai-llm-domains repo:",
                style="dim",
            )
            for d in rep.unlisted[:40]:
                console.print(f"    {d}", style="dim")

        if rep.sample_truncated:
            console.print(
                "\n  NOTE: web_domain sample was truncated — treat counts as a "
                "lower bound.",
                style="yellow",
            )
        console.print(
            f"\n  Profile: {profile.api_calls} API call(s) this run "
            f"(0 = served from cache)",
            style="dim",
        )
    finally:
        client.close()


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

"""AI/LLM CLI commands -- sync, sync-ruleset, discover, and status.

Commands:
  exa aillm sync           -- Sync 6 AI/LLM context tables from reference data
  exa aillm sync-ruleset   -- Sync 'AI/LLM DLP Rulesets' from live alert history
  exa aillm discover       -- Discover AI activity candidates for context tables
  exa aillm status         -- Show live record counts for all 6 tables
"""

from __future__ import annotations

from pathlib import Path
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


@aillm_app.command("sources")
def sources_cmd(
    lookback: Annotated[
        int,
        typer.Option("--lookback", help="Days of tenant history to enumerate"),
    ] = 7,
    show_all: Annotated[
        bool,
        typer.Option(
            "--all/--ai-only",
            help="Include sources with no AI/LLM relevance [default: ai-only]",
        ),
    ] = False,
    json_out: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Emit JSON [default: no-json]"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Inventory the vendors, products and collectors feeding this tenant.

    Run this FIRST. Every later step assumes a source exists to populate the
    field it measures, and that assumption is worth two API calls to check --
    a DNS-only tenant emits dns-response rather than web-activity, so the OOTB
    AI rules cannot fire regardless of how well the context tables are filled.

    Reports which sources exist and what they emit, never how much: group_by
    returns distinct values with no count field at all.

    \b
    Examples:
      uv run exa aillm sources --tenant baystate
      uv run exa aillm sources --all --lookback 30 --tenant baystate
      uv run exa aillm sources --json --tenant baystate | jq .
    """
    import dataclasses
    import json as _json

    from exa.aillm.sources import collect_sources

    client = _make_client(tenant)
    try:
        inv = collect_sources(client, lookback_days=lookback)

        if json_out:
            payload = {
                "lookback_days": inv.lookback_days,
                "api_calls": inv.api_calls,
                "truncated": inv.truncated,
                "collectors_available": inv.collectors_available,
                "missing_roles": inv.missing_roles(),
                "sources": [
                    {
                        **{
                            k: v
                            for k, v in dataclasses.asdict(s).items()
                            if k != "pack"
                        },
                        "pack": s.pack.key if s.pack else None,
                        "ai_relevant": s.ai_relevant,
                        "recognised": s.recognised,
                    }
                    for s in inv.sources
                ],
            }
            console.print_json(_json.dumps(payload))
            return

        console.rule(f"Source inventory — last {inv.lookback_days} days")

        if not inv.sources:
            console.print(
                "\n  No vendor/product values returned. Either the tenant is "
                "silent over this window, or `vendor`/`product` are unpopulated.",
                style="yellow",
            )
            return

        shown = inv.sources if show_all else inv.ai_sources
        tbl = Table(show_header=True, header_style="bold")
        tbl.add_column("Vendor", style="cyan", no_wrap=True)
        tbl.add_column("Product", no_wrap=True)
        tbl.add_column("Role")
        tbl.add_column("Known", justify="center")
        tbl.add_column("Activity types", max_width=40)
        tbl.add_column("Collector", max_width=34)
        for s in shown:
            acts = ", ".join(s.activity_types[:3])
            if len(s.activity_types) > 3:
                acts += f" (+{len(s.activity_types) - 3})"
            coll = ", ".join(s.collectors[:2])
            if len(s.collectors) > 2:
                coll += f" (+{len(s.collectors) - 2})"
            tbl.add_row(
                s.vendor,
                s.product,
                s.role,
                "yes" if s.recognised else "-",
                acts or "-",
                coll or "-",
            )
        console.print(tbl)

        total, ai = len(inv.sources), len(inv.ai_sources)
        if not show_all:
            console.print(
                f"\n  {ai} AI-relevant of {total} sources. "
                "Use --all to see the rest.",
                style="dim",
            )

        missing = inv.missing_roles()
        if missing:
            console.print(
                f"\n  No source for: {', '.join(missing)}",
                style="yellow",
            )
            if "agent" in missing:
                console.print(
                    "    Without an agent source, llm_request / ai_token_* / result "
                    "are unpopulated and the rules needing them cannot fire —\n"
                    "    no amount of context-table population changes that.",
                    style="dim",
                )
            if "edr" in missing:
                console.print(
                    "    Without endpoint telemetry there is no detection path for "
                    "locally-run models (ollama, lm studio, llama.cpp).",
                    style="dim",
                )

        unknown = inv.unrecognised
        if unknown:
            console.print(
                f"\n  {len(unknown)} source(s) have no vendor pack — "
                "candidates to add after this engagement:",
                style="dim",
            )
            for s in unknown[:10]:
                console.print(f"    {s.key}  ({s.role})", style="dim")

        if not inv.collectors_available:
            console.print(
                "\n  Cloud Collector listing unavailable — the tenant may ingest "
                "via Site Collectors or syslog instead.",
                style="dim",
            )
        if inv.truncated:
            console.print(
                "\n  Sample truncated — treat this inventory as a LOWER BOUND.",
                style="yellow",
            )
        console.print(
            f"\n  {inv.api_calls} API call(s) this run", style="dim"
        )
    finally:
        client.close()


# No help= here on purpose: Typer prefers it over the callback docstring, and
# the docstring is what carries the withhold-reason table and the examples that
# tests/test_help.py requires of every command.
gaps_app = typer.Typer(name="gaps", invoke_without_command=True)
aillm_app.add_typer(gaps_app)


@gaps_app.callback(invoke_without_command=True)
def gaps_cmd(
    ctx: typer.Context,
    output: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "--output",
            "-o",
            help="Write the reviewable JSON gap report to this path [default: none]",
        ),
    ] = None,
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
    deep: Annotated[
        bool,
        typer.Option(
            "--deep/--no-deep",
            help="Re-enumerate any field whose standing 5,000-value sample was "
            "truncated, at a 50,000 row cap. One read-only API call per "
            "truncated field, and the reason the proposal counts are right "
            "[default: deep]",
        ),
    ] = True,
    include_withheld_values: Annotated[
        bool,
        typer.Option(
            "--include-withheld-values/--no-include-withheld-values",
            help="Write withheld alert_name text into the report. Those strings "
            "are free text from the source product and can carry customer "
            "content [default: no-include-withheld-values]",
        ),
    ] = False,
    max_listed: Annotated[
        int,
        typer.Option(
            "--max-listed",
            help="Withheld entries listed per reason in the output; 0 lists all. "
            "Counts are always complete -- this caps the listing only "
            "[default: 200]",
        ),
    ] = 200,
    json_out: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Emit JSON to stdout [default: no-json]"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Show what this tenant emits that the AI/LLM context tables do not hold.

    READ-ONLY -- this command never writes to a tenant. It classifies every
    missing value into propose (safe to add) or withhold (with a machine-readable
    reason), and never drops one silently: examined always equals accounted for.

    Values are normalised through the vendor pack first. Microsoft Purview wraps
    each classic DLP match with the message subject, so 19,134 distinct live
    values collapsed to 2 real policy names on one tenant -- diffing the raw
    strings compares one-shot text and proposes adding all of it.

    \b
    Withhold reasons:
      high-cardinality-per-record -- one distinct value per event; unmatchable
      machine-generated           -- vendor noise tokens (dga-*, *.TC.*)
      not-ai-related              -- no AI/LLM signal
      excluded-martech            -- adtech riding the .ai TLD
      needs-review                -- plausible, but not safe unattended
      covered-after-normalisation -- already in the table once normalised

    Counts are LOWER BOUNDS wherever the live sample was truncated. --deep (on
    by default) re-enumerates any capped field at a 50,000 row cap first: the
    standing 5,000-value sample hid six of eight genuine AI alert names behind
    per-email DLP noise on a live tenant.

    \b
    Examples:
      uv run exa aillm gaps --tenant baystate
      uv run exa aillm gaps --tenant baystate --out gaps.json
      uv run exa aillm gaps --no-deep --json --tenant baystate
      uv run exa aillm gaps apply gaps.json --tenant baystate
    """
    import json as _json

    from exa.aillm.gaps import analyze_gaps, gap_report_to_dict

    # This is a group callback so 'gaps apply' can hang off it. Click runs the
    # callback before every subcommand, so without this guard 'gaps apply' would
    # silently re-run the whole analysis -- ~10 API calls -- before writing.
    if ctx.invoked_subcommand is not None:
        return

    client = _make_client(tenant)
    try:
        report = analyze_gaps(
            client,
            lookback_days=lookback,
            refresh=refresh,
            include_withheld_values=include_withheld_values,
            deep=deep,
        )
    finally:
        client.close()

    payload = gap_report_to_dict(report, max_listed_per_reason=max_listed)

    if output is not None:
        output.write_text(_json.dumps(payload, indent=2), encoding="utf-8")

    if json_out:
        console.print_json(_json.dumps(payload))
        return

    console.rule("AI/LLM context table gaps -- read only")

    def _bound(n: int, truncated: bool) -> str:
        return f">= {n}" if truncated else str(n)

    tbl = Table(show_header=True, header_style="bold")
    tbl.add_column("Table", style="cyan", no_wrap=True)
    tbl.add_column("Field", style="dim")
    tbl.add_column("Missing", justify="right")
    tbl.add_column("Propose", justify="right")
    tbl.add_column("Withhold", justify="right")
    tbl.add_column("Top withhold reason", max_width=32)
    tbl.add_column("Status")

    colours = {"OK": "green", "WEAK": "yellow", "DEAD": "red", "EMPTY": "red"}
    for t in report.tables:
        reasons = t.by_reason()
        top = next(iter(reasons.items()), None)
        tbl.add_row(
            t.table_name,
            ", ".join(t.fields),
            _bound(t.examined, t.truncated_sample),
            str(t.proposed),
            _bound(t.withheld_values, t.truncated_sample),
            f"{top[0]} ({top[1]})" if top else "-",
            f"[{colours.get(t.status, 'dim')}]{t.status}[/]",
        )
    console.print(tbl)

    for t in report.tables:
        if not t.propose:
            continue
        console.print(f"\n  {t.table_name} -- {len(t.propose)} proposed:", style="bold")
        for g in t.propose:
            src = f"  [{', '.join(g.sources)}]" if g.sources else ""
            console.print(f"    + {g.value}", style="green")
            console.print(f"        {g.reason}{src}", style="dim")

    for t in report.tables:
        reasons = t.by_reason()
        if not reasons:
            continue
        console.print(f"\n  {t.table_name} -- withheld:", style="dim")
        for reason, count in reasons.items():
            console.print(
                f"    {_bound(count, t.truncated_sample):>10}  {reason}", style="dim"
            )

    unbalanced = [t.table_name for t in report.tables if not t.balanced]
    if unbalanced:
        console.print(
            f"\n  BUG: values unaccounted for in: {', '.join(unbalanced)}",
            style="red",
        )
    else:
        console.print(
            "\n  Every examined value is accounted for in exactly one bucket.",
            style="dim",
        )

    if report.deepened_fields:
        console.print(
            "\n  Re-enumerated at a 50,000 row cap (standing sample was capped "
            f"at 5,000): {', '.join(report.deepened_fields)}",
            style="dim",
        )

    if report.lower_bound:
        console.print(
            "\n  Live samples were truncated for: "
            f"{', '.join(report.truncated_fields)}.\n"
            "  EVERY count above is a LOWER BOUND -- a value absent here may "
            "still be present on the tenant.",
            style="yellow",
        )

    if output is not None:
        console.print(f"\n  Wrote {output}", style="green")
        if not include_withheld_values:
            console.print(
                "  Withheld alert_name text is redacted in that file "
                "(--include-withheld-values to keep it).",
                style="dim",
            )
    console.print(
        f"\n  Profile: {report.api_calls} API call(s) this run "
        f"(0 = served from cache)",
        style="dim",
    )


@gaps_app.command("apply")
def gaps_apply_cmd(
    report_file: Annotated[
        Path,
        typer.Argument(
            help="gaps.json written by 'exa aillm gaps --out'",
            exists=True,
            dir_okay=False,
        ),
    ],
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run/--no-dry-run",
            help="Show what would be written without writing it. "
            "--no-dry-run writes to the tenant [default: dry-run]",
        ),
    ] = True,
    table: Annotated[
        list[str] | None,
        typer.Option(
            "--table",
            help="Restrict to this table display name; repeatable "
            "[default: every table in the report]",
        ),
    ] = None,
    json_out: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Emit JSON to stdout [default: no-json]"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Write a reviewed gap report's proposals into their context tables.

    Reads the file rather than re-deriving the analysis, deliberately: a human
    has to be able to read what will be written before it is written. Only the
    'propose' bucket is ever written -- nothing withheld can be promoted from
    here, at any flag.

    DRY RUN IS THE DEFAULT. --no-dry-run writes to the tenant.

    Two safeguards worth knowing about, because both cover failures the API
    reports as success:

    \b
      - The key attribute is re-resolved per table. It is not always named
        'key' -- writing under the wrong one is accepted and lands nothing.
      - The table is re-read first, so a value that arrived between the report
        and the apply is skipped. addRecords is additive; re-writing duplicates.

    Writes are then polled to a terminal uploadStatus. The POST returns 200
    before the records are queryable, so an immediate read reports the
    pre-write state and reads exactly like a failed write.

    \b
    Examples:
      uv run exa aillm gaps apply gaps.json --tenant baystate
      uv run exa aillm gaps apply gaps.json --tenant baystate --no-dry-run
      uv run exa aillm gaps apply gaps.json --table "AI/LLM DLP Rulesets"
    """
    import json as _json

    from exa.aillm.gaps import apply_gaps

    client = _make_client(tenant)
    try:
        results = apply_gaps(
            client, report_file, dry_run=dry_run, tables=list(table) if table else None
        )
    finally:
        client.close()

    if json_out:
        console.print_json(
            _json.dumps(
                {
                    "dry_run": dry_run,
                    "tables": [
                        {
                            "table": r.table_name,
                            "table_id": r.table_id,
                            "key_attr": r.key_attr,
                            "proposed": r.proposed,
                            "already_present": r.already_present,
                            "written": r.written,
                            "status": r.status,
                            "errors": r.errors,
                            "timed_out": r.timed_out,
                            "skipped_reason": r.skipped_reason,
                            "ok": r.ok,
                        }
                        for r in results
                    ],
                }
            )
        )
        return

    console.rule("AI/LLM gaps apply -- DRY RUN" if dry_run else "AI/LLM gaps apply")

    tbl = Table(show_header=True, header_style="bold")
    tbl.add_column("Table", style="cyan", no_wrap=True)
    tbl.add_column("Key attr", style="dim")
    tbl.add_column("Proposed", justify="right")
    tbl.add_column("Present", justify="right")
    tbl.add_column("Written" if not dry_run else "Would write", justify="right")
    tbl.add_column("Status")

    for r in results:
        if r.skipped_reason:
            status = f"[dim]{r.skipped_reason}[/]"
        elif r.timed_out:
            status = "[yellow]still uploading -- re-check later[/]"
        elif r.errors:
            status = f"[red]{r.errors} error(s)[/]"
        else:
            status = f"[green]{r.status or 'ok'}[/]"
        tbl.add_row(
            r.table_name,
            r.key_attr,
            str(r.proposed),
            str(r.already_present),
            str(r.written),
            status,
        )
    console.print(tbl)

    total = sum(r.written for r in results)
    if dry_run:
        console.print(
            f"\n  DRY RUN -- nothing was written. {total} record(s) would be "
            "added.\n  Re-run with --no-dry-run to write.",
            style="yellow",
        )
        return

    failed = [r for r in results if not r.ok and not r.skipped_reason]
    if failed:
        console.print(
            f"\n  {len(failed)} table(s) did not complete cleanly: "
            f"{', '.join(r.table_name for r in failed)}",
            style="red",
        )
    console.print(f"\n  {total} record(s) written.", style="green")
    console.print(
        "  Re-run 'exa aillm validate' to confirm overlap improved -- record "
        "count alone does not prove a table matches live data.",
        style="dim",
    )


@aillm_app.command("dashboard")
def dashboard_cmd(
    output: Annotated[
        Path,
        typer.Option(
            "--out",
            "--output",
            "-o",
            help="Write the dashboard .config here [default: aillm-landscape.config]",
        ),
    ] = Path("aillm-landscape.config"),
    title: Annotated[
        str,
        typer.Option(
            "--title",
            help="Dashboard title. Leave at the default to keep two tenants' "
            "configs diffable [default: AI/LLM Landscape]",
        ),
    ] = "AI/LLM Landscape",
    lookback: Annotated[
        str,
        typer.Option("--lookback", help="Relative timeframe [default: 30 day]"),
    ] = "30 day",
    header: Annotated[
        bool,
        typer.Option(
            "--header/--no-header",
            help="Include the explanatory text tile [default: header]",
        ),
    ] = True,
    portable: Annotated[
        bool,
        typer.Option(
            "--portable/--no-portable",
            help="Strip resolved table IDs, for diffing two tenants' output. "
            "NOT importable [default: no-portable]",
        ),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Generate an AI/LLM Landscape dashboard that is identical on every tenant.

    READ-ONLY -- resolves context table IDs and writes a file. Import it from
    the Exabeam UI (Dashboards -> Import).

    Every panel filters through a context table, so the only tenant-specific
    values in the output are the resolved table IDs. Anything that varies by
    tenant -- outcome vocabulary, vendor, category strings -- is a group-by or
    a pivot instead. That is what makes the same config work at a Check Point
    site and a Zscaler site with no edit, and it moves customisation into
    Context Management where the customer can do it themselves.

    A panel whose table is absent is SKIPPED and reported, never emitted
    unfiltered. An unfiltered panel renders every event on the tenant and looks
    like a working AI panel.

    \b
    Examples:
      uv run exa aillm dashboard --tenant baystate
      uv run exa aillm dashboard --tenant baystate -o bs.config
      uv run exa aillm dashboard --tenant geha --lookback "7 day"
      uv run exa aillm dashboard --tenant baystate --portable -o bs.portable.json
    """
    import json as _json

    from exa.aillm.dashboard import build_dashboard, portable_form

    client = _make_client(tenant)
    try:
        build = build_dashboard(
            client, title=title, lookback=lookback, include_header=header
        )
    finally:
        client.close()

    payload = portable_form(build.config) if portable else build.config
    output.write_text(_json.dumps(payload, indent=2), encoding="utf-8")

    console.rule("AI/LLM Landscape dashboard")

    tbl = Table(show_header=True, header_style="bold")
    tbl.add_column("Context table", style="cyan", no_wrap=True)
    tbl.add_column("Resolved ID", style="dim")
    for name, table_id in sorted(build.resolved.items()):
        tbl.add_row(name, table_id)
    console.print(tbl)

    console.print(f"\n  {build.panel_count} panel(s) written to {output}", style="green")

    if build.skipped:
        console.print(
            f"\n  {len(build.skipped)} panel(s) SKIPPED -- table missing on this "
            "tenant:",
            style="yellow",
        )
        for s in build.skipped:
            console.print(f"    - {s}", style="yellow")
        console.print(
            "  Skipped rather than emitted unfiltered: an unfiltered panel "
            "renders\n  every event on the tenant and reads as working.",
            style="dim",
        )

    if portable:
        console.print(
            "\n  --portable strips table IDs for diffing. This file will NOT "
            "import.",
            style="yellow",
        )
    else:
        console.print(
            "\n  Import via Dashboards -> Import in the Exabeam UI.", style="dim"
        )
    console.print(
        "  A blank panel means its table holds nothing this tenant emits -- "
        "run\n  'exa aillm gaps' before concluding there is no activity.",
        style="dim",
    )


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

"""Splunk SPL → Exabeam EQL CLI commands.

Commands:
  exa splunk convert  -- Convert Splunk searches from Excel to Exabeam rules
  exa splunk one      -- Convert a single SPL search string inline (no file needed)
  exa splunk deploy   -- Deploy converted rules to Exabeam (disabled by default)
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

splunk_app = typer.Typer(
    name="splunk",
    help="Convert Splunk SPL searches to Exabeam correlation rules.",
    no_args_is_help=True,
)
console = Console()

_TENANT_HELP = "Tenant nickname or FQDN (default: saved default)"


def _make_client(tenant: str | None = None):
    from exa.client import ExaClient

    client = ExaClient(tenant=tenant)
    client.authenticate()
    return client


# ── convert ──────────────────────────────────────────────────────────────────


@splunk_app.command("convert")
def convert_cmd(
    excel_file: Annotated[
        Path,
        typer.Argument(help="Input file (.xlsx, .csv, or savedsearches.conf)"),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output JSON file for API payloads"),
    ] = None,
    sheet: Annotated[
        str,
        typer.Option("--sheet", help="Sheet name (Excel only) [default: in]"),
    ] = "in",
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show full warnings for each rule"),
    ] = False,
    compress: Annotated[
        bool,
        typer.Option(
            "--compress/--no-compress",
            help="Auto-compress oversized EQL with RGXi alternation [default: compress]",
        ),
    ] = True,
) -> None:
    """Convert Splunk SPL searches to Exabeam correlation rules.

    Supports .xlsx, .csv, and savedsearches.conf input formats. Reads
    'title' and 'search' columns (Excel/CSV) or stanza names (conf).
    Outputs a rich table and an API-ready JSON file.

    All converted rules are deploy_ready="Needs review" — SPL-to-EQL is
    lossy (stats/lookups/eval are dropped) and require human sign-off
    before deployment.

    \b
    Usage pattern:
      exa splunk convert FILE [OPTIONS]
      FILE must come before any options. Quote paths that contain spaces.

    \b
    Examples:
      exa splunk convert searches.xlsx
      exa splunk convert searches.xlsx --sheet Enabled
      exa splunk convert "My Searches.xlsx" --sheet Enabled
      exa splunk convert "C:\\path\\to\\My Searches.xlsx" --sheet Enabled -o out.json
      exa splunk convert searches.csv --verbose
      exa splunk convert savedsearches.conf

    To deploy converted rules:
      exa splunk deploy <output.json>
    """
    from exa.splunk.batch import conversion_summary, convert_file, export_api_payloads

    if not excel_file.exists():
        console.print(f"[red]File not found: {excel_file}[/red]")
        raise typer.Exit(1)

    console.rule("[bold cyan]Splunk -> Exabeam Rule Conversion[/bold cyan]")
    console.print(f"  Input: {excel_file}", style="dim")
    suffix = excel_file.suffix.lower()
    if suffix in (".xlsx", ".xls"):
        console.print(f"  Sheet: {sheet}", style="dim")
    else:
        console.print(f"  Format: {suffix or 'auto-detect'}", style="dim")
    console.print()

    try:
        results = convert_file(excel_file, sheet=sheet, compress=compress)
    except Exception as e:
        console.print(f"[red]Failed to read Excel file: {e}[/red]")
        raise typer.Exit(1)

    if not results:
        console.print("[yellow]No valid rows found in the file.[/yellow]")
        raise typer.Exit(0)

    # ── Results table ─────────────────────────────────────────────────────
    tbl = Table(show_header=True, header_style="bold", box=None)
    tbl.add_column("#", style="dim", width=3)
    tbl.add_column("Rule Name", style="cyan", max_width=45)
    tbl.add_column("Index", width=16)
    tbl.add_column("Activity Type", width=20)
    tbl.add_column("EQL Preview", max_width=40, style="dim")
    tbl.add_column("Warns", justify="right", width=5)
    tbl.add_column("Ready", width=12)

    for i, r in enumerate(results, 1):
        name = r["name"].replace("[Splunk] ", "")
        eql_preview = r["eql_query"][:37] + "…" if len(r["eql_query"]) > 40 else r["eql_query"]
        warn_count = len(r["warnings"])
        if r["deploy_ready"] == "Needs review":
            ready_style = "yellow"
        elif r["deploy_ready"] == "EQL too long":
            ready_style = "bold red"
        else:
            ready_style = "red"
        tbl.add_row(
            str(i),
            name,
            r["index"] or "-",
            r.get("activity_type_hint") or "-",
            eql_preview,
            str(warn_count),
            f"[{ready_style}]{r['deploy_ready']}[/{ready_style}]",
        )

    console.print(tbl)

    # ── Summary ───────────────────────────────────────────────────────────
    summary = conversion_summary(results)
    console.print()
    console.rule("Summary", style="dim")
    console.print(f"  Rules converted:    {summary['total']}")
    console.print(f"  With warnings:      {summary['rules_with_warnings']}")
    if summary.get("compressed"):
        console.print(
            f"  Compressed (RGXi):  {summary['compressed']}",
            style="cyan",
        )
    if summary["context_tables_needed"]:
        console.print(
            f"  Context tables needed: {', '.join(summary['context_tables_needed'])}",
            style="yellow",
        )
    if summary["dropped_stages"]:
        dropped_str = ", ".join(
            f"{k} (×{v})" for k, v in sorted(summary["dropped_stages"].items())
        )
        console.print(f"  Dropped SPL features: {dropped_str}", style="dim")

    # ── Verbose warnings ─────────────────────────────────────────────────
    if verbose:
        console.print()
        for r in results:
            if r["warnings"]:
                console.print(f"\n  [cyan]{r['name']}[/cyan]")
                for w in r["warnings"]:
                    console.print(f"    [yellow]![/yellow] {w}")

    # ── Export ────────────────────────────────────────────────────────────
    if output is None:
        output = excel_file.with_suffix(".converted.json")

    try:
        saved = export_api_payloads(results, output)
        console.print(f"\n  [green]+[/green] Saved {len(results)} payloads -> {saved}")
    except Exception as e:
        console.print(f"  [red]x[/red] Failed to save output: {e}")
        raise typer.Exit(1)

    console.print(
        "\n  All rules marked [yellow]Needs review[/yellow] - "
        "validate EQL before deploying.",
        style="dim",
    )
    console.print(
        "  Deploy with:  [bold]exa splunk deploy[/bold] " + str(output),
        style="dim",
    )


# ── one ──────────────────────────────────────────────────────────────────────


@splunk_app.command("one")
def one_cmd(
    search: Annotated[
        str,
        typer.Argument(help="SPL search string to convert"),
    ],
    title: Annotated[
        str,
        typer.Option("--title", "-t", help="Rule title (default: 'Ad-hoc SPL Search')"),
    ] = "Ad-hoc SPL Search",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Save API payload to JSON file"),
    ] = None,
    json_out: Annotated[
        bool,
        typer.Option("--json", help="Print raw JSON payload instead of rich output"),
    ] = False,
) -> None:
    """Convert a single SPL search string to an Exabeam EQL correlation rule.

    Converts inline without needing an Excel file.  Prints the EQL query,
    description, and all warnings.  Optionally saves the API payload to JSON.

    Examples:

      exa splunk one 'index=c42 severity="High" | stats count by username'

      exa splunk one 'index=o365 Operation=Send' --title "O365 Email Send"

      exa splunk one 'index=fireamp_stream severity="High"' -o rule.json
    """
    import json as _json

    from exa.splunk.converter import convert_spl_to_exa_rule, to_api_payload

    rule = convert_spl_to_exa_rule(title, search)
    payload = to_api_payload(rule)

    if json_out:
        console.print_json(_json.dumps(payload, indent=2))
        if output:
            output.write_text(_json.dumps([payload], indent=2), encoding="utf-8")
        return

    console.rule("[bold cyan]SPL -> Exabeam Conversion[/bold cyan]")
    console.print(f"  [bold]Rule:[/bold]  {rule['name']}")
    console.print(f"  [bold]Index:[/bold] {rule['index'] or '-'}  |  "
                  f"[bold]Activity Type:[/bold] {rule['activity_type_hint'] or '-'}")
    console.print()

    console.print("[bold]EQL Query:[/bold]")
    console.print(f"  [green]{rule['eql_query']}[/green]")
    console.print()

    console.print("[bold]Description:[/bold]")
    console.print(f"  [dim]{rule['description']}[/dim]")
    console.print()

    if rule["context_tables"]:
        console.print(f"[bold]Context Tables Needed:[/bold] "
                      f"[yellow]{', '.join(rule['context_tables'])}[/yellow]")
        console.print()

    if rule["dropped_stages"]:
        console.print(f"[bold]Dropped SPL stages:[/bold] "
                      f"[dim]{', '.join(rule['dropped_stages'])}[/dim]")
        console.print()

    if rule["warnings"]:
        console.print("[bold]Warnings:[/bold]")
        for w in rule["warnings"]:
            console.print(f"  [yellow]![/yellow] {w}")
        console.print()

    console.print(
        f"  [yellow]deploy_ready: {rule['deploy_ready']}[/yellow] - "
        "review EQL before deploying",
        style="dim",
    )

    if output:
        output.write_text(_json.dumps([payload], indent=2), encoding="utf-8")
        console.print(f"\n  [green]+[/green] Payload saved -> {output}")


# ── deploy ────────────────────────────────────────────────────────────────────


@splunk_app.command("deploy")
def deploy_cmd(
    payload_file: Annotated[
        Path,
        typer.Argument(help="JSON file produced by 'exa splunk convert'"),
    ],
    enabled: Annotated[
        bool,
        typer.Option("--enabled", help="Create rules in enabled state"),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview without writing to Exabeam"),
    ] = False,
    validate: Annotated[
        bool,
        typer.Option(
            "--validate/--no-validate",
            help="Validate EQL against live tenant before deploying [default: validate]",
        ),
    ] = True,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Deploy converted Splunk rules to Exabeam via the correlation rules API.

    Reads the JSON produced by 'exa splunk convert' and POSTs each rule
    to POST /correlation-rules/v2/rules.  Rules are created disabled by
    default — use --enabled to activate immediately (not recommended).

    Use --dry-run to see what would be deployed without making API calls.

    EQL validation (--validate, default on) calls POST /search/v2/events
    with each EQL before creating the rule.  Rules with unknown fields or
    syntax errors are skipped with Exabeam's own error message — no more
    discovering broken rules in the UI after deployment.
    Use --no-validate to skip validation and deploy unconditionally.
    """
    import json

    if not payload_file.exists():
        console.print(f"[red]File not found: {payload_file}[/red]")
        raise typer.Exit(1)

    try:
        payloads = json.loads(payload_file.read_text(encoding="utf-8"))
    except Exception as e:
        console.print(f"[red]Failed to read payload file: {e}[/red]")
        raise typer.Exit(1)

    prefix = "[DRY RUN] " if dry_run else ""
    console.rule(f"{prefix}Deploy Splunk Rules -> Exabeam")
    console.print(f"  Rules to deploy: {len(payloads)}")
    console.print(f"  Enabled on create: {enabled}")
    if not dry_run:
        console.print(f"  EQL validation:   {'on' if validate else 'off (--no-validate)'}")
    console.print()

    if dry_run:
        for i, p in enumerate(payloads, 1):
            console.print(f"  {i:>2}. {p['name']}", style="cyan")
            eql_preview = p['sequencesConfig']['sequences'][0]['query'][:80]
            console.print(f"      EQL: {eql_preview}", style="dim")
        if validate:
            console.print("\n  [dim]Validation will run against the live tenant at deploy time.[/dim]")
        console.print("  [dim]Dry run - no API calls made.[/dim]")
        return

    from exa.correlation import create_rule as create_correlation_rule, validate_eql

    eql_limit = 1024

    client = _make_client(tenant)
    created = 0
    failed = 0
    skipped = 0
    invalid = 0
    try:
        for p in payloads:
            name = p["name"]
            eql = p.get("sequencesConfig", {}).get("sequences", [{}])[0].get("query", "")
            if len(eql) > eql_limit:
                console.print(
                    f"  [yellow]-[/yellow] {name}: EQL too long"
                    f" ({len(eql)} chars, limit {eql_limit}) - skipped",
                    style="yellow",
                )
                skipped += 1
                continue
            if validate:
                errors = validate_eql(client, eql)
                if errors:
                    console.print(f"  [red]x[/red] {name}: EQL invalid - {errors[0]}")
                    invalid += 1
                    continue
            p["enabled"] = enabled
            try:
                resp = create_correlation_rule(client, p)
                rule_id = resp.get("id", "?") if isinstance(resp, dict) else str(resp)
                console.print(f"  [green]+[/green] {name} ({rule_id})")
                created += 1
            except Exception as e:
                console.print(f"  [red]x[/red] {name}: {e}")
                failed += 1
            client.batch_write_sleep()
    finally:
        client.close()

    style = "green" if not (failed or invalid) else "red"
    console.rule("Deploy Complete", style=style)
    parts = [f"Created: {created}", f"Skipped (EQL too long): {skipped}"]
    if validate:
        parts.append(f"Invalid EQL: {invalid}")
    parts.append(f"Failed: {failed}")
    console.print(f"  {' | '.join(parts)}")

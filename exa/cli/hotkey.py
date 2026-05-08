"""Hot key CLI commands — analyze, scan, expand, rollback."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

hotkey_app = typer.Typer(
    name="hotkey",
    help="Analyze and fix Dataflow hot key risk in Network Zones.",
    no_args_is_help=True,
)
console = Console()

_TENANT_HELP = "Tenant nickname or FQDN (default: saved default)"
_RISK_STYLE = {"COARSE": "red", "MEDIUM": "yellow", "FINE": "green", "UNKNOWN": "dim"}


def _make_client(tenant: str | None = None):
    from exa.client import ExaClient

    client = ExaClient(tenant=tenant)
    client.authenticate()
    return client


# -- analyze ------------------------------------------------------------------


@hotkey_app.command("analyze")
def analyze(
    tenant: Annotated[str | None, typer.Option("--tenant", "-t", help=_TENANT_HELP)] = None,
    ip_field: Annotated[
        str | None,
        typer.Option("--ip-field", help="Column id holding the IP/subnet value"),
    ] = None,
    name_field: Annotated[
        str | None,
        typer.Option("--name-field", help="Column id holding the zone name"),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Output as JSON")] = False,
    as_csv: Annotated[bool, typer.Option("--csv", help="Output as CSV")] = False,
) -> None:
    """Classify Network Zones table entries by hot key risk (COARSE/MEDIUM/FINE)."""
    from exa.hotkey.analyze import analyze_zones

    client = _make_client(tenant)
    try:
        with console.status("Reading Network Zones table…"):
            zones = analyze_zones(client, ip_field=ip_field, name_field=name_field)
    except ValueError as e:
        console.print(f"FAIL: {e}", style="red")
        raise typer.Exit(1)
    finally:
        client.close()

    rows = [
        {
            "zone_name": z.entry.zone_name,
            "key": z.entry.key,
            "prefix_len": z.prefix_len,
            "cardinality": z.cardinality,
            "risk": z.risk,
        }
        for z in zones
    ]

    if as_json:
        console.print(json.dumps(rows, indent=2))
        return

    if as_csv:
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf, fieldnames=["zone_name", "key", "prefix_len", "cardinality", "risk"]
        )
        writer.writeheader()
        writer.writerows(rows)
        console.print(buf.getvalue(), end="")
        return

    coarse = sum(1 for z in zones if z.risk == "COARSE")
    table = Table(title="Network Zones — Hot Key Risk", show_lines=False)
    table.add_column("Zone Name", style="white", no_wrap=True)
    table.add_column("Key (IP/Subnet)", style="dim")
    table.add_column("Prefix", justify="right")
    table.add_column("Addresses", justify="right")
    table.add_column("Risk", justify="center")

    for z in sorted(zones, key=lambda z: (z.prefix_len or 999, z.entry.zone_name)):
        style = _RISK_STYLE.get(z.risk, "")
        cardinality = f"{z.cardinality:,}" if z.cardinality is not None else "—"
        prefix = f"/{z.prefix_len}" if z.prefix_len is not None else "—"
        table.add_row(
            z.entry.zone_name,
            z.entry.key,
            prefix,
            cardinality,
            f"[{style}]{z.risk}[/{style}]",
        )

    console.print(table)
    if coarse:
        console.print(
            f"\n[red]{coarse} COARSE zone(s)[/red] — run [bold]exa hotkey scan[/bold] to assess"
            f" traffic, then [bold]exa hotkey expand[/bold] to fix."
        )


# -- scan ---------------------------------------------------------------------


@hotkey_app.command("scan")
def scan(
    tenant: Annotated[str | None, typer.Option("--tenant", "-t", help=_TENANT_HELP)] = None,
    lookback: Annotated[int, typer.Option("--lookback", help="Days of events to search")] = 7,
    threshold: Annotated[
        int,
        typer.Option("--threshold", help="Distinct IPs per zone above which zone is HOT_KEY_RISK"),
    ] = 500,
    limit: Annotated[int, typer.Option("--limit", help="Max IPs to collect from search")] = 50_000,
    ip_field: Annotated[str | None, typer.Option("--ip-field")] = None,
    name_field: Annotated[str | None, typer.Option("--name-field")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
    as_csv: Annotated[bool, typer.Option("--csv")] = False,
) -> None:
    """Scan recent events for active source IPs per zone; flag HOT_KEY_RISK zones.

    Note: event_count is always 0 — the Exabeam search API does not return
    per-IP event counts for group_by queries (verified 2026-05-08).
    ip_count is the sole hot key signal.
    """
    from exa.hotkey.analyze import analyze_zones
    from exa.hotkey.scan import scan_zones

    client = _make_client(tenant)
    try:
        with console.status("Reading Network Zones table…"):
            zones = analyze_zones(client, ip_field=ip_field, name_field=name_field)
        with console.status(f"Scanning events (last {lookback}d, limit {limit:,})…"):
            results = scan_zones(
                client, zones, lookback_days=lookback, threshold=threshold, limit=limit
            )
    except ValueError as e:
        console.print(f"FAIL: {e}", style="red")
        raise typer.Exit(1)
    finally:
        client.close()

    rows = [
        {"zone_name": r.zone_name, "ip_count": r.ip_count, "risk": r.risk}
        for r in results
    ]

    if as_json:
        console.print(json.dumps(rows, indent=2))
        return

    if as_csv:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=["zone_name", "ip_count", "risk"])
        writer.writeheader()
        writer.writerows(rows)
        console.print(buf.getvalue(), end="")
        return

    hot = sum(1 for r in results if r.risk == "HOT_KEY_RISK")
    table = Table(title=f"Network Zones — Active IP Scan (last {lookback}d)", show_lines=False)
    table.add_column("Zone Name", style="white", no_wrap=True)
    table.add_column("Distinct IPs", justify="right")
    table.add_column("Risk", justify="center")

    for r in results:
        if r.ip_count == 0:
            continue  # skip zones with no observed traffic
        risk_style = "red" if r.risk == "HOT_KEY_RISK" else "green"
        table.add_row(
            r.zone_name,
            f"{r.ip_count:,}",
            f"[{risk_style}]{r.risk}[/{risk_style}]",
        )

    console.print(table)
    if hot:
        console.print(
            f"\n[red]{hot} HOT_KEY_RISK zone(s)[/red] — run "
            f"[bold]exa hotkey expand[/bold] to fix."
        )


# -- expand -------------------------------------------------------------------


@hotkey_app.command("expand")
def expand(
    tenant: Annotated[str | None, typer.Option("--tenant", "-t", help=_TENANT_HELP)] = None,
    zone: Annotated[
        str | None,
        typer.Option("--zone", help="Zone name to expand (default: all COARSE zones)"),
    ] = None,
    lookback: Annotated[
        int, typer.Option("--lookback", help="Days of events to scan for observed IPs")
    ] = 7,
    enumerate_all: Annotated[
        bool,
        typer.Option("--enumerate/--no-enumerate", help="Enumerate all /24s (not just observed)"),
    ] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run/--no-dry-run")] = False,
    limit: Annotated[int, typer.Option("--limit")] = 50_000,
    ip_field: Annotated[str | None, typer.Option("--ip-field")] = None,
    name_field: Annotated[str | None, typer.Option("--name-field")] = None,
) -> None:
    """Expand coarse zone(s) to /24 granularity.

    Writes a rollback manifest to ~/.exa/hotkey-rollback/ before making changes.
    Use --dry-run to preview without writing anything.
    """
    from exa.hotkey.analyze import analyze_zones
    from exa.hotkey.expand import expand_zones
    from exa.hotkey.scan import _parse_grouped_rows
    from exa.search.events import search_events

    client = _make_client(tenant)
    try:
        with console.status("Reading Network Zones table…"):
            zones = analyze_zones(client, ip_field=ip_field, name_field=name_field)

        coarse = [z for z in zones if z.risk == "COARSE"]
        if zone:
            coarse = [z for z in coarse if z.entry.zone_name == zone]

        if not coarse:
            label = f"zone '{zone}'" if zone else "any COARSE zones"
            console.print(f"No targets found for {label}.", style="yellow")
            raise typer.Exit(0)

        observed_ips: list[str] | None = None
        if not enumerate_all:
            with console.status(f"Scanning events (last {lookback}d) for observed IPs…"):
                rows = search_events(
                    client,
                    "src_ip:*",
                    fields=["src_ip"],
                    group_by=["src_ip"],
                    lookback_days=lookback,
                    limit=limit,
                )
                observed_ips = _parse_grouped_rows(rows)

        verb = "[yellow][dry-run][/yellow] Would expand" if dry_run else "Expanding"
        console.print(f"{verb} {len(coarse)} COARSE zone(s) to /24 granularity…")

        summary = expand_zones(
            client,
            zones,
            zone_name=zone,
            observed_ips=observed_ips,
            enumerate_all=enumerate_all,
            dry_run=dry_run,
            tenant=tenant or "default",
        )

    except ValueError as e:
        console.print(f"FAIL: {e}", style="red")
        raise typer.Exit(1)
    finally:
        client.close()

    table = Table(title="Expand Results", show_lines=False)
    table.add_column("Zone", style="white", no_wrap=True)
    table.add_column("Old Key", style="dim")
    table.add_column("New /24 Entries", justify="right")
    table.add_column("Status", justify="center")

    for row in summary:
        status = row["status"]
        style = "yellow" if status == "dry-run" else "green"
        table.add_row(
            row["zone_name"],
            row["old_key"],
            str(row["new_key_count"]),
            f"[{style}]{status}[/{style}]",
        )

    console.print(table)

    if not dry_run and summary:
        console.print(
            "\nRollback manifest written to "
            f"[dim]~/.exa/hotkey-rollback/{tenant or 'default'}/[/dim]"
        )
        console.print("Undo with: [bold]exa hotkey rollback[/bold]")


# -- autofix ------------------------------------------------------------------


@hotkey_app.command("autofix")
def autofix(
    tenant: Annotated[str | None, typer.Option("--tenant", "-t", help=_TENANT_HELP)] = None,
    lookback: Annotated[int, typer.Option("--lookback", help="Days of traffic to scan")] = 7,
    threshold: Annotated[int, typer.Option(
        "--threshold",
        help="Min distinct IPs in a zone to qualify for expansion",
    )] = 500,
    limit: Annotated[int, typer.Option("--limit", help="Max IPs fetched from search")] = 50_000,
    max_zones: Annotated[int, typer.Option(
        "--max-zones",
        help="Safety cap: refuse to expand more than N zones in one run",
    )] = 10,
    enumerate_all: Annotated[bool, typer.Option(
        "--enumerate/--no-enumerate",
        help="Enumerate all /24s in range (not just observed IPs)",
    )] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run/--no-dry-run")] = False,
    ip_field: Annotated[str | None, typer.Option("--ip-field")] = None,
    name_field: Annotated[str | None, typer.Option("--name-field")] = None,
    as_json: Annotated[
        bool, typer.Option("--json", help="Machine-readable output (progress to stderr)")
    ] = False,
) -> None:
    """Analyze, scan, and expand all hot key zones in one step.

    Chains: analyze -> scan -> expand (COARSE + HOT_KEY_RISK zones only).
    Writes a rollback manifest before every change.
    Safe to schedule -- non-interactive, exits non-zero on any failure.
    """
    import json
    import sys

    from rich.console import Console as _Console
    from rich.table import Table

    from exa.hotkey.analyze import analyze_zones
    from exa.hotkey.expand import expand_zones
    from exa.hotkey.scan import _parse_grouped_rows, scan_zones
    from exa.search.events import search_events

    # Progress messages go to stderr when --json so stdout stays pipeable
    err = _Console(stderr=True) if as_json else console

    client = _make_client(tenant)
    try:
        # Phase 1 — Analyze
        err.print("  [1/3] Analyzing Network Zones table...", style="dim")
        try:
            zones = analyze_zones(client, ip_field=ip_field, name_field=name_field)
        except ValueError as e:
            err.print(f"FAIL: {e}", style="red")
            raise typer.Exit(1)

        coarse = [z for z in zones if z.risk == "COARSE"]
        if not coarse:
            err.print("No COARSE zones found. Nothing to do.", style="green")
            raise typer.Exit(0)

        # Phase 2 — Scan
        err.print(
            f"  [2/3] Scanning {len(coarse)} COARSE zone(s) for active traffic...",
            style="dim",
        )
        scans = scan_zones(
            client, zones, lookback_days=lookback, threshold=threshold, limit=limit
        )
        hot = [s for s in scans if s.risk == "HOT_KEY_RISK"]

        if not hot:
            err.print(
                f"No HOT_KEY_RISK zones detected above threshold={threshold}.",
                style="green",
            )
            raise typer.Exit(0)

        # Safety cap
        if len(hot) > max_zones:
            err.print(
                f"FAIL: {len(hot)} zones qualify for expansion but --max-zones={max_zones}.\n"
                f"  Re-run with --max-zones {len(hot)} to proceed, or use "
                f"'exa hotkey expand --zone NAME' to fix individually.",
                style="red",
            )
            raise typer.Exit(1)

        # Phase 3 — Expand
        verb = "[DRY RUN] Would expand" if dry_run else "Expanding"
        err.print(f"  [3/3] {verb} {len(hot)} zone(s) to /24 granularity...", style="dim")

        # Fetch observed IPs for targeted /24 selection (re-query; scan only stores counts)
        observed_ips: list[str] | None = None
        if not enumerate_all:
            rows = search_events(
                client,
                "src_ip:*",
                fields=["src_ip"],
                group_by=["src_ip"],
                lookback_days=lookback,
                limit=limit,
            )
            observed_ips = _parse_grouped_rows(rows)

        # Expand only COARSE zones confirmed HOT_KEY_RISK by scan
        hot_names = {s.zone_name for s in hot}
        target_zones = [
            z for z in zones if z.entry.zone_name in hot_names and z.risk == "COARSE"
        ]

        results = expand_zones(
            client,
            target_zones,
            observed_ips=observed_ips,
            enumerate_all=enumerate_all,
            dry_run=dry_run,
            tenant=tenant or "default",
        )

    except typer.Exit:
        raise
    except Exception as e:
        err.print(f"FAIL: {e}", style="red")
        raise typer.Exit(1)
    finally:
        client.close()

    if as_json:
        for r in results:
            sys.stdout.write(json.dumps({
                "zone": r["zone_name"],
                "old_key": r["old_key"],
                "new_entries": r["new_key_count"],
                "status": r["status"],
            }) + "\n")
        return

    tbl = Table(title="Autofix Results", show_lines=False)
    tbl.add_column("Zone", style="white", no_wrap=True)
    tbl.add_column("Old Key", style="dim")
    tbl.add_column("New /24 Entries", justify="right")
    tbl.add_column("Status", justify="center")

    for r in results:
        status = r["status"]
        style = "yellow" if status == "dry-run" else "green"
        tbl.add_row(
            r["zone_name"],
            r["old_key"],
            str(r["new_key_count"]),
            f"[{style}]{status}[/{style}]",
        )
    console.print(tbl)

    if not dry_run and results:
        console.print(
            f"\n{len(results)} zone(s) expanded · rollback manifests at "
            f"[dim]~/.exa/hotkey-rollback/{tenant or 'default'}/[/dim]"
        )


# -- rollback -----------------------------------------------------------------


@hotkey_app.command("rollback")
def rollback(
    tenant: Annotated[str | None, typer.Option("--tenant", "-t", help=_TENANT_HELP)] = None,
    manifest_path: Annotated[
        str | None,
        typer.Option("--manifest", "-m", help="Path to manifest file (default: most recent)"),
    ] = None,
    confirm: Annotated[
        bool,
        typer.Option("--confirm/--no-confirm", help="Apply the rollback (required to write)"),
    ] = False,
) -> None:
    """Restore Network Zones from a rollback manifest written by expand.

    Shows a diff of changes and requires --confirm to apply.
    """
    from exa.hotkey.rollback import apply_rollback, latest_manifest, load_manifest

    if manifest_path:
        path = Path(manifest_path)
    else:
        path = latest_manifest(tenant or "default")

    if not path or not path.exists():
        console.print(
            "No rollback manifest found. "
            f"Expected under ~/.exa/hotkey-rollback/{tenant or 'default'}/",
            style="red",
        )
        raise typer.Exit(1)

    try:
        m = load_manifest(path)
    except Exception as e:
        console.print(f"FAIL: Failed to load manifest: {e}", style="red")
        raise typer.Exit(1)

    console.print(f"Manifest: [dim]{path}[/dim]")
    console.print(f"Table:    [bold]{m.table_display_name}[/bold] ({m.table_id})")
    console.print(f"Zone:     [bold]{m.zone_name}[/bold]")
    console.print(f"Written:  {m.timestamp}")
    console.print()
    console.print(f"  Will [red]delete[/red]  {len(m.added_keys):,} /24 entries added by expand")
    console.print(f"  Will [green]restore[/green] {len(m.original_records)} original record(s)")

    if not confirm:
        console.print("\nRe-run with [bold]--confirm[/bold] to apply.", style="yellow")
        raise typer.Exit(0)

    client = _make_client(tenant)
    try:
        with console.status("Applying rollback…"):
            apply_rollback(client, m, table_id=m.table_id)
    except Exception as e:
        console.print(f"FAIL: Rollback failed: {e}", style="red")
        raise typer.Exit(1)
    finally:
        client.close()

    console.print("Rollback applied.", style="green")

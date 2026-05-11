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
_RISK_STYLE = {
    "CRITICAL": "bold red",
    "COARSE": "red",
    "FINE": "green",
    "UNKNOWN": "dim",
}
# Sort order for risk levels in table output (lower = shown first)
_RISK_ORDER = {"CRITICAL": 0, "COARSE": 1, "FINE": 2, "UNKNOWN": 3}


def _make_client(tenant: str | None = None):
    from exa.client import ExaClient

    client = ExaClient(tenant=tenant)
    client.authenticate()
    return client


def _analyze_rec(risk: str, tenant: str | None) -> str:
    """One-line recommendation string for analyze output."""
    t = f" --tenant {tenant}" if tenant else ""
    if risk == "CRITICAL":
        return f"Guaranteed hot key risk - run: exa hotkey expand{t}"
    if risk == "COARSE":
        return f"Run: exa hotkey scan{t} to assess traffic"
    if risk == "FINE":
        return "No action needed"
    return "Non-CIDR key - review manually"


def _scan_rec(zone_risk: str, scan_risk: str, tenant: str | None) -> str:
    """One-line recommendation string for scan output."""
    t = f" --tenant {tenant}" if tenant else ""
    if zone_risk == "CRITICAL":
        return f"AUTO-FLAG: expand regardless of traffic - run: exa hotkey expand{t}"
    if scan_risk == "HOT_KEY_RISK":
        return f"Active hot key confirmed - run: exa hotkey expand{t}"
    return "Below threshold - monitor or expand proactively"


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
    """Classify Network Zones table entries by hot key risk (CRITICAL/COARSE/FINE)."""
    from exa.hotkey.analyze import analyze_zones

    client = _make_client(tenant)
    try:
        with console.status("Reading Network Zones table..."):
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
            "recommendation": _analyze_rec(z.risk, tenant),
        }
        for z in zones
    ]

    if as_json:
        console.print(json.dumps(rows, indent=2))
        return

    if as_csv:
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=["zone_name", "key", "prefix_len", "cardinality", "risk", "recommendation"],
        )
        writer.writeheader()
        writer.writerows(rows)
        console.print(buf.getvalue(), end="")
        return

    n_critical = sum(1 for z in zones if z.risk == "CRITICAL")
    n_coarse = sum(1 for z in zones if z.risk == "COARSE")

    table = Table(title="Network Zones - Hot Key Risk", show_lines=False)
    table.add_column("Zone Name", style="white", no_wrap=True)
    table.add_column("Key (IP/Subnet)", style="dim", no_wrap=True)
    table.add_column("Prefix", justify="right")
    table.add_column("Addresses", justify="right")
    table.add_column("Risk", justify="center", no_wrap=True)

    def sort_key(z):
        return (_RISK_ORDER.get(z.risk, 99), z.prefix_len or 999, z.entry.zone_name)

    for z in sorted(zones, key=sort_key):
        style = _RISK_STYLE.get(z.risk, "")
        cardinality = f"{z.cardinality:,}" if z.cardinality is not None else "-"
        prefix = f"/{z.prefix_len}" if z.prefix_len is not None else "-"
        if z.risk == "CRITICAL":
            risk_label = "[bold red]CRITICAL[/bold red]"
        elif style:
            risk_label = f"[{style}]{z.risk}[/{style}]"
        else:
            risk_label = z.risk
        table.add_row(z.entry.zone_name, z.entry.key, prefix, cardinality, risk_label)

    console.print(table)

    # Per-tier recommendation legend (same text for all zones of a tier — no repetition)
    t = f" --tenant {tenant}" if tenant else ""
    if n_critical or n_coarse:
        parts = []
        if n_critical:
            parts.append(f"[bold red]{n_critical} CRITICAL[/bold red]")
        if n_coarse:
            parts.append(f"[red]{n_coarse} COARSE[/red]")
        console.print("\n" + " + ".join(parts) + " zone(s) require attention.")
        if n_critical:
            console.print(
                f"  [bold red]CRITICAL[/bold red]  Prefix too coarse - guaranteed hot key"
                f" risk. Run: [bold]exa hotkey expand{t}[/bold]"
            )
        if n_coarse:
            console.print(
                f"  [red]COARSE[/red]     Coarse prefix - run [bold]exa hotkey scan{t}[/bold]"
                f" to assess traffic, then expand if HOT_KEY_RISK."
            )
        console.print(
            f"\nFix all flagged zones: [bold]exa hotkey autofix{t}[/bold]"
        )
    else:
        console.print("\nNo hot key risk detected in network zones.", style="green")


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

    CRITICAL zones (/8-/16) are shown with ip_count=-- because they qualify for
    expansion regardless of observed traffic. Only COARSE zones (/17-/23) are
    traffic-scanned to determine HOT_KEY_RISK status.
    """
    from exa.hotkey.analyze import analyze_zones
    from exa.hotkey.scan import scan_zones

    client = _make_client(tenant)
    try:
        with console.status("Reading Network Zones table..."):
            zones = analyze_zones(client, ip_field=ip_field, name_field=name_field)

        critical = [z for z in zones if z.risk == "CRITICAL"]
        coarse = [z for z in zones if z.risk == "COARSE"]

        # Only scan COARSE zones; CRITICAL zones qualify without traffic confirmation
        scan_results = []
        if coarse:
            with console.status(f"Scanning events (last {lookback}d, limit {limit:,})..."):
                scan_results = scan_zones(
                    client, coarse, lookback_days=lookback, threshold=threshold, limit=limit
                )
    except ValueError as e:
        console.print(f"FAIL: {e}", style="red")
        raise typer.Exit(1)
    finally:
        client.close()

    if as_json:
        out = [
            {"zone_name": z.entry.zone_name, "key": z.entry.key, "ip_count": None,
             "risk": "CRITICAL"}
            for z in sorted(critical, key=lambda z: z.entry.zone_name)
        ] + [
            {"zone_name": r.zone_name, "ip_count": r.ip_count, "risk": r.risk}
            for r in scan_results
        ]
        console.print(json.dumps(out, indent=2))
        return

    if as_csv:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=["zone_name", "ip_count", "risk", "recommendation"])
        writer.writeheader()
        for z in sorted(critical, key=lambda z: z.entry.zone_name):
            writer.writerow({
                "zone_name": z.entry.zone_name,
                "ip_count": "--",
                "risk": "CRITICAL",
                "recommendation": _scan_rec("CRITICAL", "CRITICAL", tenant),
            })
        for r in scan_results:
            writer.writerow({
                "zone_name": r.zone_name,
                "ip_count": r.ip_count,
                "risk": r.risk,
                "recommendation": _scan_rec("COARSE", r.risk, tenant),
            })
        console.print(buf.getvalue(), end="")
        return

    hot_coarse = sum(1 for r in scan_results if r.risk == "HOT_KEY_RISK")
    table = Table(
        title=f"Network Zones - Active IP Scan (last {lookback}d)", show_lines=False
    )
    table.add_column("Zone Name", style="white", no_wrap=True)
    table.add_column("Distinct IPs", justify="right")
    table.add_column("Risk", justify="center", no_wrap=True)

    # CRITICAL zones always shown (auto-flag, no traffic query run)
    for z in sorted(critical, key=lambda z: z.entry.zone_name):
        table.add_row(z.entry.zone_name, "--", "[bold red]CRITICAL[/bold red]")

    # COARSE scan results (skip truly zero-traffic zones)
    for r in scan_results:
        if r.ip_count == 0:
            continue
        risk_style = "red" if r.risk == "HOT_KEY_RISK" else "green"
        table.add_row(
            r.zone_name,
            f"{r.ip_count:,}",
            f"[{risk_style}]{r.risk}[/{risk_style}]",
        )

    console.print(table)

    t = f" --tenant {tenant}" if tenant else ""
    if critical or hot_coarse:
        parts = []
        if critical:
            parts.append(f"[bold red]{len(critical)} CRITICAL[/bold red]")
        if hot_coarse:
            parts.append(f"[red]{hot_coarse} HOT_KEY_RISK COARSE[/red]")
        console.print("\n" + " + ".join(parts) + " zone(s) flagged.")
        if critical:
            console.print(
                "  [bold red]CRITICAL[/bold red]  Guaranteed hot key - expand regardless"
                " of traffic count."
            )
        if hot_coarse:
            console.print(
                "  [red]HOT_KEY_RISK[/red] Active hot key confirmed - split into /24s."
            )
        console.print(f"Run [bold]exa hotkey expand{t}[/bold] to fix.")


# -- expand -------------------------------------------------------------------


@hotkey_app.command("expand")
def expand(
    tenant: Annotated[str | None, typer.Option("--tenant", "-t", help=_TENANT_HELP)] = None,
    zone: Annotated[
        str | None,
        typer.Option("--zone", help="Zone name to expand (default: all CRITICAL/COARSE zones)"),
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
    Targets CRITICAL (/8-/16) and COARSE (/17-/23) zones.
    """
    from exa.hotkey.analyze import analyze_zones
    from exa.hotkey.expand import expand_zones
    from exa.hotkey.scan import _parse_grouped_rows
    from exa.search.events import search_events

    client = _make_client(tenant)
    try:
        with console.status("Reading Network Zones table..."):
            zones = analyze_zones(client, ip_field=ip_field, name_field=name_field)

        targets = [z for z in zones if z.risk in ("CRITICAL", "COARSE")]
        if zone:
            targets = [z for z in targets if z.entry.zone_name == zone]

        if not targets:
            label = f"zone '{zone}'" if zone else "any CRITICAL or COARSE zones"
            console.print(f"No targets found for {label}.", style="yellow")
            raise typer.Exit(0)

        observed_ips: list[str] | None = None
        if not enumerate_all:
            with console.status(f"Scanning events (last {lookback}d) for observed IPs..."):
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
        console.print(f"{verb} {len(targets)} zone(s) to /24 granularity...")

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
        help="Min distinct IPs in a COARSE zone to qualify for expansion",
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

    CRITICAL zones (/8-/16) are always expanded without a scan check.
    COARSE zones (/17-/23) require HOT_KEY_RISK confirmation from scan.
    Writes a rollback manifest before every change.
    Safe to schedule -- non-interactive, exits non-zero on any failure.
    """
    import json as _json
    import sys

    from rich.console import Console as _Console
    from rich.table import Table as _Table

    from exa.hotkey.analyze import analyze_zones
    from exa.hotkey.expand import expand_zones
    from exa.hotkey.scan import _parse_grouped_rows, scan_zones
    from exa.search.events import search_events

    # Progress messages go to stderr when --json so stdout stays pipeable
    err = _Console(stderr=True) if as_json else console

    client = _make_client(tenant)
    try:
        # Phase 1 - Analyze
        err.print("  [1/3] Analyzing Network Zones table...", style="dim")
        try:
            zones = analyze_zones(client, ip_field=ip_field, name_field=name_field)
        except ValueError as e:
            err.print(f"FAIL: {e}", style="red")
            raise typer.Exit(1)

        critical = [z for z in zones if z.risk == "CRITICAL"]
        coarse = [z for z in zones if z.risk == "COARSE"]

        if not critical and not coarse:
            err.print("No CRITICAL or COARSE zones found. Nothing to do.", style="green")
            raise typer.Exit(0)

        # Phase 2 - Scan (COARSE only; CRITICAL zones qualify without traffic confirmation)
        hot_coarse: list = []
        if critical and not coarse:
            err.print(
                f"  [2/3] {len(critical)} CRITICAL zone(s) auto-flagged - scan not required.",
                style="dim",
            )
        else:
            scan_label = (
                f"{len(critical)} CRITICAL auto-flagged; scanning {len(coarse)} COARSE zone(s)..."
                if critical
                else f"Scanning {len(coarse)} COARSE zone(s) for active traffic..."
            )
            err.print(f"  [2/3] {scan_label}", style="dim")
            scans = scan_zones(
                client, coarse, lookback_days=lookback, threshold=threshold, limit=limit
            )
            hot_coarse = [s for s in scans if s.risk == "HOT_KEY_RISK"]

        total_qualifying = len(critical) + len(hot_coarse)

        if total_qualifying == 0:
            err.print(
                f"No zones require expansion (0 CRITICAL, COARSE below threshold={threshold}).",
                style="green",
            )
            raise typer.Exit(0)

        # Safety cap applies to total qualifying (CRITICAL + HOT_KEY_RISK COARSE)
        if total_qualifying > max_zones:
            cap_msg = (
                f"FAIL: {total_qualifying} zones qualify but --max-zones={max_zones}. "
                f"Re-run with --max-zones {total_qualifying} to proceed, "
                f"or use 'exa hotkey expand --zone NAME' to fix individually."
            )
            err.print(cap_msg, style="red",
            )
            raise typer.Exit(1)

        # Phase 3 - Expand CRITICAL + hot COARSE zones
        verb = "[DRY RUN] Would expand" if dry_run else "Expanding"
        err.print(f"  [3/3] {verb} {total_qualifying} zone(s) to /24 granularity...", style="dim")

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

        # CRITICAL always qualifies; add COARSE zones confirmed HOT_KEY_RISK by scan
        hot_coarse_names = {s.zone_name for s in hot_coarse}
        target_zones = critical + [
            z for z in coarse if z.entry.zone_name in hot_coarse_names
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
            sys.stdout.write(_json.dumps({
                "zone": r["zone_name"],
                "old_key": r["old_key"],
                "new_entries": r["new_key_count"],
                "status": r["status"],
            }) + "\n")
        return

    tbl = _Table(title="Autofix Results", show_lines=False)
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
            f"\n{len(results)} zone(s) expanded - rollback manifests at "
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
        with console.status("Applying rollback..."):
            apply_rollback(client, m, table_id=m.table_id)
    except Exception as e:
        console.print(f"FAIL: Rollback failed: {e}", style="red")
        raise typer.Exit(1)
    finally:
        client.close()

    console.print("Rollback applied.", style="green")

"""Zones CLI commands — export, remove, import for the Network Zones context table."""

from __future__ import annotations

import csv
import ipaddress
from collections import Counter
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from exa.client import ExaClient

zones_app = typer.Typer(
    name="zones",
    no_args_is_help=True,
)
console = Console()

# Parentheses required for TEXT options — Rich interprets [brackets] as markup
# and silently drops unknown tags.  Bool toggle flags use [default: X] (safe).
_TENANT_HELP = "Tenant nickname or FQDN (default: saved default)"


@zones_app.callback()
def _zones_group() -> None:
    """Manage the Network Zones context table.

    All writes snapshot the full table and save a rollback manifest to
    ~/.exa/hotkey-rollback/<tenant>/ before touching the API. Undo with:
      exa hotkey rollback --tenant TENANT

    The Network Zones table is OOTB (source=Exabeam). deleteRecords returns
    HTTP 404 (EXA-COLLECTOR-API-9). Every write uses full-table replace.

    \b
    Typical edit workflow:
      exa zones export --tenant TENANT                               # 1 save state
      # edit the generated CSV in your editor                       # 2 make changes
      exa zones import --csv zones.csv --dry-run --tenant TENANT    # 3 preview diff
      exa zones import --csv zones.csv --confirm --tenant TENANT    # 4 apply
    """


def _make_client(tenant: str | None = None) -> ExaClient:
    from exa.client import ExaClient

    client = ExaClient(tenant=tenant)
    client.authenticate()
    return client


# -- export -------------------------------------------------------------------


@zones_app.command("export")
def zones_export(
    output: Annotated[
        str | None,
        typer.Option(
            "--output",
            "-o",
            help="Output file path (default: zones-TENANT-DATE.csv)",
        ),
    ] = None,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Dump the current Network Zones table to a CSV file.

    Output columns: cidr_range, zone_name. Read-only — no writes to the table.
    The CSV can be passed directly to 'exa zones import' after editing.

    \b
    Examples:
      uv run exa zones export --tenant csnafusion
      uv run exa zones export -o backup.csv --tenant csnafusion
      uv run exa zones export -o zones-$(date +%F).csv --tenant csnafusion
    """
    from exa.zones.table import get_zones_snapshot

    client = _make_client(tenant)
    try:
        with console.status("Reading Network Zones table..."):
            snap = get_zones_snapshot(client)
    except ValueError as e:
        console.print(f"FAIL: {e}", style="red")
        raise typer.Exit(1)
    finally:
        client.close()

    tenant_label = tenant or "default"
    out_path = (
        Path(output) if output else Path(f"zones-{tenant_label}-{date.today()}.csv")
    )

    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["cidr_range", "zone_name"])
        for rec in snap.records:
            writer.writerow([rec.get(snap.ip_field, ""), rec.get(snap.name_field, "")])

    console.print(f"  {len(snap.records):,} rows -> {out_path}", style="green")


# -- remove -------------------------------------------------------------------


def _matches_remove_filter(
    rec: dict[str, Any],
    ip_field: str,
    name_field: str,
    cidrs: set[str],
    zones: set[str],
    patterns: list[str],
) -> bool:
    """Return True if this record should be removed by the given filters."""
    key = rec.get(ip_field, "")
    name = rec.get(name_field, "")
    if key in cidrs:
        return True
    if name in zones:
        return True
    name_lower = name.lower()
    return any(p.lower() in name_lower for p in patterns)


@zones_app.command("remove")
def zones_remove(
    cidr: Annotated[
        list[str],
        typer.Option(
            "--cidr",
            help="Exact CIDR range to remove, e.g. 10.0.0.0/8 (repeatable)",
        ),
    ] = [],
    zone: Annotated[
        list[str],
        typer.Option(
            "--zone",
            help="Remove all entries with this exact zone name (repeatable)",
        ),
    ] = [],
    pattern: Annotated[
        list[str],
        typer.Option(
            "--pattern",
            help="Remove entries whose zone_name contains this substring, "
            "case-insensitive (repeatable)",
        ),
    ] = [],
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run/--no-dry-run",
            help="Print the removal table without writing to the API [default: no-dry-run]",
        ),
    ] = False,
    confirm: Annotated[
        bool,
        typer.Option(
            "--confirm/--no-confirm",
            help="Skip the interactive confirmation prompt [default: no-confirm]",
        ),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Remove specific entries from Network Zones without touching the rest.

    Filters --cidr / --zone / --pattern are OR-combined: a record is removed
    if it matches any one of them. At least one filter is required.

    Always prints the full removal table before acting. Use --dry-run to stop
    there. Writes a rollback manifest before the replace call; undo with:
      exa hotkey rollback --tenant TENANT

    \b
    Examples:
      uv run exa zones remove --cidr 10.0.0.0/8 --dry-run --tenant csnafusion
      uv run exa zones remove --zone "US-Denver" --confirm --tenant csnafusion
      uv run exa zones remove --pattern "Net_10" --dry-run --tenant csnafusion
      uv run exa zones remove --cidr 10.0.0.0/8 --cidr 172.16.0.0/12 \\
          --dry-run --tenant csnafusion
    """
    from exa.context.tables import add_records
    from exa.hotkey.rollback import write_manifest
    from exa.zones.table import get_zones_snapshot

    if not cidr and not zone and not pattern:
        console.print(
            "At least one of --cidr, --zone, or --pattern is required.", style="red"
        )
        raise typer.Exit(1)

    client = _make_client(tenant)
    try:
        with console.status("Reading Network Zones table..."):
            snap = get_zones_snapshot(client)
    except ValueError as e:
        console.print(f"FAIL: {e}", style="red")
        raise typer.Exit(1)
    finally:
        client.close()

    cidr_set = set(cidr)
    zone_set = set(zone)

    to_remove = [
        r for r in snap.records
        if _matches_remove_filter(
            r, snap.ip_field, snap.name_field, cidr_set, zone_set, pattern
        )
    ]
    to_keep = [r for r in snap.records if r not in to_remove]

    if not to_remove:
        console.print("  No records matched the given filters.", style="yellow")
        raise typer.Exit(0)

    tbl = Table(title="Records to Remove", show_lines=False)
    tbl.add_column("CIDR", style="dim", no_wrap=True)
    tbl.add_column("Zone Name", style="white")
    for rec in to_remove:
        tbl.add_row(rec.get(snap.ip_field, ""), rec.get(snap.name_field, ""))
    console.print(tbl)
    console.print(
        f"  {len(to_remove)} of {len(snap.records)} records would be removed."
    )

    if dry_run:
        console.print("  [yellow][dry-run][/yellow] No changes written.")
        raise typer.Exit(0)

    if not confirm:
        proceed = typer.confirm(
            f"Remove {len(to_remove)} record(s) from '{snap.table_display_name}'?",
            default=False,
        )
        if not proceed:
            console.print("  Aborted.", style="dim")
            raise typer.Exit(0)

    client = _make_client(tenant)
    try:
        manifest_path = write_manifest(
            tenant=tenant or "default",
            table_id=snap.table_id,
            table_display_name=snap.table_display_name,
            zone_name="(zones remove)",
            original_records=snap.records,
            added_keys=[],
        )
        add_records(client, snap.table_id, to_keep, operation="replace")
    except Exception as e:
        console.print(f"FAIL: {e}", style="red")
        raise typer.Exit(1)
    finally:
        client.close()

    console.print(
        f"  Removed {len(to_remove)} record(s). {len(to_keep)} remaining.",
        style="green",
    )
    console.print(f"  Rollback manifest: [dim]{manifest_path}[/dim]")
    console.print("  Undo with: [bold]exa hotkey rollback[/bold]")


# -- import -------------------------------------------------------------------


def _validate_csv(path: Path) -> tuple[list[dict[str, str]], list[tuple[int, str]]]:
    """Read and validate a zones CSV. Returns (rows, errors).

    Required columns: cidr_range, zone_name.
    Each error entry is (row_number, bad_cidr_value).
    """
    rows: list[dict[str, str]] = []
    errors: list[tuple[int, str]] = []

    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        missing = {"cidr_range", "zone_name"} - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV missing required columns: {', '.join(sorted(missing))}")
        for row_num, row in enumerate(reader, start=2):
            cidr_val = (row.get("cidr_range") or "").strip()
            zone_val = (row.get("zone_name") or "").strip()
            try:
                ipaddress.ip_network(cidr_val, strict=False)
            except ValueError:
                errors.append((row_num, cidr_val))
            rows.append({"cidr_range": cidr_val, "zone_name": zone_val})

    return rows, errors


def _prefix_distribution(rows: list[dict[str, str]]) -> str:
    """Format prefix length distribution as '/<len> (n), ...' from CSV rows."""
    counts: Counter[int] = Counter()
    for row in rows:
        try:
            net = ipaddress.ip_network(row["cidr_range"], strict=False)
            counts[net.prefixlen] += 1
        except ValueError:
            pass
    parts = [f"/{pl} ({n})" for pl, n in sorted(counts.items())]
    return ", ".join(parts) if parts else "(none)"


@zones_app.command("import")
def zones_import(
    csv_path: Annotated[
        str,
        typer.Option(
            "--csv",
            "-f",
            help="CSV file to load; must have columns cidr_range and zone_name",
        ),
    ] = ...,
    mode: Annotated[
        str,
        typer.Option(
            "--mode",
            help=(
                "'replace' overwrites the entire table with CSV rows; "
                "'merge' upserts CSV rows and keeps existing records not in the CSV "
                "(default: replace)"
            ),
        ),
    ] = "replace",
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run/--no-dry-run",
            help="Show the diff or merge summary without writing [default: no-dry-run]",
        ),
    ] = False,
    confirm: Annotated[
        bool,
        typer.Option(
            "--confirm/--no-confirm",
            help="Skip the interactive confirmation prompt [default: no-confirm]",
        ),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Replace or merge the Network Zones table from a CSV file.

    CSV validation runs before any API call:
      - Required columns: cidr_range, zone_name
      - Every cidr_range is checked with ipaddress.ip_network()
      - Invalid rows are listed with row number and bad value; exits 1 if any

    On success, prints row count, unique zone names, and prefix distribution.
    Writes a rollback manifest before the replace call; undo with:
      exa hotkey rollback --tenant TENANT

    \b
    Examples:
      uv run exa zones import --csv zones.csv --dry-run --tenant csnafusion
      uv run exa zones import --csv zones.csv --confirm --tenant csnafusion
      uv run exa zones import --csv new-zones.csv --mode merge --dry-run \\
          --tenant csnafusion
      uv run exa zones import --csv zones.csv --mode replace --confirm \\
          --tenant csnafusion
    """
    from exa.context.tables import add_records
    from exa.hotkey.rollback import write_manifest
    from exa.zones.table import get_zones_snapshot

    if mode not in ("replace", "merge"):
        console.print(
            f"Invalid --mode '{mode}'. Choose 'replace' or 'merge'.", style="red"
        )
        raise typer.Exit(1)

    in_path = Path(csv_path)
    if not in_path.exists():
        console.print(f"File not found: {in_path}", style="red")
        raise typer.Exit(1)

    try:
        csv_rows, errors = _validate_csv(in_path)
    except ValueError as e:
        console.print(f"FAIL: {e}", style="red")
        raise typer.Exit(1)

    if errors:
        for row_num, bad_val in errors:
            console.print(f"  Row {row_num}: invalid CIDR '{bad_val}'", style="red")
        console.print(
            f"  {len(errors)} validation error(s). Fix CSV and retry.", style="red"
        )
        raise typer.Exit(1)

    from exa.hotkey.analyze import _CRITICAL_PREFIX_MAX

    critical_rows = []
    for r in csv_rows:
        net = ipaddress.ip_network(r["cidr_range"], strict=False)
        if net.prefixlen <= _CRITICAL_PREFIX_MAX:
            critical_rows.append((r["cidr_range"], r["zone_name"], net.prefixlen))
    if critical_rows:
        for cidr_val, zone_val, prefix in critical_rows:
            console.print(
                f"  CRITICAL hotkey risk: {cidr_val} (/{prefix}) '{zone_val}'",
                style="red",
            )
        console.print(
            f"  {len(critical_rows)} CIDR(s) with prefix <= /{_CRITICAL_PREFIX_MAX} blocked -- "
            f"guaranteed Dataflow hot key risk. Split to /24s or remove before importing.",
            style="red",
        )
        raise typer.Exit(1)

    unique_zones = len({r["zone_name"] for r in csv_rows})
    console.print(
        f"  CSV: {len(csv_rows):,} rows, {unique_zones} unique zone name(s) | "
        f"prefixes: {_prefix_distribution(csv_rows)}"
    )

    client = _make_client(tenant)
    try:
        with console.status("Reading Network Zones table..."):
            snap = get_zones_snapshot(client)
    except ValueError as e:
        console.print(f"FAIL: {e}", style="red")
        raise typer.Exit(1)
    finally:
        client.close()

    ip_f = snap.ip_field
    name_f = snap.name_field
    csv_by_key = {r["cidr_range"]: r for r in csv_rows}
    existing_by_key = {r.get(ip_f, ""): r for r in snap.records}

    if mode == "replace":
        final_records = [
            {ip_f: r["cidr_range"], name_f: r["zone_name"]} for r in csv_rows
        ]
        removed_count = len(set(existing_by_key) - set(csv_by_key))
        added_count = len(set(csv_by_key) - set(existing_by_key))
        unchanged_count = len(set(existing_by_key) & set(csv_by_key))
        console.print(
            f"  Diff (replace): [red]{removed_count} removed[/red], "
            f"[green]{added_count} added[/green], "
            f"{unchanged_count} unchanged"
        )
    else:  # merge
        merged = dict(existing_by_key)
        for cidr_key, row in csv_by_key.items():
            merged[cidr_key] = {ip_f: cidr_key, name_f: row["zone_name"]}
        final_records = list(merged.values())
        new_or_updated = len(csv_by_key)
        kept = len(set(existing_by_key) - set(csv_by_key))
        console.print(
            f"  Diff (merge): {kept} existing kept, "
            f"[green]{new_or_updated} CSV records merged[/green] "
            f"({len(final_records)} total)"
        )

    if dry_run:
        console.print(
            f"  [yellow][dry-run][/yellow] Would write {len(final_records):,} records."
        )
        raise typer.Exit(0)

    if not confirm:
        proceed = typer.confirm(
            f"Write {len(final_records):,} records to '{snap.table_display_name}'?",
            default=False,
        )
        if not proceed:
            console.print("  Aborted.", style="dim")
            raise typer.Exit(0)

    client = _make_client(tenant)
    try:
        manifest_path = write_manifest(
            tenant=tenant or "default",
            table_id=snap.table_id,
            table_display_name=snap.table_display_name,
            zone_name="(zones import)",
            original_records=snap.records,
            added_keys=[],
        )
        add_records(client, snap.table_id, final_records, operation="replace")
    except Exception as e:
        console.print(f"FAIL: {e}", style="red")
        raise typer.Exit(1)
    finally:
        client.close()

    console.print(
        f"  {len(final_records):,} records written to '{snap.table_display_name}'.",
        style="green",
    )
    console.print(f"  Rollback manifest: [dim]{manifest_path}[/dim]")
    console.print("  Undo with: [bold]exa hotkey rollback[/bold]")

"""CLI sub-app for context table management.

  exa tables list              — list tables
  exa tables create            — create a table, optionally uploading a CSV
  exa tables delete            — delete a table
  exa tables records list      — read records from a table
  exa tables records upload    — upload records from a CSV
  exa tables records export    — export all records to a CSV
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from exa.client import ExaClient

tables_app = typer.Typer(
    name="tables",
    help="Context table management — list, create, delete, and manage records.",
    no_args_is_help=True,
)
records_app = typer.Typer(
    name="records",
    help="Record operations for a context table.",
    no_args_is_help=True,
)
tables_app.add_typer(records_app)

console = Console()
_TENANT_HELP = "Tenant nickname or FQDN (default: saved default)"


def _make_client(tenant: str | None = None) -> ExaClient:
    from exa.client import ExaClient

    client = ExaClient(tenant=tenant)
    client.authenticate()
    return client


def _resolve_table_id(client: ExaClient, id_or_name: str) -> str:
    """Resolve a table ID or display name to a table ID.

    Strings without spaces are tried as a direct ID first (Exabeam table IDs are
    10-char alphanumeric, not UUID format). Falls back to name substring match.
    """
    from exa.context import get_table, get_tables

    if " " not in id_or_name:
        try:
            get_table(client, id_or_name)
            return id_or_name
        except Exception:
            pass

    matches = get_tables(client, name=id_or_name)
    if len(matches) == 0:
        console.print(f"Table not found: '{id_or_name}'", style="red")
        raise typer.Exit(1)
    if len(matches) == 1:
        return matches[0]["id"]

    console.print("Ambiguous name — use table ID:", style="red")
    for m in matches:
        console.print(f"  {m['id']}  {m.get('displayName', m.get('name', '?'))}")
    raise typer.Exit(1)


def _fmt_ts(ts: int | None) -> str:
    """Format a Unix timestamp (seconds or milliseconds) to YYYY-MM-DD."""
    if not ts:
        return ""
    try:
        epoch_s = ts // 1000 if ts > 9_999_999_999 else ts
        return datetime.fromtimestamp(epoch_s, tz=UTC).strftime("%Y-%m-%d")
    except (ValueError, OSError):
        return str(ts)


# ---------------------------------------------------------------------------
# Pure CSV helpers — tested directly without mocking
# ---------------------------------------------------------------------------


def _parse_csv_file(path: str) -> tuple[list[str], list[dict[str, str]]]:
    """Return (headers, rows). Strips whitespace from keys/values; skips blank rows."""
    import csv as _csv

    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = _csv.DictReader(fh)
        if not reader.fieldnames:
            return [], []
        headers = [h.strip() for h in reader.fieldnames]
        rows: list[dict[str, str]] = []
        for raw in reader:
            row = {k.strip(): v.strip() for k, v in raw.items()}
            if all(v == "" for v in row.values()):
                continue
            rows.append(row)
    return headers, rows


def _derive_attributes(headers: list[str], key_col: str) -> list[dict[str, Any]]:
    """Build an attributes list from CSV headers.

    Args:
        headers: Ordered column names from the CSV.
        key_col: Which column is the table key.

    Returns:
        List of attribute dicts suitable for create_table().

    Raises:
        ValueError: If key_col is not present in headers.
    """
    if key_col not in headers:
        raise ValueError(
            f"Key column '{key_col}' not found in CSV headers: {headers}"
        )
    return [{"id": col, "isKey": col == key_col} for col in headers]


# ---------------------------------------------------------------------------
# exa tables list
# ---------------------------------------------------------------------------


@tables_app.command("list")
def tables_list(
    name: Annotated[
        str | None,
        typer.Option("--name", "-n", help="Filter tables by name substring"),
    ] = None,
    json_out: Annotated[
        bool,
        typer.Option("--json", help="Output each table as a JSON line (ndjson)"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """List context tables."""
    import json as _json
    import sys

    from exa.context import get_tables

    client = _make_client(tenant)
    try:
        data = get_tables(client, name=name)

        if json_out:
            for t in data:
                sys.stdout.write(_json.dumps(t) + "\n")
            return

        tbl = Table(show_header=True, header_style="bold")
        tbl.add_column("ID")
        tbl.add_column("Name")
        tbl.add_column("Type")
        tbl.add_column("Source")
        tbl.add_column("Records", justify="right")
        tbl.add_column("Updated")

        for t in data:
            display = t.get("displayName") or t.get("name", "")
            tbl.add_row(
                t.get("id", ""),
                display,
                t.get("contextType", ""),
                t.get("source", ""),
                str(t.get("totalItems", "")),
                _fmt_ts(t.get("lastUpdated")),
            )

        console.print(tbl)
        console.print(f"  {len(data)} tables", style="dim")
    finally:
        client.close()


# ---------------------------------------------------------------------------
# exa tables create
# ---------------------------------------------------------------------------


@tables_app.command("create")
def tables_create(
    name: Annotated[str, typer.Argument(help="Display name for the new table")],
    context_type: Annotated[
        str,
        typer.Option(
            "--type",
            help="Context type: Other, User, TI_ips, TI_domains, Device, Domain, IP",
        ),
    ] = "Other",
    key_col: Annotated[
        str,
        typer.Option("--key", metavar="COLNAME", help="Name of the key column"),
    ] = "key",
    columns: Annotated[
        str | None,
        typer.Option(
            "--columns",
            metavar="a,b,c",
            help="Extra column names (ignored when --csv is given)",
        ),
    ] = None,
    csv_path: Annotated[
        str | None,
        typer.Option("--csv", metavar="PATH", help="CSV file to upload after creation"),
    ] = None,
    replace: Annotated[
        bool,
        typer.Option("--replace", help="Use replace operation for the initial CSV upload"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Create a context table, optionally uploading records from a CSV."""
    from exa.context import add_records, create_table

    if csv_path:
        headers, rows = _parse_csv_file(csv_path)
        if not headers:
            console.print("CSV is empty or has no headers.", style="red")
            raise typer.Exit(1)
        if key_col not in headers:
            console.print(
                f"Key column '{key_col}' not found in CSV. "
                f"Available: {', '.join(headers)}",
                style="red",
            )
            raise typer.Exit(1)
        attrs = _derive_attributes(headers, key_col)
    else:
        extra = [c.strip() for c in columns.split(",") if c.strip()] if columns else []
        attrs = [{"id": key_col, "isKey": True}]
        attrs += [{"id": col, "isKey": False} for col in extra]
        rows = []

    client = _make_client(tenant)
    try:
        result = create_table(client, name, context_type=context_type, attributes=attrs)
        table_obj = result.get("table", result)
        table_id = table_obj.get("id", "")
        console.print(f"Created table '{name}' (id: {table_id})", style="green")

        if csv_path and rows:
            operation = "replace" if replace else "append"
            console.print(
                f"  Uploading {len(rows):,} records ({operation})...", style="dim"
            )
            add_records(client, table_id, rows, operation=operation)
            console.print(f"  {len(rows):,} records uploaded", style="green")
    finally:
        client.close()


# ---------------------------------------------------------------------------
# exa tables delete
# ---------------------------------------------------------------------------


@tables_app.command("delete")
def tables_delete(
    table: Annotated[str, typer.Argument(help="Table ID or display name")],
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip the confirmation prompt"),
    ] = False,
    purge_attributes: Annotated[
        bool,
        typer.Option(
            "--purge-attributes",
            help="Delete unused custom attributes along with the table",
        ),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Delete a context table."""
    from exa.context import delete_table, get_table

    client = _make_client(tenant)
    try:
        table_id = _resolve_table_id(client, table)
        resp = get_table(client, table_id)
        table_obj = resp.get("table", resp)
        display = table_obj.get("displayName", table_obj.get("name", table_id))

        if not yes:
            confirm = typer.prompt(
                f"Delete table '{display}' (id: {table_id})? [y/N]",
                default="N",
            )
            if confirm.strip().lower() != "y":
                raise typer.Exit(0)

        delete_table(client, table_id, delete_unused_attributes=purge_attributes)
        console.print(f"Deleted table '{display}'", style="green")
    finally:
        client.close()


# ---------------------------------------------------------------------------
# exa tables records list
# ---------------------------------------------------------------------------


@records_app.command("list")
def records_list(
    table: Annotated[str, typer.Argument(help="Table ID or display name")],
    limit: Annotated[
        int,
        typer.Option("--limit", help="Max records to return"),
    ] = 1000,
    offset: Annotated[
        int,
        typer.Option("--offset", help="Pagination offset"),
    ] = 0,
    csv_path: Annotated[
        str | None,
        typer.Option("--csv", metavar="PATH", help="Write records to a CSV file"),
    ] = None,
    json_out: Annotated[
        bool,
        typer.Option("--json", help="Output each record as a JSON line"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """List records from a context table."""
    import csv as _csv
    import json as _json
    import sys

    from exa.context import get_records

    client = _make_client(tenant)
    try:
        table_id = _resolve_table_id(client, table)
        resp = get_records(client, table_id, limit=limit, offset=offset)
        records = resp.get("records", resp) if isinstance(resp, dict) else list(resp)

        if not records:
            console.print("  0 records", style="dim")
            return

        if json_out:
            for r in records:
                sys.stdout.write(_json.dumps(r) + "\n")
            return

        if csv_path:
            cols = list(records[0].keys())
            with open(csv_path, "w", newline="", encoding="utf-8") as fh:
                writer = _csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(records)
            console.print(
                f"  {len(records):,} records written to {csv_path}", style="dim"
            )
            return

        cols = list(records[0].keys())
        tbl = Table(show_header=True, header_style="bold")
        for col in cols:
            tbl.add_column(col)
        for r in records:
            tbl.add_row(*[str(r.get(c, "")) for c in cols])
        console.print(tbl)
        console.print(f"  {len(records):,} records", style="dim")
    finally:
        client.close()


# ---------------------------------------------------------------------------
# exa tables records upload
# ---------------------------------------------------------------------------


@records_app.command("upload")
def records_upload(
    table: Annotated[str, typer.Argument(help="Table ID or display name")],
    csv_file: Annotated[str, typer.Argument(help="Path to CSV file")],
    replace: Annotated[
        bool,
        typer.Option("--replace", help="Replace entire table contents (default: append)"),
    ] = False,
    key_col: Annotated[
        str | None,
        typer.Option("--key", metavar="COLNAME", help="Assert which column is the key"),
    ] = None,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Upload records from a CSV file to a context table."""
    from exa.context import add_records

    headers, rows = _parse_csv_file(csv_file)
    if not headers:
        console.print("CSV is empty or has no headers.", style="red")
        raise typer.Exit(1)

    if key_col and key_col not in headers:
        console.print(
            f"Key column '{key_col}' not found. Available: {', '.join(headers)}",
            style="red",
        )
        raise typer.Exit(1)

    if not rows:
        console.print("CSV has no data rows.", style="red")
        raise typer.Exit(1)

    client = _make_client(tenant)
    try:
        table_id = _resolve_table_id(client, table)
        operation = "replace" if replace else "append"
        console.print(
            f"  Uploading {len(rows):,} records ({operation})...", style="dim"
        )
        add_records(client, table_id, rows, operation=operation)
        console.print(
            f"  {len(rows):,} records uploaded to '{table}' (operation: {operation})",
            style="green",
        )
    finally:
        client.close()


# ---------------------------------------------------------------------------
# exa tables records export
# ---------------------------------------------------------------------------


@records_app.command("export")
def records_export(
    table: Annotated[str, typer.Argument(help="Table ID or display name")],
    output_path: Annotated[str, typer.Argument(help="Output CSV file path")],
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Export all records from a context table to a CSV file."""
    import csv as _csv

    from exa.context.tables import get_all_records

    client = _make_client(tenant)
    try:
        table_id = _resolve_table_id(client, table)
        console.print("  Fetching all records...", style="dim")
        records = get_all_records(client, table_id)

        if not records:
            console.print("  0 records", style="dim")
            return

        cols = list(records[0].keys())
        with open(output_path, "w", newline="", encoding="utf-8") as fh:
            writer = _csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(records)

        console.print(
            f"  {len(records):,} records exported to {output_path}", style="green"
        )
    finally:
        client.close()

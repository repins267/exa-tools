"""CLI commands for Detection (analytics) rule management.

  exa detection list     — list rules with optional filters
  exa detection get      — get a single rule by ID
  exa detection enable   — enable a rule
  exa detection disable  — disable a rule
  exa detection export   — export rules to a JSON file
  exa detection import   — import rules from a JSON file
  exa detection diff     — diff two exported rule bundles
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

detection_app = typer.Typer(
    name="detection",
    help="Analytics (detection) rule management.",
    no_args_is_help=True,
)

console = Console()

_TENANT_HELP = "Tenant nickname or FQDN [default: saved default]"


def _make_client(tenant: str | None = None):
    from exa.client import ExaClient

    client = ExaClient(tenant=tenant)
    client.authenticate()
    return client


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

_CSV_FIELDS = ["id", "name", "isEnabled", "severity", "type", "families", "author",
               "createdAt", "updatedAt", "description"]


@detection_app.command("list")
def detection_list(
    name: Annotated[
        str | None,
        typer.Option("--name", "-n", help="Filter by rule name (substring)"),
    ] = None,
    status: Annotated[
        str | None,
        typer.Option("--status", "-s", help='Filter by status: "enabled" or "disabled"'),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", help="Max rules to return; 0 returns all rules [default: 100]"),
    ] = 100,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
    json_out: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Output as JSON to stdout or --output file [default: no-json]"),
    ] = False,
    csv_out: Annotated[
        bool,
        typer.Option("--csv/--no-csv", help="Output as CSV to stdout or --output file [default: no-csv]"),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write output to file instead of stdout"),
    ] = None,
) -> None:
    """List analytics/detection rules with optional filters and export.

    Fetches all rules from the API and applies name/status filters client-side.
    Use --limit 0 to return all rules (default 100). Results can be exported as
    JSON or CSV with --json/--csv; combine with --output to write to a file.

    \b
    Examples:
      uv run exa detection list
      uv run exa detection list --name "[Sigma]*" --status enabled
      uv run exa detection list --limit 0 --csv --output rules.csv
      uv run exa detection list --json --output all-rules.json --tenant csnafusion
    """
    from exa.detection import get_detection_rules

    effective_limit = None if limit == 0 else limit
    client = _make_client(tenant)
    try:
        rules = get_detection_rules(client, name=name, status=status, limit=effective_limit)

        # ── JSON ──────────────────────────────────────────────────────────────
        if json_out:
            payload = json.dumps(rules, indent=2)
            if output:
                output.write_text(payload, encoding="utf-8")
                console.print(f"Wrote {len(rules)} rules -> [bold]{output}[/bold]")
            else:
                console.print_json(payload)
            return

        # ── CSV ───────────────────────────────────────────────────────────────
        if csv_out:
            # Use fields present in the first rule + our preferred order
            sample = rules[0] if rules else {}
            extra = [k for k in sample if k not in _CSV_FIELDS]
            fields = [f for f in _CSV_FIELDS if f in sample or f in ("id", "name", "isEnabled", "severity")] + extra

            dest = open(output, "w", newline="", encoding="utf-8") if output else sys.stdout
            try:
                writer = csv.DictWriter(dest, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                for r in rules:
                    row = {f: r.get(f, "") for f in fields}
                    # Flatten lists (e.g. families, mitre) to semicolon-separated strings
                    for k, v in row.items():
                        if isinstance(v, list):
                            row[k] = "; ".join(str(x) for x in v)
                        elif isinstance(v, dict):
                            row[k] = json.dumps(v)
                    writer.writerow(row)
            finally:
                if output:
                    dest.close()
            if output:
                console.print(f"Wrote {len(rules)} rules -> [bold]{output}[/bold]")
            return

        # ── Rich table ────────────────────────────────────────────────────────
        sample = rules[0] if rules else {}
        has_type = "type" in sample
        has_families = "families" in sample

        cols = ["ID", "Name", "Enabled", "Severity"]
        if has_type:
            cols.append("Type")
        if has_families:
            cols.append("Families")

        tbl = Table(*cols, show_header=True, header_style="bold")
        for r in rules:
            enabled_val = r.get("isEnabled")
            enabled_str = ("[green]yes[/green]" if enabled_val is True
                           else "[dim]no[/dim]" if enabled_val is False else "")
            families_val = r.get("families", [])
            families_str = "; ".join(str(f) for f in families_val) if isinstance(families_val, list) else str(families_val)

            row = [r.get("id", ""), r.get("name", ""), enabled_str, r.get("severity", "")]
            if has_type:
                row.append(r.get("type", ""))
            if has_families:
                row.append(families_str)
            tbl.add_row(*row)

        console.print(tbl)
        console.print(f"\n  {len(rules)} rules", style="dim")
        if has_type:
            types = sorted({r.get("type", "") for r in rules if r.get("type")})
            console.print(f"  Rule types: {', '.join(types)}", style="dim")
    finally:
        client.close()


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------

@detection_app.command("get")
def detection_get(
    rule_id: Annotated[str, typer.Argument(help="Rule UUID")],
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
    json_out: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Output raw JSON [default: no-json]"),
    ] = False,
) -> None:
    """Get full details for a single detection rule by UUID.

    \b
    Examples:
      uv run exa detection get <rule-uuid>
      uv run exa detection get <rule-uuid> --json
      uv run exa detection get <rule-uuid> --tenant csnafusion
    """
    from exa.detection import get_detection_rule

    client = _make_client(tenant)
    try:
        rule = get_detection_rule(client, rule_id)
        if json_out:
            console.print_json(json.dumps(rule))
            return
        for k, v in rule.items():
            console.print(f"  {k:<20} {v}")
    finally:
        client.close()


# ---------------------------------------------------------------------------
# enable / disable
# ---------------------------------------------------------------------------

@detection_app.command("enable")
def detection_enable(
    rule_id: Annotated[str, typer.Argument(help="Rule UUID")],
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Enable a detection rule by UUID.

    \b
    Examples:
      uv run exa detection enable <rule-uuid>
      uv run exa detection enable <rule-uuid> --tenant csnafusion
    """
    from exa.detection import set_detection_rule_state

    client = _make_client(tenant)
    try:
        set_detection_rule_state(client, rule_id, enabled=True)
        console.print(f"Enabled: {rule_id}", style="green")
    finally:
        client.close()


@detection_app.command("disable")
def detection_disable(
    rule_id: Annotated[str, typer.Argument(help="Rule UUID")],
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Disable a detection rule by UUID.

    \b
    Examples:
      uv run exa detection disable <rule-uuid>
      uv run exa detection disable <rule-uuid> --tenant csnafusion
    """
    from exa.detection import set_detection_rule_state

    client = _make_client(tenant)
    try:
        set_detection_rule_state(client, rule_id, enabled=False)
        console.print(f"Disabled: {rule_id}", style="yellow")
    finally:
        client.close()


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

@detection_app.command("export")
def detection_export(
    output: Annotated[
        Path,
        typer.Argument(help="Output JSON file path"),
    ],
    rule_ids: Annotated[
        list[str] | None,
        typer.Option("--id", help="Rule ID to export (repeat for multiple)"),
    ] = None,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Export detection rules to a portable JSON bundle file.

    Omit --id to export all rules (fetches rule list automatically). Use --id
    once per rule UUID to export a specific subset. The bundle format is
    compatible with 'exa detection import' and can be diffed with
    'exa detection diff'.

    \b
    Examples:
      uv run exa detection export all-rules.json
      uv run exa detection export subset.json --id <uuid1> --id <uuid2>
      uv run exa detection export all-rules.json --tenant csnafusion
    """
    from exa.detection import export_rules

    client = _make_client(tenant)
    try:
        bundle = export_rules(client, rule_ids=rule_ids if rule_ids else None)
        output.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        count = len(bundle.get("ruleDefinitions", []))
        console.print(f"Exported {count} rules to {output}", style="green")
    finally:
        client.close()


# ---------------------------------------------------------------------------
# import
# ---------------------------------------------------------------------------

@detection_app.command("import")
def detection_import(
    input_file: Annotated[
        Path,
        typer.Argument(help="JSON bundle file (from 'detection export')"),
    ],
    overwrite: Annotated[
        bool,
        typer.Option("--overwrite/--no-overwrite", help="Overwrite existing rules with same ID [default: no-overwrite]"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Import detection rules from a JSON bundle file.

    The bundle must be in the format produced by 'exa detection export'. By
    default, rules that already exist (matching ID) are skipped; use
    --overwrite to replace them.

    \b
    Examples:
      uv run exa detection import all-rules.json
      uv run exa detection import all-rules.json --overwrite
      uv run exa detection import all-rules.json --tenant csnafusion
    """
    from exa.detection import import_rules

    if not input_file.exists():
        console.print(f"File not found: {input_file}", style="red")
        raise typer.Exit(1)

    bundle = json.loads(input_file.read_text(encoding="utf-8"))
    client = _make_client(tenant)
    try:
        result = import_rules(client, bundle, overwrite=overwrite)
        imported = result.get("imported", result.get("count", "?"))
        skipped = result.get("skipped", 0)
        errors = result.get("errors", [])
        console.print(f"Imported: {imported}  Skipped: {skipped}", style="green")
        if errors:
            console.print(f"Errors ({len(errors)}):", style="red")
            for e in errors:
                console.print(f"  {e}", style="red")
    finally:
        client.close()


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

@detection_app.command("diff")
def detection_diff(
    file_a: Annotated[
        Path,
        typer.Argument(help="Baseline JSON bundle (older)"),
    ],
    file_b: Annotated[
        Path,
        typer.Argument(help="Current JSON bundle (newer)"),
    ],
    json_out: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Output diff as raw JSON [default: no-json]"),
    ] = False,
) -> None:
    """Diff two exported detection rule bundles.

    Compares two JSON bundles produced by 'exa detection export' and shows
    rules added, removed, and changed (with field-level deltas). Useful for
    auditing rule changes between TDM update cycles.

    \b
    Examples:
      uv run exa detection diff baseline.json current.json
      uv run exa detection diff before.json after.json --json
    """
    from exa.detection import diff_rules

    bundle_a = json.loads(file_a.read_text(encoding="utf-8"))
    bundle_b = json.loads(file_b.read_text(encoding="utf-8"))

    rules_a: list[dict] = bundle_a if isinstance(bundle_a, list) else bundle_a.get("ruleDefinitions", [])
    rules_b: list[dict] = bundle_b if isinstance(bundle_b, list) else bundle_b.get("ruleDefinitions", [])

    result = diff_rules(rules_a, rules_b, key="templateId")

    if json_out:
        console.print_json(json.dumps(result))
        return

    console.print(f"  Added:     {len(result['added'])}", style="green")
    console.print(f"  Removed:   {len(result['removed'])}", style="red")
    console.print(f"  Changed:   {len(result['changed'])}", style="yellow")
    console.print(f"  Unchanged: {result['unchanged']}", style="dim")

    if result["added"]:
        console.print("\n[green]Added:[/green]")
        for r in result["added"]:
            console.print(f"  + {r.get('templateId', '?')}  {r.get('name', '')}")

    if result["removed"]:
        console.print("\n[red]Removed:[/red]")
        for r in result["removed"]:
            console.print(f"  - {r.get('templateId', '?')}  {r.get('name', '')}")

    if result["changed"]:
        console.print("\n[yellow]Changed:[/yellow]")
        for entry in result["changed"]:
            console.print(f"  ~ {entry.get('templateId', '?')}")
            for field, delta in entry.get("changes", {}).items():
                console.print(
                    f"      {field}: {delta['before']!r} -> {delta['after']!r}",
                    style="dim",
                )


# ---------------------------------------------------------------------------
# snapshot
# ---------------------------------------------------------------------------

@detection_app.command("snapshot")
def detection_snapshot(
    table: Annotated[
        str,
        typer.Argument(help="Context table name (creates if not found) or exact table ID"),
    ],
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Snapshot all analytics rules into a context table (full replace).

    Exports all detection rules and writes them into the specified context
    table, replacing the entire table contents atomically. Creates the table
    with the correct column schema if it does not already exist. Accepts a
    table name (substring match) or an exact table UUID. Safe to re-run after
    TDM updates — idempotent full replace each time.

    \b
    Examples:
      uv run exa detection snapshot "Detection Snapshot"
      uv run exa detection snapshot <table-uuid>
      uv run exa detection snapshot "Detection Snapshot" --tenant csnafusion
    """
    from exa.detection.snapshot import snapshot_rules_to_table

    client = _make_client(tenant)
    try:
        table_id, display_name = _resolve_or_create_snapshot_table(client, table)
        result = snapshot_rules_to_table(client, table_id)
        console.print(
            f"Wrote {result['written']} rules to context table '{display_name}'",
            style="green",
        )
    finally:
        client.close()


def _resolve_or_create_snapshot_table(client, name_or_id: str) -> tuple[str, str]:
    """Return (table_id, display_name), creating the table if name is not found."""
    from exa.context.tables import get_tables
    from exa.detection.snapshot import create_snapshot_table

    tables = get_tables(client)

    # Exact ID match first
    for t in tables:
        if t.get("id") == name_or_id:
            return t["id"], t.get("displayName") or t.get("name", name_or_id)

    # Substring match on displayName or name (case-insensitive)
    needle = name_or_id.lower()
    matches = [
        t for t in tables
        if needle in (t.get("displayName") or "").lower()
        or needle in (t.get("name") or "").lower()
    ]
    if len(matches) == 1:
        t = matches[0]
        return t["id"], t.get("displayName") or t.get("name", name_or_id)
    if len(matches) > 1:
        names = [t.get("displayName") or t.get("name", "?") for t in matches]
        raise typer.BadParameter(
            f"Ambiguous table name '{name_or_id}' — matches: {names}."
            " Use a more specific name or the table ID."
        )

    # Not found — create with the snapshot column schema
    console.print(f"Table '{name_or_id}' not found — creating with snapshot schema...", style="dim")
    table_id = create_snapshot_table(client, name_or_id)
    console.print(f"Created table '{name_or_id}' (id: {table_id})", style="dim")
    return table_id, name_or_id

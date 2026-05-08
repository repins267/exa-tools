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

import json
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

_TENANT_HELP = "Tenant nickname or FQDN (default: saved default)"


def _make_client(tenant: str | None = None):
    from exa.client import ExaClient

    client = ExaClient(tenant=tenant)
    client.authenticate()
    return client


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

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
        typer.Option("--limit", help="Max rules to return"),
    ] = 100,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
    json_out: Annotated[
        bool,
        typer.Option("--json", help="Output raw JSON"),
    ] = False,
) -> None:
    """List analytics/detection rules."""
    from exa.detection import get_detection_rules

    client = _make_client(tenant)
    try:
        rules = get_detection_rules(client, name=name, status=status, limit=limit)
        if json_out:
            console.print_json(json.dumps(rules))
            return
        tbl = Table("ID", "Name", "Enabled", "Severity", show_header=True, header_style="bold")
        for r in rules:
            enabled_val = r.get("isEnabled")
            if enabled_val is True:
                enabled_str = "[green]yes[/green]"
            elif enabled_val is False:
                enabled_str = "[dim]no[/dim]"
            else:
                enabled_str = ""
            tbl.add_row(
                r.get("id", ""),
                r.get("name", ""),
                enabled_str,
                r.get("severity", ""),
            )
        console.print(tbl)
        console.print(f"\n  {len(rules)} rules", style="dim")
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
        typer.Option("--json", help="Output raw JSON"),
    ] = False,
) -> None:
    """Get a single detection rule by ID."""
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
    """Enable a detection rule."""
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
    """Disable a detection rule."""
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
    """Export detection rules to a JSON bundle file."""
    from exa.detection import export_rules

    client = _make_client(tenant)
    try:
        bundle = export_rules(client, rule_ids=rule_ids if rule_ids else None)
        output.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        count = len(bundle.get("rules", bundle.get("ruleIds", [])))
        console.print(f"Exported {count} rules → {output}", style="green")
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
        typer.Option("--overwrite", help="Overwrite existing rules with same ID"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Import detection rules from a JSON bundle file."""
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
        typer.Option("--json", help="Output raw JSON diff"),
    ] = False,
) -> None:
    """Diff two exported detection rule bundles."""
    from exa.detection import diff_rules

    bundle_a = json.loads(file_a.read_text(encoding="utf-8"))
    bundle_b = json.loads(file_b.read_text(encoding="utf-8"))

    rules_a: list[dict] = bundle_a if isinstance(bundle_a, list) else bundle_a.get("rules", [])
    rules_b: list[dict] = bundle_b if isinstance(bundle_b, list) else bundle_b.get("rules", [])

    result = diff_rules(rules_a, rules_b)

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
            console.print(f"  + {r.get('id', '?')}  {r.get('name', '')}")

    if result["removed"]:
        console.print("\n[red]Removed:[/red]")
        for r in result["removed"]:
            console.print(f"  - {r.get('id', '?')}  {r.get('name', '')}")

    if result["changed"]:
        console.print("\n[yellow]Changed:[/yellow]")
        for entry in result["changed"]:
            console.print(f"  ~ {entry.get('id', '?')}")
            for field, delta in entry.get("changes", {}).items():
                console.print(
                    f"      {field}: {delta['before']!r} -> {delta['after']!r}",
                    style="dim",
                )

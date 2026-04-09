"""Sigma rule conversion and deployment CLI commands."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

sigma_app = typer.Typer(
    name="sigma",
    help="Convert and deploy Sigma rules to Exabeam EQL correlation rules.",
    no_args_is_help=True,
)
console = Console()


def _collect_rule_files(
    rule: Path | None,
    dir_path: Path | None,
) -> list[Path]:
    """Resolve rule file(s) from --rule or --dir."""
    if rule:
        if not rule.exists():
            console.print(f"File not found: {rule}", style="red")
            raise typer.Exit(1)
        return [rule]

    if dir_path is None:
        from exa.config import load_config

        saved_dir = load_config("sigma.rules-dir")
        if saved_dir:
            dir_path = Path(saved_dir)
        else:
            console.print(
                "No --rule or --dir specified and no sigma.rules-dir configured.\n"
                "  Use: exa config set sigma.rules-dir <path>",
                style="red",
            )
            raise typer.Exit(1)

    if not dir_path.is_dir():
        console.print(f"Directory not found: {dir_path}", style="red")
        raise typer.Exit(1)

    files = sorted(dir_path.rglob("*.yml"))
    if not files:
        console.print(f"No .yml files found in {dir_path}", style="yellow")
        raise typer.Exit(0)
    return files


def _convert_files(
    files: list[Path],
) -> list[dict]:
    """Parse and convert a list of Sigma YAML files.

    Returns list of dicts with keys: path, rule, error.
    """
    from exa.exceptions import SigmaConversionError
    from exa.sigma.converter import convert_to_exa_rule
    from exa.sigma.parser import parse_sigma_rule

    results: list[dict] = []
    for f in files:
        try:
            parsed = parse_sigma_rule(f)
            exa_rule = convert_to_exa_rule(parsed)
            results.append({"path": f, "rule": exa_rule, "error": None})
        except SigmaConversionError as e:
            results.append({"path": f, "rule": None, "error": str(e)})
        except Exception as e:
            results.append({"path": f, "rule": None, "error": str(e)})
    return results


def _print_conversion_table(results: list[dict]) -> None:
    """Print a Rich table of conversion results."""
    table = Table(title="Sigma Conversion Results", show_lines=True)
    table.add_column("Rule Name", style="white", max_width=40)
    table.add_column("EQL Preview", style="dim", max_width=60)
    table.add_column("Deploy Ready", justify="center", width=14)
    table.add_column("Warnings", style="yellow", max_width=40)

    for r in results:
        if r["error"]:
            table.add_row(
                str(r["path"].stem),
                "",
                "[red]Error[/red]",
                r["error"][:60],
            )
            continue

        rule = r["rule"]
        name = rule["name"]
        eql = rule["eql_query"]
        eql_preview = (eql[:57] + "...") if len(eql) > 60 else eql
        warnings = rule.get("warnings", [])
        warn_text = "; ".join(warnings) if warnings else ""

        deploy = rule["deploy_ready"]
        if deploy == "Yes" and not warnings:
            deploy_styled = "[green]Yes[/green]"
        elif deploy == "Yes" or deploy == "Needs review":
            deploy_styled = f"[yellow]{deploy}[/yellow]"
        else:
            deploy_styled = f"[red]{deploy}[/red]"

        table.add_row(name, eql_preview, deploy_styled, warn_text)

    console.print(table)

    total = len(results)
    ok = sum(1 for r in results if r["rule"])
    errs = sum(1 for r in results if r["error"])
    console.print(
        f"\n  {total} rules processed: {ok} converted, {errs} errors",
        style="dim",
    )


def _deploy_rules(
    results: list[dict],
    tenant: str | None = None,
) -> None:
    """Deploy converted rules via correlation rules API using keyring credentials."""
    from exa.client import ExaClient
    from exa.correlation.rules import create_rule
    from exa.sigma.converter import to_api_payload

    deployable = [
        r for r in results
        if r["rule"] and r["rule"]["deploy_ready"] != "No"
    ]
    if not deployable:
        console.print("  No rules are deploy-ready.", style="yellow")
        return

    client = ExaClient(tenant=tenant)
    client.authenticate()

    deploy_table = Table(title="Deployment Results", show_lines=True)
    deploy_table.add_column("Rule Name", style="white", max_width=40)
    deploy_table.add_column("API Status", justify="center", width=12)
    deploy_table.add_column("Rule ID", style="cyan", width=38)
    deploy_table.add_column("Endpoint", style="dim", max_width=40)

    try:
        for r in deployable:
            rule = r["rule"]
            payload = to_api_payload(rule)
            try:
                resp = create_rule(client, payload)
                rule_id = resp.get("id", "unknown")
                deploy_table.add_row(
                    rule["name"],
                    "[green]Created[/green]",
                    str(rule_id),
                    client.base_url,
                )
            except Exception as e:
                deploy_table.add_row(
                    rule["name"],
                    "[red]Failed[/red]",
                    "",
                    str(e)[:40],
                )
    finally:
        client.close()

    console.print(deploy_table)


@sigma_app.command("convert")
def convert(
    rule: Annotated[
        Path | None,
        typer.Option("--rule", "-r", help="Single Sigma YAML file"),
    ] = None,
    dir_path: Annotated[
        Path | None,
        typer.Option("--dir", "-d", help="Directory of Sigma YAML files"),
    ] = None,
    deploy: Annotated[
        bool,
        typer.Option("--deploy", help="Deploy converted rules to Exabeam"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help="Tenant profile (default: saved default)"),
    ] = None,
) -> None:
    """Convert Sigma rules to Exabeam EQL correlation rules."""
    files = _collect_rule_files(rule, dir_path)
    results = _convert_files(files)
    _print_conversion_table(results)

    if deploy:
        _deploy_rules(results, tenant=tenant)


@sigma_app.command("deploy")
def deploy_cmd(
    rule: Annotated[
        Path,
        typer.Option("--rule", "-r", help="Sigma YAML file to deploy"),
    ],
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help="Tenant profile (default: saved default)"),
    ] = None,
) -> None:
    """Convert a Sigma rule and deploy it to Exabeam in one step."""
    files = _collect_rule_files(rule, None)
    results = _convert_files(files)
    _print_conversion_table(results)
    _deploy_rules(results, tenant=tenant)

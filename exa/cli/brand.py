"""`exa brand` — manage the report-logo registry used by the branded renderer.

Register a customer (or team) logo once, then select it per report with
``--brand <name>`` on the CLI or ``brand:"<name>"`` in the render_report MCP spec.
Logos live under ``~/.exa/brand/`` and are embedded per render; they are never
committed or promoted into shipped assets.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

brand_app = typer.Typer(
    name="brand",
    help="Manage report logos (exabeam / exa-tools presets + your registered logos).",
    no_args_is_help=True,
)
console = Console()


@brand_app.command("add")
def add_cmd(
    name: Annotated[str, typer.Argument(help="Name to register the logo under, e.g. acme")],
    logo: Annotated[Path, typer.Argument(help="Path to the logo file (svg/png/jpg/gif/webp)")],
    logo_light: Annotated[
        Path | None,
        typer.Option("--logo-light", help="Optional variant for light backgrounds"),
    ] = None,
) -> None:
    """Register a logo so reports can select it with --brand <name>.

    \b
    Examples:
      exa brand add acme ./acme-logo.svg
      exa brand add acme ./acme-dark.svg --logo-light ./acme-light.svg
    """
    from exa.report.brand import BrandError, add_brand

    try:
        dest = add_brand(name, logo, logo_light)
    except BrandError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)
    console.print(f"[green]Registered brand[/] '{name}' -> {dest}")
    console.print(f"Use it: exa dashboard preview <cfg> --brand {name}", style="dim")


@brand_app.command("list")
def list_cmd() -> None:
    """List the built-in presets and every registered logo.

    \b
    Examples:
      exa brand list
    """
    from exa.report.brand import list_brands

    table = Table(show_header=True, header_style="bold")
    table.add_column("Brand")
    table.add_column("Kind")
    table.add_row("exabeam", "[dim]preset (default, customer-facing)[/]")
    table.add_row("exa-tools", "[dim]preset (internal)[/]")
    for name in list_brands():
        table.add_row(name, "registered (~/.exa/brand/)")
    console.print(table)


@brand_app.command("remove")
def remove_cmd(
    name: Annotated[str, typer.Argument(help="Registered brand name to remove")],
) -> None:
    """Remove a registered logo (presets cannot be removed).

    \b
    Examples:
      exa brand remove acme
    """
    from exa.report.brand import BrandError, remove_brand

    try:
        n = remove_brand(name)
    except BrandError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)
    console.print(f"[green]Removed[/] '{name}' ({n} file(s))")

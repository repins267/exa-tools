"""Config CLI commands — get, set, and show exa-tools configuration."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

config_app = typer.Typer(
    name="config",
    help="View and modify exa-tools configuration (~/.exa/config.json).",
    no_args_is_help=True,
)
console = Console()


@config_app.command("set")
def config_set(
    key: Annotated[str, typer.Argument(help="Config key (e.g. sigma.rules-dir)")],
    value: Annotated[str, typer.Argument(help="Config value")],
) -> None:
    """Set a configuration value."""
    from exa.config import (
        _INTERNAL_KEYS,
        _SPECIAL_KEYS,
        save_config,
        set_default_tenant,
    )

    if key in _INTERNAL_KEYS:
        console.print(
            f"'{key}' is managed internally. Use 'exa configure' instead.",
            style="red",
        )
        raise typer.Exit(1)

    # Handle special keys that map to dedicated functions
    canonical = _SPECIAL_KEYS.get(key, key)
    if canonical == "default_tenant":
        set_default_tenant(value)
    else:
        save_config(canonical, value)

    console.print(f"  {key} = {value}", style="green")


@config_app.command("get")
def config_get(
    key: Annotated[str, typer.Argument(help="Config key to read")],
) -> None:
    """Get a configuration value."""
    from exa.config import _SPECIAL_KEYS, load_config

    canonical = _SPECIAL_KEYS.get(key, key)
    value = load_config(canonical)
    if value is None:
        console.print(f"  '{key}' is not set", style="yellow")
        raise typer.Exit(1)
    console.print(f"  {key} = {value}")


@config_app.command("show")
def config_show() -> None:
    """Show all current configuration values."""
    from exa.config import list_config

    items = list_config()

    if not items:
        console.print("  No configuration set. Run 'exa configure' to get started.", style="dim")
        return

    table = Table(title="exa-tools configuration", show_header=True)
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="white")

    for k, v in sorted(items.items()):
        table.add_row(k, str(v))

    console.print(table)
    console.print(
        "\n  Config file: ~/.exa/config.json",
        style="dim",
    )


@config_app.command("tenants")
def config_tenants() -> None:
    """List all configured tenant profiles (no secrets shown)."""
    from exa.config import _read_config_file

    config = _read_config_file()
    tenants = config.get("tenants", {})
    default = config.get("default_tenant", "")

    if not tenants:
        console.print(
            "  No tenants configured. Run 'exa configure' to add one.",
            style="dim",
        )
        return

    table = Table(title="Configured Tenants", show_header=True)
    table.add_column("Nickname", style="cyan", no_wrap=True)
    table.add_column("FQDN", style="white")
    table.add_column("Region", style="white")
    table.add_column("API Server", style="dim")
    table.add_column("Default", justify="center")

    for nickname, entry in sorted(tenants.items()):
        is_default = "✓" if nickname == default else ""
        table.add_row(
            nickname,
            entry.get("fqdn", f"{nickname}.exabeam.cloud"),
            entry.get("region", "—"),
            entry.get("api_server", "—"),
            f"[green]{is_default}[/green]",
        )

    console.print(table)
    console.print(
        f"\n  {len(tenants)} tenant(s) | "
        f"Default: [cyan]{default or '(none)'}[/cyan] | "
        f"Secrets in Windows Credential Manager",
        style="dim",
    )

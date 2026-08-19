"""Config CLI commands — get, set, and show exa-tools configuration."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

config_app = typer.Typer(
    name="config",
    help=(
        "View and modify exa-tools configuration (~/.exa/config.json). "
        "Takes SUBCOMMANDS, not flags -- try 'exa config tenants'. "
        "To ADD a tenant, use 'exa configure' (no -ure/-ig confusion: "
        "'configure' sets one up, 'config' inspects what exists)."
    ),
    no_args_is_help=True,
)
console = Console()


@config_app.command("set")
def config_set(
    key: Annotated[str, typer.Argument(help="Config key (e.g. sigma.rules-dir)")],
    value: Annotated[str, typer.Argument(help="Config value")],
) -> None:
    """Set a configuration value in ~/.exa/config.json.

    Settable keys: default_tenant, sigma.rules-dir, sigma.deploy-tenant.
    The key default_tenant sets which tenant profile is used when --tenant
    is omitted. Run 'exa config show' to see all current values.

    \b
    Examples:
      uv run exa config set default_tenant csnafusion
      uv run exa config set sigma.rules-dir ~/sigma/rules/windows
    """
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
    """Get a single configuration value by key.

    \b
    Examples:
      uv run exa config get default_tenant
      uv run exa config get sigma.rules-dir
    """
    from exa.config import _SPECIAL_KEYS, load_config

    canonical = _SPECIAL_KEYS.get(key, key)
    value = load_config(canonical)
    if value is None:
        console.print(f"  '{key}' is not set", style="yellow")
        raise typer.Exit(1)
    console.print(f"  {key} = {value}")


@config_app.command("show")
def config_show() -> None:
    """Show all current configuration values from ~/.exa/config.json.

    \b
    Examples:
      uv run exa config show
    """
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
    """List all configured tenant profiles (no secrets shown).

    Displays nickname, FQDN, region, API server, and which tenant is the
    default. Credentials are stored in the OS credential store and never
    shown here.

    \b
    Examples:
      uv run exa config tenants
    """
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
        is_default = "yes" if nickname == default else ""
        table.add_row(
            nickname,
            entry.get("fqdn", f"{nickname}.exabeam.cloud"),
            entry.get("region", "-"),
            entry.get("api_server", "-"),
            f"[green]{is_default}[/green]",
        )

    console.print(table)
    console.print(
        f"\n  {len(tenants)} tenant(s) | "
        f"Default: [cyan]{default or '(none)'}[/cyan] | "
        f"Secrets in Windows Credential Manager",
        style="dim",
    )


@config_app.command("set-kind")
def config_set_kind(
    tenant: Annotated[str, typer.Argument(help="Tenant nickname (see 'exa config tenants')")],
    kind: Annotated[str, typer.Argument(help="'demo' or 'customer'")],
) -> None:
    """Tag a tenant as demo or customer.

    The label is surfaced by the MCP get_active_tenant / list_tenants tools so an
    agent can tell a customer tenant from a demo one before writing. Stored as
    non-secret metadata in ~/.exa/config.json.

    
    Examples:
      uv run exa config set-kind sademodev22 demo
      uv run exa config set-kind lvcva customer
    """
    from exa.config import set_tenant_kind

    try:
        set_tenant_kind(tenant, kind)
    except Exception as e:
        console.print(f"  {e}", style="red")
        raise typer.Exit(1)
    console.print(f"  {tenant} tagged as [bold]{kind.strip().lower()}[/bold]", style="green")


@config_app.command("remove")
def config_remove(
    tenant: Annotated[str, typer.Option("--tenant", "-t", help="Tenant nickname to remove")] = ...,
    confirm: Annotated[
        bool,
        typer.Option(
            "--confirm/--no-confirm",
            help="Skip confirmation prompt [default: no-confirm]",
        ),
    ] = False,
) -> None:
    """Remove a tenant profile and its stored credentials.

    Deletes the keyring credentials and config file entry for the named tenant.
    If the tenant was the default, clears the default as well.

    \b
    Examples:
      uv run exa config remove --tenant csnafusion
      uv run exa config remove --tenant csnafusion --confirm
    """
    import keyring
    import keyring.errors

    from exa.config import _KEYRING_SERVICE, _read_config_file, _write_config_file

    service = f"{_KEYRING_SERVICE}/{tenant}"
    config = _read_config_file()

    in_config = tenant in config.get("tenants", {})
    client_id_exists = keyring.get_password(service, "client_id") is not None
    client_secret_exists = keyring.get_password(service, "client_secret") is not None
    in_keyring = client_id_exists or client_secret_exists

    if not in_config and not in_keyring:
        console.print(f"  Tenant '{tenant}' not found in config or credential store.", style="red")
        raise typer.Exit(1)

    tenant_entry = config.get("tenants", {}).get(tenant, {})
    is_default = config.get("default_tenant") == tenant

    if not confirm:
        console.print(f"\n  Will delete credentials for tenant '[cyan]{tenant}[/cyan]':")
        if tenant_entry.get("fqdn"):
            console.print(f"    FQDN:       {tenant_entry['fqdn']}", style="dim")
        if tenant_entry.get("api_server"):
            console.print(f"    API server: {tenant_entry['api_server']}", style="dim")
        if in_keyring:
            console.print(f"    Keyring:    {service} (client_id, client_secret)", style="dim")
        if is_default:
            console.print(
                f"    Note: '{tenant}' is the current default — will be cleared.",
                style="yellow",
            )
        console.print()
        proceed = typer.confirm(f"Delete credentials for tenant '{tenant}'?", default=False)
        if not proceed:
            console.print("  Aborted.", style="dim")
            raise typer.Exit(0)

    if client_id_exists:
        try:
            keyring.delete_password(service, "client_id")
        except keyring.errors.PasswordDeleteError:
            pass
    if client_secret_exists:
        try:
            keyring.delete_password(service, "client_secret")
        except keyring.errors.PasswordDeleteError:
            pass

    if in_config:
        config.get("tenants", {}).pop(tenant, None)
    if is_default:
        config.pop("default_tenant", None)

    _write_config_file(config)
    console.print(f"  Removed tenant '[cyan]{tenant}[/cyan]'.", style="green")

"""exa-tools CLI application."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console

if TYPE_CHECKING:
    from exa.client import ExaClient

app = typer.Typer(
    name="exa",
    help="Python automation toolkit for Exabeam New-Scale Analytics (NSA) / SIEM.",
    no_args_is_help=True,
)
console = Console()

_TENANT_HELP = "Tenant nickname or FQDN (default: saved default)"


def _make_client(tenant: str | None = None) -> ExaClient:
    """Create and authenticate an ExaClient from keyring."""
    from exa.client import ExaClient

    client = ExaClient(tenant=tenant)
    client.authenticate()
    return client


# -- Configure ----------------------------------------------------------------

@app.command()
def configure() -> None:
    """Set up tenant credentials (stored in Windows Credential Manager)."""
    from rich.prompt import Prompt

    from exa.config import resolve_fqdn, save_profile, set_default_tenant

    # Tenant FQDN
    fqdn_input = Prompt.ask(
        "Tenant FQDN or name "
        "(e.g. sademodev22.exabeam.cloud or "
        "csdevfusion.use1.exabeam.cloud)"
    )
    if not fqdn_input.strip():
        console.print("Tenant FQDN cannot be empty.", style="red")
        raise typer.Exit(1)

    try:
        nickname, fqdn, api_server, region = resolve_fqdn(fqdn_input)
    except ValueError as e:
        console.print(f"\u2717 {e}", style="red")
        raise typer.Exit(1)

    console.print(
        f"\u2713 Resolved: {fqdn} \u2192 {region} ({api_server})",
        style="green",
    )

    # Credentials
    client_id = Prompt.ask("Client ID")
    if not client_id.strip():
        console.print("Client ID cannot be empty.", style="red")
        raise typer.Exit(1)
    client_id = client_id.strip()

    client_secret = Prompt.ask("Client Secret", password=True)
    if not client_secret:
        console.print("Client Secret cannot be empty.", style="red")
        raise typer.Exit(1)

    # Test connection
    from exa.client import ExaClient

    console.print("\nTesting connection...", style="dim")
    try:
        test_client = ExaClient(api_server, client_id, client_secret)
        test_client.authenticate()
        test_client.close()
    except Exception as e:
        console.print(
            f"\u2717 Connection failed \u2014 "
            f"verify credentials and region\n"
            f"  API server tried: {api_server}\n"
            f"  Error: {e}",
            style="red",
        )
        raise typer.Exit(1)

    console.print(
        f"\u2713 Connected \u2014 {fqdn} ({region})",
        style="green",
    )

    # Save profile
    save_profile(
        nickname, api_server, client_id, client_secret,
        fqdn=fqdn, region=region,
    )
    console.print(
        "  Credentials saved to Windows Credential Manager",
        style="dim",
    )

    # Default tenant
    set_as_default = Prompt.ask(
        "Set as default tenant?", choices=["Y", "n"], default="Y",
    )
    if set_as_default.upper() == "Y":
        set_default_tenant(nickname)
        console.print(f"  Default tenant: {nickname}", style="dim")

    # CIM2 reference data
    download_cim2 = Prompt.ask(
        "Download CIM2 reference data now?",
        choices=["Y", "n"], default="Y",
    )
    if download_cim2.upper() == "Y":
        from exa.cli.update import _run_update

        _run_update()

    # SigmaHQ community rules
    download_sigma = Prompt.ask(
        "Download SigmaHQ community rules? (~500MB)",
        choices=["Y", "n"], default="n",
    )
    if download_sigma.upper() == "Y":
        from exa.update import update_reference_data

        console.print("Cloning SigmaHQ...", style="dim")
        update_reference_data(include_sigma=True)


# -- Auth test ----------------------------------------------------------------

@app.command()
def auth(
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Test authentication against saved tenant credentials."""
    import time

    try:
        client = _make_client(tenant)
        ttl = int(client._expires_at - time.time())
        console.print(
            "Authentication successful", style="green",
        )
        console.print(f"  Token expires in {ttl}s")
        console.print(f"  API server: {client.base_url}", style="dim")
        client.close()
    except Exception as e:
        console.print(f"Authentication failed: {e}", style="red")
        raise typer.Exit(1)


# -- Context tables -----------------------------------------------------------

@app.command()
def tables(
    name: Annotated[
        str | None,
        typer.Option("--name", help="Filter by name"),
    ] = None,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """List context tables."""
    from exa.context import get_tables

    client = _make_client(tenant)
    try:
        result = get_tables(client, name=name)
        for t in result:
            console.print(
                f"  {t.get('id', '?'):<40} {t.get('name', '?')}",
            )
        console.print(f"\n  {len(result)} tables", style="dim")
    finally:
        client.close()


# -- AI/LLM sync -------------------------------------------------------------

@app.command()
def sync_aillm(
    force: Annotated[
        bool,
        typer.Option("--force", help="Replace instead of append"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Sync AI/LLM context tables from reference data."""
    from exa.aillm import sync_aillm_context_tables

    client = _make_client(tenant)
    try:
        sync_aillm_context_tables(client, force=force)
    finally:
        client.close()


# -- Search -------------------------------------------------------------------

@app.command()
def search(
    filter_str: Annotated[
        str, typer.Argument(help="EQL filter string"),
    ],
    lookback_days: Annotated[
        int,
        typer.Option("--lookback", help="Days to search back"),
    ] = 1,
    limit: Annotated[
        int, typer.Option("--limit", help="Max events"),
    ] = 100,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Search Exabeam events."""
    from exa.search import search_events

    client = _make_client(tenant)
    try:
        events = search_events(
            client, filter_str,
            lookback_days=lookback_days, limit=limit,
        )
        for e in events:
            console.print(e)
        console.print(f"\n  {len(events)} events", style="dim")
    finally:
        client.close()


# -- Frameworks ---------------------------------------------------------------

@app.command()
def frameworks() -> None:
    """List available compliance frameworks."""
    from exa.compliance.frameworks import (
        AVAILABLE_FRAMEWORKS,
        load_framework,
    )

    for fw_id in AVAILABLE_FRAMEWORKS:
        try:
            fw = load_framework(fw_id)
            testable = len(fw.testable_controls)
            console.print(
                f"  {fw_id:<20} {fw.name:<35} "
                f"({testable} testable controls)",
            )
        except Exception:
            console.print(
                f"  {fw_id:<20} (load error)", style="red",
            )


# -- Compliance ---------------------------------------------------------------

from exa.cli.compliance import compliance_app

app.add_typer(compliance_app)


# -- Config -------------------------------------------------------------------

from exa.cli.config import config_app

app.add_typer(config_app)


# -- Update -------------------------------------------------------------------

from exa.cli.update import update_app

app.add_typer(update_app)


# -- Sigma --------------------------------------------------------------------

from exa.cli.sigma import sigma_app

app.add_typer(sigma_app)

# Short aliases: exa sc → exa sigma convert, exa sd → exa sigma deploy
sc_app = typer.Typer(
    name="sc", hidden=True, invoke_without_command=True,
)
sd_app = typer.Typer(
    name="sd", hidden=True, invoke_without_command=True,
)


@sc_app.callback(invoke_without_command=True)
def sc_alias(ctx: typer.Context) -> None:
    """Alias for 'exa sigma convert'."""
    from exa.cli.sigma import convert

    ctx.invoke(convert)


@sd_app.callback(invoke_without_command=True)
def sd_alias(ctx: typer.Context) -> None:
    """Alias for 'exa sigma deploy'."""
    from exa.cli.sigma import deploy_cmd

    ctx.invoke(deploy_cmd)


app.add_typer(sc_app)
app.add_typer(sd_app)


# -- Dev (internal only) ------------------------------------------------------

dev_app = typer.Typer(
    name="dev",
    help="Internal development commands (requires @exabeam.com).",
    no_args_is_help=True,
)
app.add_typer(dev_app)


@dev_app.command()
def connect() -> None:
    """Connect using EXA_CLIENT_ID/EXA_CLIENT_SECRET env vars (internal only)."""
    import time

    from exa.internal.dev import get_dev_client_from_env

    try:
        client = get_dev_client_from_env()
        ttl = int(client._expires_at - time.time())
        console.print("Connected (internal tier)", style="green")
        console.print(f"  Token expires in {ttl}s")
        client.close()
    except Exception as e:
        console.print(f"Failed: {e}", style="red")
        raise typer.Exit(1)

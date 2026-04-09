"""exa-tools CLI application."""

from __future__ import annotations

import getpass
from typing import TYPE_CHECKING, Annotated, Optional

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


def _get_client(
    base_url: str,
    client_id: str,
    client_secret: str | None = None,
) -> ExaClient:
    """Create and authenticate an ExaClient with explicit credentials."""
    from exa.client import ExaClient

    if not client_secret:
        client_secret = getpass.getpass("Client Secret: ")
    client = ExaClient(base_url, client_id, client_secret)
    client.authenticate()
    return client


# -- Configure ----------------------------------------------------------------

@app.command()
def configure() -> None:
    """Set up tenant credentials (stored in Windows Credential Manager)."""
    from rich.prompt import Prompt
    from rich.table import Table

    from exa.config import REGIONS, save_profile, set_default_tenant

    # Tenant name
    tenant = Prompt.ask("Tenant name (e.g. sademodev22)")
    if not tenant.strip():
        console.print("Tenant name cannot be empty.", style="red")
        raise typer.Exit(1)
    tenant = tenant.strip()

    # Region selection
    region_list = list(REGIONS.items())
    table = Table(title="Regions", show_header=True)
    table.add_column("#", style="cyan", width=4)
    table.add_column("Region", style="white")
    table.add_column("API Server", style="dim")
    for i, (name, url) in enumerate(region_list, 1):
        table.add_row(str(i), name, url)
    console.print(table)

    choice = Prompt.ask(
        "Select region",
        choices=[str(i) for i in range(1, len(region_list) + 1)],
    )
    region_name, api_server = region_list[int(choice) - 1]

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
        console.print(f"\u2717 Connection failed \u2014 {e}", style="red")
        raise typer.Exit(1)

    console.print(f"\u2713 Connected \u2014 {tenant} ({region_name})", style="green")

    # Save profile
    save_profile(tenant, api_server, client_id, client_secret)
    console.print("  Credentials saved to Windows Credential Manager", style="dim")

    # Default tenant
    set_as_default = Prompt.ask("Set as default tenant?", choices=["Y", "n"], default="Y")
    if set_as_default.upper() == "Y":
        set_default_tenant(tenant)
        console.print(f"  Default tenant: {tenant}", style="dim")

    # CIM2 reference data
    download_cim2 = Prompt.ask(
        "Download CIM2 reference data now?", choices=["Y", "n"], default="Y",
    )
    if download_cim2.upper() == "Y":
        from exa.cli.update import _run_update

        _run_update()


# -- Auth test ----------------------------------------------------------------

@app.command()
def auth(
    base_url: Annotated[str, typer.Option("--url", help="Exabeam base URL")],
    client_id: Annotated[str, typer.Option("--client-id", help="API client ID")],
    client_secret: Annotated[Optional[str], typer.Option("--client-secret", help="API client secret (prompted if omitted)")] = None,
) -> None:
    """Test authentication against Exabeam API."""
    try:
        client = _get_client(base_url, client_id, client_secret)
        console.print("Authentication successful", style="green")
        console.print(f"  Token expires in {int(client._expires_at - __import__('time').time())}s")
        client.close()
    except Exception as e:
        console.print(f"Authentication failed: {e}", style="red")
        raise typer.Exit(1)


# -- Context tables -----------------------------------------------------------

@app.command()
def tables(
    base_url: Annotated[str, typer.Option("--url", help="Exabeam base URL")],
    client_id: Annotated[str, typer.Option("--client-id", help="API client ID")],
    client_secret: Annotated[Optional[str], typer.Option("--client-secret")] = None,
    name: Annotated[Optional[str], typer.Option("--name", help="Filter by name")] = None,
) -> None:
    """List context tables."""
    from exa.context import get_tables

    client = _get_client(base_url, client_id, client_secret)
    try:
        result = get_tables(client, name=name)
        for t in result:
            console.print(f"  {t.get('id', '?'):<40} {t.get('name', '?')}")
        console.print(f"\n  {len(result)} tables", style="dim")
    finally:
        client.close()


# -- AI/LLM sync -------------------------------------------------------------

@app.command()
def sync_aillm(
    base_url: Annotated[str, typer.Option("--url", help="Exabeam base URL")],
    client_id: Annotated[str, typer.Option("--client-id", help="API client ID")],
    client_secret: Annotated[Optional[str], typer.Option("--client-secret")] = None,
    force: Annotated[bool, typer.Option("--force", help="Replace instead of append")] = False,
) -> None:
    """Sync AI/LLM context tables from reference data."""
    from exa.aillm import sync_aillm_context_tables

    client = _get_client(base_url, client_id, client_secret)
    try:
        sync_aillm_context_tables(client, force=force)
    finally:
        client.close()


# -- Compliance audit ---------------------------------------------------------

@app.command()
def audit(
    framework: Annotated[str, typer.Argument(help="Framework ID (e.g. NIST_CSF, CMMC_L2)")],
    base_url: Annotated[str, typer.Option("--url", help="Exabeam base URL")],
    client_id: Annotated[str, typer.Option("--client-id", help="API client ID")],
    client_secret: Annotated[Optional[str], typer.Option("--client-secret")] = None,
    lookback_days: Annotated[int, typer.Option("--lookback", help="Days to search back")] = 30,
    min_evidence: Annotated[int, typer.Option("--min-evidence", help="Min events per control")] = 10,
    output: Annotated[Optional[str], typer.Option("--output", "-o", help="Save report to JSON file")] = None,
) -> None:
    """Run a compliance framework audit."""
    from exa.compliance import run_compliance_audit

    client = _get_client(base_url, client_id, client_secret)
    try:
        run_compliance_audit(
            client,
            framework,
            lookback_days=lookback_days,
            minimum_evidence=min_evidence,
            output_report=output,
        )
    finally:
        client.close()


# -- Search -------------------------------------------------------------------

@app.command()
def search(
    filter_str: Annotated[str, typer.Argument(help="EQL filter string")],
    base_url: Annotated[str, typer.Option("--url", help="Exabeam base URL")],
    client_id: Annotated[str, typer.Option("--client-id", help="API client ID")],
    client_secret: Annotated[Optional[str], typer.Option("--client-secret")] = None,
    lookback_days: Annotated[int, typer.Option("--lookback", help="Days to search back")] = 1,
    limit: Annotated[int, typer.Option("--limit", help="Max events")] = 100,
) -> None:
    """Search Exabeam events."""
    from exa.search import search_events

    client = _get_client(base_url, client_id, client_secret)
    try:
        events = search_events(client, filter_str, lookback_days=lookback_days, limit=limit)
        for e in events:
            console.print(e)
        console.print(f"\n  {len(events)} events", style="dim")
    finally:
        client.close()


# -- Frameworks ---------------------------------------------------------------

@app.command()
def frameworks() -> None:
    """List available compliance frameworks."""
    from exa.compliance.frameworks import AVAILABLE_FRAMEWORKS, load_framework

    for fw_id in AVAILABLE_FRAMEWORKS:
        try:
            fw = load_framework(fw_id)
            testable = len(fw.testable_controls)
            console.print(f"  {fw_id:<20} {fw.name:<35} ({testable} testable controls)")
        except Exception:
            console.print(f"  {fw_id:<20} (load error)", style="red")


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
sc_app = typer.Typer(name="sc", hidden=True, invoke_without_command=True)
sd_app = typer.Typer(name="sd", hidden=True, invoke_without_command=True)


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

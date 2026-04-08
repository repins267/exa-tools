"""exa-tools CLI application."""

from __future__ import annotations

import getpass
from typing import Annotated, Optional

import typer
from rich.console import Console

app = typer.Typer(
    name="exa",
    help="Python toolkit for Exabeam New-Scale SIEM automation.",
    no_args_is_help=True,
)
console = Console()


def _get_client(
    base_url: str,
    client_id: str,
    client_secret: str | None = None,
) -> "ExaClient":
    """Create and authenticate an ExaClient."""
    from exa.client import ExaClient

    if not client_secret:
        client_secret = getpass.getpass("Client Secret: ")
    client = ExaClient(base_url, client_id, client_secret)
    client.authenticate()
    return client


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


# -- Dev (internal only) ------------------------------------------------------

dev_app = typer.Typer(name="dev", help="Internal development commands (requires @exabeam.com).", no_args_is_help=True)
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

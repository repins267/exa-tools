"""AI/LLM CLI commands — sync and status.

Commands:
  exa aillm sync    -- Sync 6 AI/LLM context tables from reference data
  exa aillm status  -- Show live record counts for all 6 tables
"""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

aillm_app = typer.Typer(
    name="aillm",
    help="AI/LLM context table sync and status.",
    no_args_is_help=True,
)
console = Console()

_TENANT_HELP = "Tenant nickname or FQDN (default: saved default)"


def _make_client(tenant: str | None = None):
    """Create and authenticate an ExaClient from keyring."""
    from exa.client import ExaClient

    client = ExaClient(tenant=tenant)
    client.authenticate()
    return client


# -- sync ---------------------------------------------------------------------


@aillm_app.command("sync")
def sync_cmd(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview changes without writing to Exabeam"),
    ] = False,
    force: Annotated[
        bool,
        typer.Option("--force", help="Replace existing records instead of append"),
    ] = False,
    discover_from_logs: Annotated[
        bool,
        typer.Option(
            "--discover-from-logs",
            help="Query proxy/web logs for additional AI domains seen in your environment",
        ),
    ] = False,
    lookback: Annotated[
        int,
        typer.Option(
            "--lookback",
            help="Days to look back when discovering domains from logs (default 30)",
        ),
    ] = 30,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Sync AI/LLM context tables from reference data.

    Populates all 6 Exabeam AI/LLM context tables from the bundled
    reference dataset (596 records). Use --dry-run to preview first.
    Use --discover-from-logs to augment with domains actively seen in
    your environment's proxy/web logs.
    """
    from exa.aillm import sync_aillm_context_tables

    client = _make_client(tenant)
    try:
        discovered_domains: list[str] | None = None

        if discover_from_logs:
            from exa.aillm.discover import search_logs_for_ai_domains

            console.print(
                f"Discovering domains from proxy/web logs "
                f"(lookback: {lookback} days)...",
                style="dim",
            )
            discovered_domains = search_logs_for_ai_domains(
                client, lookback_days=lookback
            )
            console.print(
                f"  Found {len(discovered_domains)} distinct domains in logs",
                style="dim",
            )

        sync_aillm_context_tables(
            client,
            discovered_domains=discovered_domains,
            force=force,
            dry_run=dry_run,
        )
    finally:
        client.close()


# -- status -------------------------------------------------------------------


@aillm_app.command("status")
def status_cmd(
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Show live record counts for all 6 AI/LLM context tables."""
    from exa.aillm.status import get_aillm_table_status

    client = _make_client(tenant)
    try:
        statuses = get_aillm_table_status(client)

        tbl = Table(show_header=True, header_style="bold")
        tbl.add_column("Table", style="cyan", no_wrap=True)
        tbl.add_column("Records", justify="right")
        tbl.add_column("Last Synced", style="dim")

        total = 0
        for s in statuses:
            if not s.found:
                tbl.add_row(s.table_name, "—", "Not found", style="dim")
            else:
                tbl.add_row(
                    s.table_name,
                    str(s.record_count),
                    s.last_updated,
                )
                total += s.record_count

        console.print(tbl)
        console.print(f"\n  Total records: {total}", style="dim")
    finally:
        client.close()

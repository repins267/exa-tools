"""Compliance CLI commands — sync-identity, status, audit."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

compliance_app = typer.Typer(
    name="compliance",
    help="Compliance identity sync, audit, and reporting.",
    no_args_is_help=True,
)
console = Console()


def _resolve_framework_id(name_or_id: str) -> str:
    """Resolve a display name or ID to a framework ID.

    Accepts: "NIST_CSF", "NIST CSF v2.0", "nist csf", etc.
    """
    from exa.compliance.frameworks import (
        AVAILABLE_FRAMEWORKS,
        load_framework,
    )

    # Exact ID match
    if name_or_id in AVAILABLE_FRAMEWORKS:
        return name_or_id

    # Try display name match (case-insensitive)
    query = name_or_id.lower().strip()
    for fw_id in AVAILABLE_FRAMEWORKS:
        fw = load_framework(fw_id)
        if fw.name.lower() == query:
            return fw_id
        # Partial match: "nist csf" matches "NIST CSF v2.0"
        if query in fw.name.lower():
            return fw_id

    available = ", ".join(AVAILABLE_FRAMEWORKS)
    console.print(
        f"Framework '{name_or_id}' not found.\n"
        f"  Available: {available}",
        style="red",
    )
    raise typer.Exit(1)


# -- sync-ootb ---------------------------------------------------------------


@compliance_app.command("sync-ootb")
def sync_ootb(
    framework: Annotated[
        str,
        typer.Option("--framework", "-f",
                     help="Framework name or ID"),
    ] = "NIST_CSF",
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run/--no-dry-run",
                     help="Report without writing"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t",
                     help="Tenant profile"),
    ] = None,
) -> None:
    """Sync framework controls to a compliance context table."""
    from exa.compliance.ootb import sync_ootb_tables

    fw_id = _resolve_framework_id(framework)

    if dry_run:
        from exa.compliance.frameworks import load_framework as _lf

        fw = _lf(fw_id)
        n = len(fw.leaf_controls)
        tname = f"Compliance - {fw.name} Controls"
        console.print(
            f"  [dry-run] Would write {n} controls "
            f"to '{tname}'",
            style="yellow",
        )
        return

    from exa.client import ExaClient

    client = ExaClient(tenant=tenant)
    client.authenticate()
    try:
        with console.status("Syncing controls + mapping..."):
            sync_results = sync_ootb_tables(client, fw_id)

        tbl = Table(title="OOTB Sync Results", show_lines=True)
        tbl.add_column("Table Name", style="white", max_width=40)
        tbl.add_column("Action", justify="center")
        tbl.add_column("Records", justify="right")
        tbl.add_column("Errors", justify="right")

        for r in sync_results:
            action = (
                "[green]Created[/green]" if r.created
                else "[cyan]Updated[/cyan]"
            )
            err_n = len(r.errors)
            err_s = "red" if err_n else "green"
            tbl.add_row(
                r.table_name,
                action,
                str(r.records_written),
                f"[{err_s}]{err_n}[/{err_s}]",
            )

        console.print(tbl)

        for r in sync_results:
            for err in r.errors:
                console.print(f"  Error: {err}", style="red")
    finally:
        client.close()


# -- sync-identity -----------------------------------------------------------


@compliance_app.command("sync-identity")
def sync_identity(
    source_privileged: Annotated[
        str | None,
        typer.Option(help="Source table for privileged users"),
    ] = None,
    source_service_accounts: Annotated[
        str | None,
        typer.Option(help="Source table for service accounts"),
    ] = None,
    source_network_systems: Annotated[
        str | None,
        typer.Option(help="Source table for network systems"),
    ] = None,
    source_shared_accounts: Annotated[
        str | None,
        typer.Option(help="Source table for shared accounts"),
    ] = None,
    source_third_party: Annotated[
        str | None,
        typer.Option(help="Source table for third-party users"),
    ] = None,
    in_scope_systems_list: Annotated[
        str | None,
        typer.Option(help="Comma-separated in-scope system names"),
    ] = None,
    in_scope_systems_source: Annotated[
        str | None,
        typer.Option(help="Source table for in-scope systems"),
    ] = None,
    network_system_list: Annotated[
        str | None,
        typer.Option(help="Comma-separated network system names"),
    ] = None,
    filter_mode: Annotated[
        bool,
        typer.Option("--filter-mode/--no-filter-mode",
                     help="Classify from a single source table"),
    ] = False,
    source_table: Annotated[
        str | None,
        typer.Option(help="Source table (with --filter-mode)"),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force/--no-force",
                     help="Replace instead of append"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t",
                     help="Tenant profile"),
    ] = None,
) -> None:
    """Sync compliance identity context tables."""
    from exa.client import ExaClient
    from exa.compliance.identity import sync_compliance_identity_tables

    # Parse comma-separated lists
    scope_list = None
    if in_scope_systems_list:
        scope_list = [
            s.strip() for s in in_scope_systems_list.split(",")
            if s.strip()
        ]
    net_list = None
    if network_system_list:
        net_list = [
            s.strip() for s in network_system_list.split(",")
            if s.strip()
        ]

    client = ExaClient(tenant=tenant)
    client.authenticate()
    try:
        results = sync_compliance_identity_tables(
            client,
            privileged_users_source=source_privileged,
            service_accounts_source=source_service_accounts,
            shared_accounts_source=source_shared_accounts,
            third_party_users_source=source_third_party,
            in_scope_systems_source=in_scope_systems_source,
            network_systems_source=source_network_systems,
            in_scope_system_list=scope_list,
            network_system_list=net_list,
            filter_mode=filter_mode,
            source_context_table=source_table,
            force=force,
        )

        # Show results table
        table = Table(title="Identity Sync Results", show_lines=True)
        table.add_column("Table Name", style="white", max_width=40)
        table.add_column("Found", justify="right")
        table.add_column("Upserted", justify="right")
        table.add_column("Errors", justify="right")

        for r in results:
            err_style = "red" if r.errors else "green"
            table.add_row(
                r.table_name,
                str(r.records_found),
                str(r.records_upserted),
                f"[{err_style}]{r.errors}[/{err_style}]",
            )
        console.print(table)

        # Show status after sync
        _print_status(client)
    finally:
        client.close()


# -- status -------------------------------------------------------------------


@compliance_app.command("status")
def status(
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t",
                     help="Tenant profile"),
    ] = None,
) -> None:
    """Show compliance identity table status."""
    from exa.client import ExaClient

    client = ExaClient(tenant=tenant)
    client.authenticate()
    try:
        _print_status(client)
    finally:
        client.close()




def _print_status(client: object) -> None:
    """Print identity table status as a Rich table."""
    from exa.compliance.identity import get_identity_table_status

    statuses = get_identity_table_status(client)  # type: ignore[arg-type]

    table = Table(
        title="Compliance Identity Tables", show_lines=True,
    )
    table.add_column("Table Name", style="white", max_width=40)
    table.add_column("Records", justify="right")
    table.add_column("Status")

    for s in statuses:
        if s.note:
            style = "yellow"
            status_text = s.note
        elif s.record_count > 0:
            style = "green"
            status_text = "Active"
        else:
            style = "yellow"
            status_text = "Empty"
        table.add_row(
            s.name,
            str(s.record_count),
            f"[{style}]{status_text}[/{style}]",
        )

    console.print(table)


# -- audit --------------------------------------------------------------------


@compliance_app.command("audit")
def audit(
    framework: Annotated[
        str,
        typer.Option("--framework", "-f",
                     help="Framework name or ID"),
    ] = "NIST_CSF",
    lookback_days: Annotated[
        int,
        typer.Option("--lookback",
                     help="Days to search back"),
    ] = 30,
    min_evidence: Annotated[
        int,
        typer.Option("--min-evidence",
                     help="Min events per control"),
    ] = 10,
    output_json: Annotated[
        str | None,
        typer.Option("--output-json", "-o",
                     help="Save JSON report to file"),
    ] = None,
    output_html: Annotated[
        str | None,
        typer.Option(
            "--output-html",
            help="Path for HTML report (default: reports/<tenant>-<fw>-<date>.html)",
        ),
    ] = None,
    output_pdf: Annotated[
        str | None,
        typer.Option(
            "--output-pdf",
            help="Render HTML report to PDF (requires: weasyprint)",
        ),
    ] = None,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t",
                     help="Tenant profile"),
    ] = None,
) -> None:
    """Run a compliance framework gap analysis audit."""
    from exa.client import ExaClient
    from exa.compliance.audit import run_compliance_audit

    fw_id = _resolve_framework_id(framework)

    client = ExaClient(tenant=tenant)
    client.authenticate()
    try:
        report = run_compliance_audit(
            client,
            fw_id,
            lookback_days=lookback_days,
            minimum_evidence=min_evidence,
            output_report=output_json,
        )

        from exa.compliance.report import (
            default_report_path,
            generate_html_report,
            save_html_report,
        )

        # Determine HTML path. When --output-pdf is given without
        # --output-html, skip saving HTML (tempfile used for PDF only).
        if output_html is not None:
            html_path: Path | None = Path(output_html)
        elif output_pdf is None:
            t_name = tenant or "default"
            date_str = report.timestamp[:10]
            html_path = default_report_path(t_name, report.framework_name, date_str)
        else:
            html_path = None  # PDF-only: HTML goes to a tempfile

        if html_path is not None:
            save_html_report(report, html_path)
            console.print(f"\n  HTML report saved: {html_path}", style="green")

        if output_pdf is not None:
            pdf_path = Path(output_pdf) if output_pdf else html_path.with_suffix(".pdf")
            pdf_path.parent.mkdir(parents=True, exist_ok=True)
            if html_path is None:
                tmp = tempfile.NamedTemporaryFile(suffix=".html", delete=False)
                tmp_path = Path(tmp.name)
                tmp.close()
                tmp_path.write_text(generate_html_report(report), encoding="utf-8")
                src_path = tmp_path
            else:
                src_path = html_path
                tmp_path = None
            try:
                from weasyprint import HTML
                HTML(filename=str(src_path)).write_pdf(str(pdf_path))
                console.print(f"\n  PDF report saved: {pdf_path}", style="green")
            except ImportError:
                console.print(
                    "  weasyprint not installed. Run: uv add weasyprint", style="yellow"
                )
            except Exception as exc:
                console.print(f"  PDF generation failed: {exc}", style="red")
            finally:
                if tmp_path is not None:
                    tmp_path.unlink(missing_ok=True)
    finally:
        client.close()

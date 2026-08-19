"""Compliance CLI commands — sync-identity, status, audit."""

from __future__ import annotations

import subprocess
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
                     help="Framework ID or name — NIST_CSF, HIPAA, PCI_DSS, SOX, CIS_V8, GDPR, "
                          "ISO_27001, FedRAMP_Moderate, CJIS, CMMC_L2, CMMC_L3 [default: NIST_CSF]"),
    ] = "NIST_CSF",
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run/--no-dry-run",
                     help="Preview changes without writing to tables [default: no-dry-run]"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t",
                     help="Tenant nickname or FQDN [default: saved default]"),
    ] = None,
) -> None:
    """Sync framework controls and rule-to-control mapping to context tables.

    Creates or updates two tables per framework:
      'Compliance - <Framework Name> Controls' — all leaf controls with family,
      description, SIEM-testable flag, and MITRE technique coverage.
      'Compliance - <Framework Name> Mapping' — correlation rules cross-referenced
      to the controls they satisfy, extracted from rule descriptions.

    Both tables use replace semantics — re-running is safe and idempotent.

    \b
    Examples:
      uv run exa compliance sync-ootb
      uv run exa compliance sync-ootb --framework HIPAA
      uv run exa compliance sync-ootb --framework PCI_DSS --dry-run
      uv run exa compliance sync-ootb --framework CMMC_L2 --tenant csnafusion
    """
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
        typer.Option(help="[DirectMap] Source table to copy into 'Compliance - Privileged Users'"),
    ] = None,
    source_service_accounts: Annotated[
        str | None,
        typer.Option(help="[DirectMap] Source table to copy into 'Compliance - System & Service Accounts'"),
    ] = None,
    source_network_systems: Annotated[
        str | None,
        typer.Option(help="[DirectMap] Source table to copy into 'Compliance - Network Security Systems'"),
    ] = None,
    source_shared_accounts: Annotated[
        str | None,
        typer.Option(help="[DirectMap] Source table to copy into 'Compliance - Shared Accounts'"),
    ] = None,
    source_third_party: Annotated[
        str | None,
        typer.Option(help="[DirectMap] Source table to copy into 'Compliance - Third-Party Users'"),
    ] = None,
    in_scope_systems_list: Annotated[
        str | None,
        typer.Option(help="Comma-separated hostnames/IPs to populate 'Compliance - In-Scope Data Systems'"),
    ] = None,
    in_scope_systems_source: Annotated[
        str | None,
        typer.Option(help="[DirectMap] Source table to copy into 'Compliance - In-Scope Data Systems'"),
    ] = None,
    network_system_list: Annotated[
        str | None,
        typer.Option(help="Comma-separated hostnames/IPs to populate 'Compliance - Network Security Systems'"),
    ] = None,
    filter_mode: Annotated[
        bool,
        typer.Option("--filter-mode/--no-filter-mode",
                     help="Auto-classify records from --source-table into 4 target tables by naming patterns [default: no-filter-mode]"),
    ] = False,
    source_table: Annotated[
        str | None,
        typer.Option(help="[FilterMode] Source table to classify records from"),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force/--no-force",
                     help="Replace existing records instead of appending [default: no-force]"),
    ] = False,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t",
                     help="Tenant nickname or FQDN [default: saved default]"),
    ] = None,
) -> None:
    """Populate the 6 compliance identity context tables from source data.

    Two modes:

    DirectMap (default) — supply one or more --source-* options; each source
    table is copied directly into its named compliance target table.
    The 6 target tables are:
      Compliance - Privileged Users
      Compliance - System & Service Accounts
      Compliance - Shared Accounts
      Compliance - Third-Party Users
      Compliance - In-Scope Data Systems
      Compliance - Network Security Systems

    FilterMode (--filter-mode) — supply a single --source-table; records are
    auto-classified into 4 tables (Privileged Users, Service Accounts, Shared
    Accounts, Third-Party Users) by matching against known naming patterns.
    Systems tables must be supplied via --in-scope-systems-source/list and
    --network-system-list separately.

    \b
    Examples:
      # DirectMap: push from named source tables
      uv run exa compliance sync-identity --source-privileged "AD Admin Users"
      uv run exa compliance sync-identity --source-privileged "Admins" --source-service-accounts "SvcAccts" --force

      # FilterMode: auto-classify from a single source table
      uv run exa compliance sync-identity --filter-mode --source-table "All Users"
      uv run exa compliance sync-identity --filter-mode --source-table "AD Users" --tenant csnafusion
    """
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
                     help="Tenant nickname or FQDN [default: saved default]"),
    ] = None,
) -> None:
    """Show record counts and health for all 6 compliance identity tables.

    Displays a summary table covering: Privileged Users, Shared Accounts,
    Third-Party Users, System & Service Accounts, In-Scope Data Systems, and
    Network Security Systems. Empty tables are highlighted in yellow.

    \b
    Examples:
      uv run exa compliance status
      uv run exa compliance status --tenant csnafusion
    """
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
                     help="Framework ID or name — NIST_CSF, HIPAA, PCI_DSS, SOX, CIS_V8, GDPR, "
                          "ISO_27001, FedRAMP_Moderate, CJIS, CMMC_L2, CMMC_L3 [default: NIST_CSF]"),
    ] = "NIST_CSF",
    lookback_days: Annotated[
        int,
        typer.Option("--lookback",
                     help="Days of events to search per control [default: 30]"),
    ] = 30,
    min_evidence: Annotated[
        int,
        typer.Option("--min-evidence",
                     help="Minimum events required to score a control PASS [default: 10]"),
    ] = 10,
    output_json: Annotated[
        str | None,
        typer.Option("--output-json", "-o",
                     help="Save full JSON report to file [default: none]"),
    ] = None,
    output_html: Annotated[
        str | None,
        typer.Option(
            "--output-html",
            help="HTML report path (default: reports/<tenant>-<fw>-<date>.html)",
        ),
    ] = None,
    output_pdf: Annotated[
        bool,
        typer.Option(
            "--output-pdf/--no-output-pdf",
            help="Render HTML report to PDF via Edge headless, saved alongside HTML [default: no-output-pdf]",
        ),
    ] = False,
    pdf_path: Annotated[
        str | None,
        typer.Option(
            "--pdf-path",
            help="Explicit PDF output path; implies --output-pdf [default: none]",
        ),
    ] = None,
    output_csv: Annotated[
        str | None,
        typer.Option(
            "--output-csv",
            help="Save control results as CSV (auto-saved beside the HTML otherwise) [default: none]",
        ),
    ] = None,
    tenant_aware: Annotated[
        bool,
        typer.Option(
            "--tenant-aware/--no-tenant-aware",
            help="Discover active activity types and resolve queries via Field Oracle [default: tenant-aware]",
        ),
    ] = True,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t",
                     help="Tenant nickname or FQDN [default: saved default]"),
    ] = None,
) -> None:
    """Run a compliance framework gap analysis and produce an HTML/PDF report.

    Queries the SIEM for evidence events matching each SIEM-testable control in
    the selected framework. Controls with at least --min-evidence events in the
    lookback window are scored PASS; those below threshold are scored FAIL or
    INSUFFICIENT. Results are written to an HTML report (auto-named in reports/)
    and optionally rendered to PDF via Edge headless.

    Use --no-tenant-aware to skip Field Oracle discovery and run static EQL
    filters directly from ControlQueries JSON (faster, less accurate).

    \b
    Examples:
      uv run exa compliance audit
      uv run exa compliance audit --framework HIPAA --lookback 90
      uv run exa compliance audit --framework PCI_DSS --output-html reports/pci.html
      uv run exa compliance audit --framework NIST_CSF --output-pdf --tenant csnafusion
      uv run exa compliance audit --no-tenant-aware --min-evidence 5
    """
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
            tenant_aware=tenant_aware,
        )

        from exa.compliance.report import (
            default_report_path,
            generate_html_report,
            save_csv_report,
            save_html_report,
        )

        want_pdf = output_pdf or pdf_path is not None

        # Determine HTML path.  When PDF is requested without --output-html,
        # skip saving HTML (a tempfile is used as PDF source instead).
        if output_html is not None:
            html_path: Path | None = Path(output_html)
        elif not want_pdf:
            t_name = tenant or "default"
            date_str = report.timestamp[:10]
            html_path = default_report_path(t_name, report.framework_name, date_str)
        else:
            html_path = None  # PDF-only: HTML goes to a tempfile

        if html_path is not None:
            save_html_report(report, html_path)
            console.print(f"\n  HTML report saved: {html_path}", style="green")

        csv_target = None
        if output_csv is not None:
            csv_target = Path(output_csv)
        elif html_path is not None:
            csv_target = html_path.with_suffix(".csv")
        if csv_target is not None:
            save_csv_report(report, csv_target)
            console.print(f"  CSV report saved: {csv_target}", style="green")

        if want_pdf:
            if pdf_path:
                resolved_pdf = Path(pdf_path)
            else:
                t_name = tenant or "default"
                date_str = report.timestamp[:10]
                resolved_pdf = default_report_path(
                    t_name, report.framework_name, date_str
                ).with_suffix(".pdf")
            resolved_pdf.parent.mkdir(parents=True, exist_ok=True)

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
                edge_candidates = [
                    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                ]
                edge = next((p for p in edge_candidates if Path(p).exists()), None)

                if edge:
                    try:
                        subprocess.run(
                            [
                                edge,
                                "--headless",
                                "--disable-gpu",
                                "--print-to-pdf-no-header",
                                f"--print-to-pdf={resolved_pdf.resolve()}",
                                str(src_path.resolve()),
                            ],
                            capture_output=True,
                            timeout=60,
                            check=True,
                        )
                        if resolved_pdf.exists() and resolved_pdf.stat().st_size > 0:
                            console.print(f"[green]PDF report saved:[/green] {resolved_pdf}")
                        else:
                            console.print(
                                "[red]PDF generation failed:[/red] "
                                "Edge ran but no PDF was written"
                            )
                    except subprocess.CalledProcessError as exc:
                        console.print(f"[red]PDF generation failed:[/red] {exc}")
                    except subprocess.TimeoutExpired:
                        console.print("[red]PDF generation timed out[/red]")
                else:
                    console.print(
                        "[yellow]PDF skipped:[/yellow] Microsoft Edge not found. "
                        "Install Edge or open the HTML report and use "
                        "File -> Print -> Save as PDF."
                    )
            finally:
                if tmp_path is not None:
                    tmp_path.unlink(missing_ok=True)
    finally:
        client.close()

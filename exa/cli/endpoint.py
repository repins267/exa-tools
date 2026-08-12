"""exa endpoint -- live API conformance testing.

Commands:
  exa endpoint test    Run conformance audit against all catalogued endpoints
  exa endpoint list    List all endpoints in the catalog
  exa endpoint results Show findings from the last audit run
  exa endpoint diff    Compare two audit runs (what fixed vs broke)
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

endpoint_app = typer.Typer(
    name="endpoint",
    help="Live API conformance testing -- test endpoints against the Exabeam OpenAPI spec.",
    no_args_is_help=True,
)
console = Console()

_TENANT_HELP = "Tenant nickname or FQDN (default: saved default)"

_STATUS_STYLE = {
    200: "green", 201: "green", 204: "green",
    400: "yellow", 401: "yellow", 403: "yellow", 404: "yellow",
    500: "red", 503: "red",
}


def _style_status(code: int | None) -> str:
    if code is None:
        return "[dim]-[/dim]"
    style = _STATUS_STYLE.get(code, "white")
    return f"[{style}]{code}[/{style}]"


def _finding_style(result: dict) -> str:
    if result.get("skipped"):
        return "[dim]SKIPPED[/dim]"
    if result.get("new_finding"):
        return "[red bold]NEW FINDING[/red bold]"
    return "[green]OK[/green]"


# ---------------------------------------------------------------------------
# exa endpoint test
# ---------------------------------------------------------------------------

@endpoint_app.command("test")
def test(
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
    spec: Annotated[
        str | None,
        typer.Option("--spec", "-s", help="Only test endpoints in this spec (e.g. threat-center). [default: all]"),
    ] = None,
    endpoint_filter: Annotated[
        str | None,
        typer.Option("--endpoint", "-e", help="Only test endpoints whose path contains this string. [default: none]"),
    ] = None,
    catalog_path: Annotated[
        str | None,
        typer.Option("--catalog", help="Path to api-verification-results.json. [default: auto-detect]"),
    ] = None,
    destructive: Annotated[
        bool,
        typer.Option("--destructive/--no-destructive",
                     help="Include write/delete endpoints. [default: no-destructive]"),
    ] = False,
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Save results to this JSON file. [default: ~/.exa/endpoint-audits/]"),
    ] = None,
    findings_only: Annotated[
        bool,
        typer.Option("--findings-only/--no-findings-only",
                     help="Only show new findings in output table. [default: no-findings-only]"),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose/--no-verbose", help="Include response previews. [default: no-verbose]"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Output results as JSON to stdout. [default: no-json]"),
    ] = False,
) -> None:
    """Run a live conformance audit against all endpoints in the catalog.

    
    Examples:
      uv run exa endpoint test --tenant sademodev22
      uv run exa endpoint test --spec "Threat Center" --tenant sademodev22
      uv run exa endpoint test --findings-only --tenant sademodev22
      uv run exa endpoint test --json --tenant sademodev22 > audit.json"""
    import json as _json

    from exa.client import ExaClient
    from exa.endpoint.catalog import filter_catalog, load_catalog
    from exa.endpoint.runner import run_audit, save_audit

    # Load catalog
    cat_path = Path(catalog_path) if catalog_path else None
    catalog = load_catalog(cat_path)
    if not catalog:
        console.print(
            "[red]No endpoint catalog found.[/red] "
            "Run the API inventory prompt first or pass --catalog <path>."
        )
        raise typer.Exit(1)

    filtered = filter_catalog(
        catalog,
        spec=spec,
        path_filter=endpoint_filter,
        include_destructive=destructive,
    )

    total = len(filtered)
    skipped_count = sum(1 for e in filtered if e.get("_skipped"))
    runnable = total - skipped_count

    if not json_output:
        console.print(
            f"[bold]exa endpoint test[/bold] -- "
            f"{total} endpoints ({runnable} runnable, {skipped_count} skipped)"
        )
        if spec:
            console.print(f"  Spec filter: [cyan]{spec}[/cyan]")
        if endpoint_filter:
            console.print(f"  Path filter: [cyan]{endpoint_filter}[/cyan]")
        console.print()

    # Authenticate
    client = ExaClient(tenant=tenant)
    client.authenticate()
    tenant_name = client.tenant or "unknown"

    if not json_output:
        console.print(f"  Tenant: [cyan]{client.base_url}[/cyan]")
        console.print()

    # Progress callback
    def _progress(i: int, total: int, ep: dict) -> None:
        if not json_output:
            pct = int((i / total) * 100) if total else 0
            console.print(
                f"  [{pct:3d}%] {ep.get('method','?'):6s} {ep.get('path','')}",
                style="dim",
                end="\r",
            )

    results = run_audit(
        client, filtered, verbose=verbose, on_progress=_progress
    )
    client.close()

    if not json_output:
        console.print()  # clear progress line

    # Save results
    out_path = save_audit(
        results,
        tenant_name,
        output_path=Path(output) if output else None,
    )

    if json_output:
        import sys
        print(_json.dumps(results, indent=2), file=sys.stdout)
        return

    # Print summary table
    new_findings = [r for r in results if r.get("new_finding")]
    rows_to_show = new_findings if findings_only else results

    tbl = Table(title="Endpoint Audit Results", show_lines=False)
    tbl.add_column("#",          width=4,  style="dim")
    tbl.add_column("Method",     width=7)
    tbl.add_column("Endpoint",   no_wrap=False)
    tbl.add_column("HTTP",       width=6,  justify="center")
    tbl.add_column("Spec codes", width=14, style="dim")
    tbl.add_column("Result",     width=14)

    for idx, r in enumerate(rows_to_show, 1):
        doc_codes = ", ".join(str(c) for c in r.get("documented_status_codes", []))
        tbl.add_row(
            str(idx),
            r.get("method", ""),
            r.get("path", ""),
            _style_status(r.get("confirmed_status")),
            doc_codes,
            _finding_style(r),
        )

    console.print(tbl)

    # Summary line
    ok_count      = sum(1 for r in results if not r.get("new_finding") and not r.get("skipped"))
    finding_count = len(new_findings)
    skip_count    = sum(1 for r in results if r.get("skipped"))

    console.print(
        f"\n[green]{ok_count} OK[/green]  "
        f"[red]{finding_count} new finding(s)[/red]  "
        f"[dim]{skip_count} skipped[/dim]"
    )

    if new_findings:
        console.print("\n[bold red]New Findings:[/bold red]")
        for r in new_findings:
            console.print(
                f"  [red]{r['method']} {r['path']}[/red]\n"
                f"    HTTP {r.get('confirmed_status','?')} -- {r.get('finding_notes','')}"
            )

    console.print(f"\nResults saved to [dim]{out_path}[/dim]")


# ---------------------------------------------------------------------------
# exa endpoint list
# ---------------------------------------------------------------------------

@endpoint_app.command("list")
def list_endpoints(
    spec: Annotated[
        str | None,
        typer.Option("--spec", "-s", help="Filter by spec name. [default: all]"),
    ] = None,
    catalog_path: Annotated[
        str | None,
        typer.Option("--catalog", help="Path to api-verification-results.json. [default: auto-detect]"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Output as JSON. [default: no-json]"),
    ] = False,
) -> None:
    """List all endpoints in the catalog.

    
    Examples:
      uv run exa endpoint list
      uv run exa endpoint list --spec "Context"
      uv run exa endpoint list --json | jq '.[].path'"""
    import json as _json
    import sys

    from exa.endpoint.catalog import load_catalog

    cat_path = Path(catalog_path) if catalog_path else None
    catalog = load_catalog(cat_path)

    if not catalog:
        console.print("[red]No endpoint catalog found.[/red]")
        raise typer.Exit(1)

    if spec:
        catalog = [e for e in catalog if e.get("spec", "").lower() == spec.lower()]

    if json_output:
        print(_json.dumps(catalog, indent=2), file=sys.stdout)
        return

    # Group by spec
    by_spec: dict[str, list] = {}
    for ep in catalog:
        by_spec.setdefault(ep.get("spec", "unknown"), []).append(ep)

    for spec_name, endpoints in sorted(by_spec.items()):
        console.print(f"\n[bold cyan]{spec_name}[/bold cyan] ({len(endpoints)} endpoints)")
        for ep in endpoints:
            codes = " ".join(str(c) for c in ep.get("documented_status_codes", []))
            console.print(
                f"  [bold]{ep['method']:6s}[/bold] {ep['path']}"
                f"  [dim]{codes}[/dim]"
            )

    console.print(f"\nTotal: {len(catalog)} endpoints")


# ---------------------------------------------------------------------------
# exa endpoint results
# ---------------------------------------------------------------------------

@endpoint_app.command("results")
def show_results(
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
    findings_only: Annotated[
        bool,
        typer.Option("--findings-only/--no-findings-only",
                     help="Only show new findings. [default: no-findings-only]"),
    ] = True,
    json_output: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Output as JSON. [default: no-json]"),
    ] = False,
) -> None:
    """Show findings from the last audit run.

    
    Examples:
      uv run exa endpoint results --tenant sademodev22
      uv run exa endpoint results --findings-only --tenant sademodev22"""
    import json as _json
    import sys

    from exa.config import get_default_tenant
    from exa.endpoint.runner import load_last_audit

    resolved_tenant = tenant if tenant is not None else get_default_tenant()
    results = load_last_audit(resolved_tenant)
    if not results:
        console.print(f"[yellow]No audit results found for tenant '{resolved_tenant}'.[/yellow]")
        console.print("Run [bold]exa endpoint test[/bold] first.")
        raise typer.Exit(1)

    if json_output:
        data = results if not findings_only else [r for r in results if r.get("new_finding")]
        print(_json.dumps(data, indent=2), file=sys.stdout)
        return

    new_findings = [r for r in results if r.get("new_finding")]
    display = new_findings if findings_only else results

    tbl = Table(title=f"Last Audit -- {resolved_tenant}", show_lines=False)
    tbl.add_column("Method",   width=7)
    tbl.add_column("Endpoint", no_wrap=False)
    tbl.add_column("HTTP",     width=6, justify="center")
    tbl.add_column("Notes",    no_wrap=False)

    for r in display:
        tbl.add_row(
            r.get("method", ""),
            r.get("path", ""),
            _style_status(r.get("confirmed_status")),
            r.get("finding_notes", ""),
        )

    console.print(tbl)
    console.print(
        f"\n[red]{len(new_findings)} new finding(s)[/red] across {len(results)} tested endpoints"
    )


# ---------------------------------------------------------------------------
# exa endpoint diff
# ---------------------------------------------------------------------------

@endpoint_app.command("diff")
def diff(
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
    before: Annotated[
        str | None,
        typer.Option("--before", help="Path to older audit JSON. [default: second-most-recent]"),
    ] = None,
    after: Annotated[
        str | None,
        typer.Option("--after", help="Path to newer audit JSON. [default: most-recent]"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Output diff as JSON. [default: no-json]"),
    ] = False,
) -> None:
    """Compare two audit runs -- what got fixed, what broke, what's new.

    
    Examples:
      uv run exa endpoint diff --tenant sademodev22
      uv run exa endpoint diff --before run-2026-08-01.json --after run-2026-08-12.json"""
    import json as _json
    import sys
    from pathlib import Path

    from exa.config import get_default_tenant
    from exa.endpoint.runner import _AUDIT_DIR, diff_audits

    resolved_tenant = tenant if tenant is not None else get_default_tenant()

    # Load before/after
    if before and after:
        old = _json.loads(Path(before).read_text())["results"]
        new = _json.loads(Path(after).read_text())["results"]
    else:
        files = sorted(_AUDIT_DIR.glob(f"{resolved_tenant}-*.json"), reverse=True)
        if len(files) < 2:
            console.print("[yellow]Need at least 2 audit runs to diff.[/yellow]")
            raise typer.Exit(1)
        new = _json.loads(files[0].read_text())["results"]
        old = _json.loads(files[1].read_text())["results"]

    result = diff_audits(old, new)

    if json_output:
        print(_json.dumps(result, indent=2), file=sys.stdout)
        return

    for category, items in [
        ("[green bold]FIXED[/green bold]",   result["fixed"]),
        ("[red bold]BROKE[/red bold]",       result["broken"]),
        ("[cyan]NEW ENDPOINT[/cyan]",        result["new"]),
    ]:
        if items:
            console.print(f"\n{category} ({len(items)})")
            for r in items:
                console.print(f"  {r['method']:6s} {r['path']}")

    console.print(
        f"\nSummary: "
        f"[green]{len(result['fixed'])} fixed[/green]  "
        f"[red]{len(result['broken'])} broke[/red]  "
        f"[cyan]{len(result['new'])} new[/cyan]  "
        f"[dim]{len(result['unchanged'])} unchanged[/dim]"
    )

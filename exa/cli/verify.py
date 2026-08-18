"""exa verify -- prove documented behavior against a live tenant.

Commands:
  exa verify search   Run the Search/EQL probe battery
  exa verify results  Show the last run for a tenant
  exa verify vault    Print the markdown rows for the vault test section

Why this exists: everything in the vault's `search-and-eql` note is distilled from
vendor documentation, and this API's habit is to return a plausible number rather
than an error. Documented-not-verified claims were already shaping tool design, and
one of them -- the "3,000-result API cap" -- turned out never to have been true.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

verify_app = typer.Typer(
    name="verify",
    help="Prove documented Exabeam behavior against a live tenant (read-only probes).",
    no_args_is_help=True,
)
console = Console()

_TENANT_HELP = "Tenant nickname or FQDN (default: saved default)"

_VERDICT_STYLE = {
    "CONFIRMED": "[green]CONFIRMED[/green]",
    "REFUTED": "[red bold]REFUTED[/red bold]",
    "INCONCLUSIVE": "[yellow]INCONCLUSIVE[/yellow]",
}


def _style_verdict(verdict: str) -> str:
    return _VERDICT_STYLE.get(verdict, verdict)


def _print_probes(artifact: dict, *, verbose: bool) -> None:
    tbl = Table(title=f"Search verification -- {artifact.get('tenant','?')}", show_lines=False)
    tbl.add_column("Probe", no_wrap=True)
    tbl.add_column("Verdict", width=14)
    tbl.add_column("Pre", width=4, justify="center")
    tbl.add_column("Finding", no_wrap=False)

    for probe in artifact.get("probes", []):
        met = probe.get("precondition_met")
        pre = "[green]y[/green]" if met else ("[red]n[/red]" if met is False else "[dim]-[/dim]")
        tbl.add_row(
            probe.get("probe", ""),
            _style_verdict(probe.get("verdict", "")),
            pre,
            probe.get("reason", ""),
        )
    console.print(tbl)

    summary = artifact.get("summary", {})
    console.print(
        f"\n[green]{summary.get('confirmed',0)} confirmed[/green]  "
        f"[red]{summary.get('refuted',0)} refuted[/red]  "
        f"[yellow]{summary.get('inconclusive',0)} inconclusive[/yellow]  "
        f"[dim]of {summary.get('total',0)} probes[/dim]"
    )

    if summary.get("inconclusive"):
        console.print(
            "\n[dim]INCONCLUSIVE is not a failure -- it means the tenant's data could not "
            "have shown the difference the probe needed. Widen --lookback or use a busier "
            "tenant; do not record it as either outcome.[/dim]"
        )

    if verbose:
        for probe in artifact.get("probes", []):
            console.print(f"\n[bold cyan]{probe.get('probe')}[/bold cyan]")
            console.print(f"  claim:  {probe.get('claim')}")
            console.print(f"  source: {probe.get('source')}")
            console.print(f"  method: {probe.get('method')}")
            for key, value in (probe.get("observed") or {}).items():
                console.print(f"    [dim]{key}[/dim] = {value}")


# ---------------------------------------------------------------------------
# exa verify search
# ---------------------------------------------------------------------------


@verify_app.command("search")
def verify_search(
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
    lookback: Annotated[
        int,
        typer.Option("--lookback", help="Days of data the probes may use. [default: 7]"),
    ] = 7,
    probe: Annotated[
        str | None,
        typer.Option(
            "--probe",
            help="Comma-separated probe names to run, e.g. limit-default,null-quoting. "
                 "[default: all except pipe-quota]",
        ),
    ] = None,
    table: Annotated[
        str,
        typer.Option(
            "--table",
            help="Context table for the 90-day window probe, matched EXACTLY. "
                 "[default: Public AI Domains and Risk]",
        ),
    ] = "Public AI Domains and Risk",
    table_id: Annotated[
        str | None,
        typer.Option(
            "--table-id",
            help="Pin the context table by ID instead of by name -- use this when two "
                 "tables have near-identical names. [default: resolve from --table]",
        ),
    ] = None,
    table_column: Annotated[
        str | None,
        typer.Option(
            "--table-column",
            help="Context table column to look up. [default: the table's real key "
                 "attribute, which is NOT necessarily named 'key']",
        ),
    ] = None,
    event_field: Annotated[
        str,
        typer.Option(
            "--event-field",
            help="CIM field matched against the context table. [default: web_domain]",
        ),
    ] = "web_domain",
    include_pipe_probes: Annotated[
        bool,
        typer.Option(
            "--include-pipe-probes/--no-include-pipe-probes",
            help="Run the pipe probe. It SPENDS from a deployment-wide quota of 1,000 pipe "
                 "queries per month. Never schedule this. [default: no-include-pipe-probes]",
        ),
    ] = False,
    pipe_eql: Annotated[
        str | None,
        typer.Option(
            "--pipe-eql",
            help="Pipe query used by the pipe probe. [default: a SELECT ... | LIMIT 5]",
        ),
    ] = None,
    output: Annotated[
        str | None,
        typer.Option(
            "--output", "-o",
            help="Save the artifact here. [default: ~/.exa/search-verify/<tenant>-<ts>.json]",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose/--no-verbose",
                     help="Print each probe's claim, method and measurements. "
                          "[default: no-verbose]"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Print the artifact as JSON. [default: no-json]"),
    ] = False,
) -> None:
    """Probe the documented Search/EQL limits against a live tenant.

    Read-only. Every probe is differential (two calls that must differ if the claim
    holds) and preconditioned (a separate measurement proving the tenant's data
    could have shown that difference). When the precondition fails the verdict is
    INCONCLUSIVE, never a guess.

    Run it on a demo tenant, not a customer: sademodev22 or csnafusion.

    \b
    Examples:
      uv run exa verify search --tenant sademodev22
      uv run exa verify search --tenant sademodev22 --lookback 30 --verbose
      uv run exa verify search --tenant sademodev22 --probe limit-default,null-quoting
      uv run exa verify search --tenant sademodev22 --table-id pg5mmUzim3
      uv run exa verify search --tenant csnafusion --probe query-vs-filter,limit-default,time-range
      uv run exa verify search --tenant sademodev22 --json > verify.json"""
    import json as _json
    import sys

    from exa.client import ExaClient
    from exa.search.verify import (
        PIPE_PROBE_NAME,
        PROBE_NAMES,
        run_verification,
        save_verification,
    )

    only = None
    if probe:
        only = [p.strip() for p in probe.split(",") if p.strip()]
        valid = set(PROBE_NAMES) | {PIPE_PROBE_NAME}
        unknown = [p for p in only if p not in valid]
        if unknown:
            console.print(f"[red]Unknown probe(s):[/red] {', '.join(unknown)}")
            console.print(f"Available: {', '.join(PROBE_NAMES)}, {PIPE_PROBE_NAME}")
            raise typer.Exit(1)
        # Asking for the pipe probe without the opt-in flag would otherwise run
        # nothing and report a clean, empty, entirely meaningless pass.
        if only == [PIPE_PROBE_NAME] and not include_pipe_probes:
            console.print(
                f"[red]--probe {PIPE_PROBE_NAME} also needs --include-pipe-probes.[/red] "
                "It is gated because it spends from a deployment-wide quota of 1,000 pipe "
                "queries per month."
            )
            raise typer.Exit(1)

    if not json_output:
        console.print("[bold]exa verify search[/bold] -- read-only probes of documented behavior")
        if include_pipe_probes:
            console.print(
                "[yellow]Pipe probe enabled: this spends 2 of the deployment's 1,000 "
                "monthly pipe queries.[/yellow]"
            )
        console.print()

    client = ExaClient(tenant=tenant)
    client.authenticate()
    tenant_name = client.tenant or "unknown"

    if not json_output:
        console.print(f"  Tenant: [cyan]{client.base_url}[/cyan]")
        console.print()

    def _progress(index: int, total: int, name: str) -> None:
        if not json_output:
            console.print(f"  [{index}/{total}] {name}", style="dim", end="\r")

    artifact = run_verification(
        client,
        lookback_days=lookback,
        table_name=table,
        table_id=table_id,
        table_column=table_column,
        event_field=event_field,
        include_pipe_probes=include_pipe_probes,
        pipe_eql=pipe_eql,
        only=only,
        on_progress=_progress,
    )
    client.close()

    out_path = save_verification(
        artifact, tenant_name, output_path=Path(output) if output else None
    )
    artifact["artifact_path"] = str(out_path)

    if json_output:
        print(_json.dumps(artifact, indent=2, default=str), file=sys.stdout)
        return

    console.print(" " * 40, end="\r")
    _print_probes(artifact, verbose=verbose)
    console.print(f"\nArtifact saved to [dim]{out_path}[/dim]")
    console.print(
        "Record the settled rows with [bold]exa verify vault[/bold] and paste them into "
        "50-Product-Docs/search-and-eql.md."
    )


# ---------------------------------------------------------------------------
# exa verify results
# ---------------------------------------------------------------------------


@verify_app.command("results")
def verify_results(
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose/--no-verbose",
                     help="Print each probe's claim, method and measurements. "
                          "[default: no-verbose]"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json/--no-json", help="Print the artifact as JSON. [default: no-json]"),
    ] = False,
) -> None:
    """Show the most recent verification run for a tenant.

    \b
    Examples:
      uv run exa verify results --tenant sademodev22
      uv run exa verify results --tenant sademodev22 --verbose
      uv run exa verify results --tenant sademodev22 --json | jq '.summary'"""
    import json as _json
    import sys

    from exa.config import get_default_tenant
    from exa.search.verify import load_last_verification

    resolved = tenant if tenant is not None else get_default_tenant()
    artifact = load_last_verification(resolved or "")
    if not artifact:
        console.print(f"[yellow]No verification run found for tenant '{resolved}'.[/yellow]")
        console.print("Run [bold]exa verify search[/bold] first.")
        raise typer.Exit(1)

    if json_output:
        print(_json.dumps(artifact, indent=2, default=str), file=sys.stdout)
        return

    console.print(f"Run at [cyan]{artifact.get('run_at','?')}[/cyan]\n")
    _print_probes(artifact, verbose=verbose)


# ---------------------------------------------------------------------------
# exa verify vault
# ---------------------------------------------------------------------------


@verify_app.command("vault")
def verify_vault(
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
    settled_only: Annotated[
        bool,
        typer.Option(
            "--settled-only/--no-settled-only",
            help="Emit only CONFIRMED and REFUTED rows, dropping INCONCLUSIVE. "
                 "[default: settled-only]",
        ),
    ] = True,
) -> None:
    """Print the last run as markdown rows for the vault's test section.

    Generated rather than retyped so the vault note and the JSON artifact behind it
    cannot drift apart. Paste under "Verified live" in
    50-Product-Docs/search-and-eql.md.

    \b
    Examples:
      uv run exa verify vault --tenant sademodev22
      uv run exa verify vault --tenant sademodev22 --no-settled-only"""
    from exa.config import get_default_tenant
    from exa.search.verify import load_last_verification, vault_rows

    resolved = tenant if tenant is not None else get_default_tenant()
    artifact = load_last_verification(resolved or "")
    if not artifact:
        console.print(f"[yellow]No verification run found for tenant '{resolved}'.[/yellow]")
        raise typer.Exit(1)

    if settled_only:
        artifact = dict(artifact)
        artifact["probes"] = [
            p for p in artifact.get("probes", [])
            if p.get("verdict") in ("CONFIRMED", "REFUTED")
        ]
        if not artifact["probes"]:
            console.print(
                "[yellow]Nothing settled in the last run -- every probe was "
                "INCONCLUSIVE.[/yellow] Re-run with a wider --lookback or a busier tenant."
            )
            raise typer.Exit(1)

    # print(), not console.print(): this output is meant to be copied verbatim, and
    # rich would wrap the table rows.
    print(vault_rows(artifact))

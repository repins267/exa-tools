"""CLI command for updating CIM2 and Content Hub reference data."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

update_app = typer.Typer(
    name="update",
    help="Download/update CIM2 and Content Hub reference data.",
    invoke_without_command=True,
)
console = Console()


@update_app.callback(invoke_without_command=True)
def update(
    ctx: typer.Context,
    check: Annotated[
        bool,
        typer.Option("--check", help="Show current state without pulling"),
    ] = False,
) -> None:
    """Download or update CIM2 and Content Hub reference data."""
    if ctx.invoked_subcommand is not None:
        return

    if check:
        _show_check()
        return

    _run_update()


def _show_check() -> None:
    """Show current reference data state."""
    from exa.update import check_reference_data

    status = check_reference_data()

    table = Table(title="Reference Data Status")
    table.add_column("Repository", style="cyan")
    table.add_column("SHA", style="white")
    table.add_column("Status", style="dim")

    for repo, sha in status.items():
        if sha == "not cloned":
            style_text = "[yellow]not cloned[/yellow]"
        else:
            style_text = "[green]available[/green]"
        table.add_row(repo, sha, style_text)

    console.print(table)


def _run_update() -> None:
    """Run the full update pipeline."""
    from rich.progress import Progress

    from exa.update import update_reference_data

    console.print("Updating reference data...\n", style="dim")

    with Progress(console=console) as progress:
        task = progress.add_task("Syncing repos + parsing...", total=None)
        result = update_reference_data()
        progress.update(task, completed=100, total=100)

    # Repo sync results
    repo_table = Table(title="Repository Sync")
    repo_table.add_column("Repository", style="cyan")
    repo_table.add_column("Action", style="white")
    repo_table.add_column("HEAD SHA", style="dim")

    if result.cim2_action:
        repo_table.add_row(
            "Content-Library-CIM2",
            f"[green]{result.cim2_action}[/green]",
            result.cim2_sha,
        )
    if result.content_hub_action:
        repo_table.add_row(
            "new-scale-content-hub",
            f"[green]{result.content_hub_action}[/green]",
            result.content_hub_sha,
        )
    if result.sigma_action:
        repo_table.add_row(
            "SigmaHQ/sigma",
            f"[green]{result.sigma_action}[/green]",
            result.sigma_sha,
        )
    if result.aillm_domains_action:
        repo_table.add_row(
            "repins267/ai-llm-domains",
            f"[green]{result.aillm_domains_action}[/green]",
            result.aillm_domains_sha,
        )
    for err in result.errors:
        repo_table.add_row("", f"[red]{err}[/red]", "")

    console.print(repo_table)

    # Cache parse results
    if result.cache_results:
        cache_table = Table(title="Parsed Cache Files")
        cache_table.add_column("File", style="cyan")
        cache_table.add_column("Records", justify="right", style="white")
        cache_table.add_column("Last Updated", style="dim")

        for cr in result.cache_results:
            if cr.error:
                cache_table.add_row(
                    cr.name, f"[red]{cr.error}[/red]", "",
                )
            else:
                cache_table.add_row(
                    cr.name, str(cr.records), cr.updated,
                )

        if result.aillm_domains_sha:
            from exa.aillm.reference import load_reference_data
            try:
                ref = load_reference_data()
                cache_table.add_row(
                    "ai_llm_domains",
                    str(len(ref.public_domains)),
                    result.aillm_domains_sha[:12],
                )
            except Exception:
                pass

        console.print(cache_table)

    console.print(
        "\n  Cache location: ~/.exa/cache/",
        style="dim",
    )

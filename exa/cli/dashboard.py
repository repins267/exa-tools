"""Render Exabeam dashboard .config files as branded exa-tools preview reports."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

dashboard_app = typer.Typer(
    name="dashboard",
    help="Preview/convert Exabeam dashboard .config files as shareable reports.",
    no_args_is_help=True,
)
console = Console()
_TENANT_HELP = "Tenant nickname or FQDN (default: saved default)"


@dashboard_app.command("preview")
def preview_cmd(
    path: Annotated[
        Path,
        typer.Argument(help="A dashboard .config file, or a directory of them"),
    ],
    output: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "--output",
            "-o",
            help="Output path [default: reports/dashboards/<slug>.<fmt>]",
        ),
    ] = None,
    scrub: Annotated[
        bool,
        typer.Option(
            "--scrub/--no-scrub",
            help="Strip customer names from titles/descriptions [default: scrub]",
        ),
    ] = True,
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="html or pdf [default: html]"),
    ] = "html",
    live: Annotated[
        bool,
        typer.Option(
            "--live/--layout",
            help="Populate panels with live SAMPLE data from the tenant, or render "
            "layout only [default: live]",
        ),
    ] = True,
    sample_limit: Annotated[
        int,
        typer.Option("--sample-limit", help="Max rows/slices per panel [default: 8]"),
    ] = 8,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Render a dashboard .config (or a folder of them) as a shareable preview report.

    A single file renders one preview; a directory renders one gallery page of every
    .config under it. Panels are populated with SAMPLE data (grouped by the panel's
    dimension; the context-table filter is approximated, so counts show shape not
    exact scoped values). --scrub removes customer identity so the output is safe to
    share (the preview shows only title/description/sample-data, and sample data comes
    from the connected tenant, not any customer).

    \b
    Examples:
      uv run exa dashboard preview "Public AI_LLM Usage.config" --tenant sademodev22
      uv run exa dashboard preview ./Dashboards -o gallery.html --tenant sademodev22
      uv run exa dashboard preview dlp.config --format pdf --no-scrub
    """
    from exa.report.dashboard import (
        configs_to_gallery,
        dashboard_preview_html,
        scrub_config,
    )

    fmt = fmt.strip().lower()
    if fmt not in ("html", "pdf"):
        console.print("[red]--format must be html or pdf[/]")
        raise typer.Exit(1)

    if path.is_dir():
        files = sorted(path.rglob("*.config"))
        if not files:
            console.print(f"[red]No .config files under {path}[/]")
            raise typer.Exit(1)
    elif path.is_file():
        files = [path]
    else:
        console.print(f"[red]Not found: {path}[/]")
        raise typer.Exit(1)

    named: list[tuple[str, dict]] = []
    for f in files:
        try:
            named.append((f.stem, json.loads(f.read_text(encoding="utf-8"))))
        except (OSError, json.JSONDecodeError) as e:
            console.print(f"[yellow]skip {f.name}: {e}[/]")
    if not named:
        console.print("[red]No valid .config files parsed[/]")
        raise typer.Exit(1)

    client = None
    if live:
        from exa.cli.app import _make_client

        client = _make_client(tenant)

    try:
        if len(named) == 1 and not path.is_dir():
            cfg = named[0][1]
            if scrub:
                cfg, notes = scrub_config(cfg)
                for n in notes:
                    console.print(f"  scrubbed: {n}", style="dim")
            html = dashboard_preview_html(cfg, client=client, sample_limit=sample_limit)
            default_name = cfg.get("title") or named[0][0]
        else:
            html = configs_to_gallery(
                named, client=client, sample_limit=sample_limit, scrub=scrub
            )
            default_name = (path.name if path.is_dir() else "dashboards") + "-gallery"
    finally:
        if client is not None:
            client.close()

    slug = re.sub(r"[^a-z0-9]+", "-", str(default_name).lower()).strip("-") or "dashboard"
    out = Path(output) if output else Path("reports") / "dashboards" / f"{slug}.{fmt}"
    out.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "html":
        out.write_text(html, encoding="utf-8")
        console.print(f"[green]Preview saved:[/] {out}")
    else:
        from exa.report.pdf import PdfUnavailableError, html_str_to_pdf

        try:
            html_str_to_pdf(html, out)
            console.print(f"[green]Preview PDF saved:[/] {out}")
        except PdfUnavailableError as e:
            console.print(f"[yellow]PDF skipped:[/] {e}")
            raise typer.Exit(1) from e

    console.print(
        f"  {len(named)} dashboard(s) · {'live sample' if live else 'layout only'} · "
        f"{'scrubbed' if scrub else 'not scrubbed'}",
        style="dim",
    )

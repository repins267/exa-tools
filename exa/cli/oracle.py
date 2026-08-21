"""`exa oracle` — build the Field Oracle from a tenant's live parser export.

Replaces the stale ~500 MB Content-Library-CIM2 clone as the Oracle's source.
Point a tenant at its parser export once (a `.zip` of parsers.conf +
event_builder.conf, or the extracted dir), and the Oracle is built from what the
tenant actually runs. Only the PATH is stored in config — exa-tools never keeps
the export itself.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

oracle_app = typer.Typer(
    name="oracle",
    help="Build the Field Oracle from a tenant's live parser export.",
    no_args_is_help=True,
)
console = Console()

_TENANT_HELP = "Tenant nickname or FQDN (default: saved default)"


@oracle_app.command("build")
def build_cmd(
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
    parsers: Annotated[
        Path | None,
        typer.Option("--parsers", help="Parser export: a .zip, a dir, or a parsers.conf"),
    ] = None,
    base: Annotated[
        bool,
        typer.Option("--base", help="Build the default base pack (fallback when no export)"),
    ] = False,
    from_api: Annotated[
        bool,
        typer.Option("--from-api", help="Build the Oracle live from the Log Stream API"),
    ] = False,
    out: Annotated[
        Path | None,
        typer.Option("--out", help="Write the Oracle here instead of the default cache path"),
    ] = None,
) -> None:
    """Build a Field Oracle from a parser export, or live from the Log Stream API.

    \b
    Examples:
      exa oracle build --tenant <tenant> --from-api                    # live, no export file
      exa oracle build --tenant <tenant> --parsers Parser_Update.zip   # build + remember the path
      exa oracle build --tenant <tenant>                               # rebuild from the saved path
      exa oracle build --base --parsers demo-parsers.zip               # the default base pack
    """
    from exa.oracle.export_builder import build_oracle_from_zip, write_oracle
    from exa.oracle.paths import base_oracle_path, tenant_oracle_path

    if from_api:
        from exa.cli.app import _make_client
        from exa.config import get_default_tenant
        from exa.oracle.api_source import build_oracle_from_api

        resolved = (tenant or "").strip() or get_default_tenant()
        if not resolved:
            console.print("[red]--from-api needs a tenant. Pass -t <tenant> or set a default.[/]")
            raise typer.Exit(1)
        try:
            client = _make_client(resolved)
        except Exception as e:  # noqa: BLE001 - surface auth/connection errors cleanly
            console.print(f"[red]Could not authenticate '{resolved}': {e}[/]")
            raise typer.Exit(1)
        try:
            oracle = build_oracle_from_api(client)
        except Exception as e:  # noqa: BLE001
            console.print(f"[red]Log Stream API build failed: {e}[/]")
            raise typer.Exit(1)
        finally:
            client.close()
        dest = out or (base_oracle_path() if base else tenant_oracle_path(resolved))
        label = f"base pack (live: {resolved})" if base else f"tenant '{resolved}' (live)"
        write_oracle(oracle, dest)
        _print_build_summary(label, dest, oracle)
        return

    if base:
        if parsers is None:
            console.print("[red]--base needs --parsers <export> to build from.[/]")
            raise typer.Exit(1)
        source: Path = parsers
        dest = out or base_oracle_path()
        label = "base pack"
    elif tenant:
        from exa.config import get_tenant_parsers_path, set_tenant_parsers_path

        if parsers is not None:
            set_tenant_parsers_path(tenant, str(parsers))  # remember it for next time
            source = parsers
        else:
            saved = get_tenant_parsers_path(tenant)
            if not saved:
                console.print(
                    f"[red]No parser export configured for '{tenant}'.[/] "
                    "Pass --parsers <export> once, or use --from-api.",
                )
                raise typer.Exit(1)
            source = Path(saved)
        dest = out or tenant_oracle_path(tenant)
        label = f"tenant '{tenant}'"
    else:
        if parsers is None:
            console.print("[red]Pass --tenant, --base, --parsers, or --from-api.[/]")
            raise typer.Exit(1)
        source = parsers
        dest = out or (Path.home() / ".exa" / "cache" / "field_oracle.json")
        label = "default Oracle"

    try:
        oracle = build_oracle_from_zip(source)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)

    write_oracle(oracle, dest)
    _print_build_summary(label, dest, oracle)


def _print_build_summary(label: str, dest, oracle: dict) -> None:
    st = oracle["stats"]
    console.print(f"[green]Built {label}[/] -> {dest}")
    console.print(
        f"  {st['parsers_processed']} parsers · {len(oracle['by_vendor'])} vendors · "
        f"{len(oracle['by_activity_type'])} activity types · "
        f"{len(oracle['raw_to_cim2'])} raw->CIM2 maps",
        style="dim",
    )
    console.print(f"  raw->CIM2: {st['raw_to_cim2_note']}", style="dim")


@oracle_app.command("use")
def use_cmd(
    which: Annotated[
        str,
        typer.Argument(help="A tenant name, or 'base', to activate as the default Oracle"),
    ],
) -> None:
    """Activate a built Oracle as the default (copies it to field_oracle.json).

    Consumers that don't target a specific tenant read the active Oracle, so this
    picks which parser set drives conversion/compliance when no tenant is given.

    \b
    Examples:
      exa oracle use <tenant>
      exa oracle use base
    """
    import shutil

    from exa.oracle.paths import base_oracle_path, tenant_oracle_path

    src = base_oracle_path() if which.strip().lower() == "base" else tenant_oracle_path(which)
    if not src.exists():
        console.print(f"[red]No Oracle built for '{which}'.[/] Build it with 'exa oracle build'.")
        raise typer.Exit(1)
    dest = Path.home() / ".exa" / "cache" / "field_oracle.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dest)
    console.print(f"[green]Active Oracle:[/] {which}  ({src.name} -> {dest.name})")


@oracle_app.command("status")
def status_cmd(
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help="Show which Oracle this tenant would use"),
    ] = None,
) -> None:
    """Show the Oracles on disk and which one a tenant resolves to.

    \b
    Examples:
      exa oracle status
      exa oracle status --tenant <tenant>
    """
    from exa.oracle.paths import _BUNDLED_BASE, oracle_path

    cache = Path.home() / ".exa" / "cache"
    rows: list[tuple[str, Path]] = []
    if cache.is_dir():
        for p in sorted(cache.glob("field_oracle*.json")):
            rows.append((p.stem, p))
    if _BUNDLED_BASE.exists():
        rows.append((_BUNDLED_BASE.stem + " (bundled)", _BUNDLED_BASE))

    if not rows:
        console.print("No Field Oracle built yet.", style="yellow")
        console.print("Build one: exa oracle build --tenant <t> --parsers <export>", style="dim")
        raise typer.Exit(0)

    table = Table(show_header=True, header_style="bold")
    table.add_column("Oracle")
    table.add_column("Parsers")
    table.add_column("Vendors")
    table.add_column("Source")
    table.add_column("Built", style="dim")
    for name, p in rows:
        try:
            o = json.loads(p.read_text(encoding="utf-8"))
            st = o.get("stats", {})
            table.add_row(
                name,
                str(st.get("parsers_processed", "?")),
                str(len(o.get("by_vendor", {}))),
                st.get("source", "cim2-clone"),
                str(o.get("built_at", ""))[:19],
            )
        except (OSError, json.JSONDecodeError):
            table.add_row(name, "[red]unreadable[/]", "-", "-", "-")
    console.print(table)

    resolved = oracle_path(tenant)
    who = f"tenant '{tenant}'" if tenant else "default (no tenant)"
    console.print(
        f"\n{who} resolves to: [cyan]{resolved if resolved else 'none — build one first'}[/]"
    )

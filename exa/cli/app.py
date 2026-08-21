"""exa-tools CLI application."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

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

_TENANT_HELP = "Tenant nickname or FQDN (default: saved default)"


def _make_client(tenant: str | None = None) -> ExaClient:
    """Create and authenticate an ExaClient from keyring."""
    from exa.client import ExaClient

    client = ExaClient(tenant=tenant)
    client.authenticate()
    return client


# -- Configure ----------------------------------------------------------------

@app.command()
def configure() -> None:
    """Set up tenant credentials (stored in Windows Credential Manager).

    \b
    Related:
      exa config tenants   list the tenants already configured
      exa auth -t <name>   verify one of them works
      exa config remove    remove a tenant and its stored credentials
    """
    from rich.prompt import Prompt

    from exa.config import resolve_fqdn, save_profile, set_default_tenant

    # Tenant FQDN
    fqdn_input = Prompt.ask(
        "Tenant FQDN or name "
        "(e.g. sademodev22.exabeam.cloud or "
        "csdevfusion.use1.exabeam.cloud)"
    )
    if not fqdn_input.strip():
        console.print("Tenant FQDN cannot be empty.", style="red")
        raise typer.Exit(1)

    try:
        nickname, fqdn, api_server, region = resolve_fqdn(fqdn_input)
    except ValueError as e:
        console.print(f"x {e}", style="red")
        raise typer.Exit(1)

    console.print(
        f"OK Resolved: {fqdn} -> {region} ({api_server})",
        style="green",
    )

    # Credentials
    client_id = Prompt.ask("Key ID")
    if not client_id.strip():
        console.print("Key ID cannot be empty.", style="red")
        raise typer.Exit(1)
    client_id = client_id.strip()

    client_secret = Prompt.ask("Key Secret", password=True)
    if not client_secret:
        console.print("Key Secret cannot be empty.", style="red")
        raise typer.Exit(1)

    # Test connection
    from exa.client import ExaClient

    console.print("\nTesting connection...", style="dim")
    try:
        test_client = ExaClient(api_server, client_id, client_secret)
        test_client.authenticate()
        test_client.close()
    except Exception as e:
        console.print(
            f"x Connection failed — "
            f"verify credentials and region\n"
            f"  API server tried: {api_server}\n"
            f"  Error: {e}",
            style="red",
        )
        raise typer.Exit(1)

    console.print(
        f"OK Connected — {fqdn} ({region})",
        style="green",
    )

    # Save profile
    save_profile(
        nickname, api_server, client_id, client_secret,
        fqdn=fqdn, region=region,
    )
    console.print(
        "  Credentials saved to Windows Credential Manager",
        style="dim",
    )

    # Default tenant
    set_as_default = Prompt.ask(
        "Set as default tenant?", choices=["Y", "n"], default="Y",
    )
    if set_as_default.upper() == "Y":
        set_default_tenant(nickname)
        console.print(f"  Default tenant: {nickname}", style="dim")

    # CIM2 reference data
    download_cim2 = Prompt.ask(
        "Download CIM2 reference data now?",
        choices=["Y", "n"], default="Y",
    )
    if download_cim2.upper() == "Y":
        from exa.cli.update import _run_update

        _run_update()

    # SigmaHQ community rules
    download_sigma = Prompt.ask(
        "Download SigmaHQ community rules? (~500MB)",
        choices=["Y", "n"], default="n",
    )
    if download_sigma.upper() == "Y":
        from exa.update import update_reference_data

        console.print("Cloning SigmaHQ...", style="dim")
        update_reference_data(include_sigma=True)


# -- Auth test ----------------------------------------------------------------

@app.command()
def auth(
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Test authentication against saved tenant credentials.

    \b
    Examples:
      exa auth                      # the saved default tenant
      exa auth -t baystate          # a specific tenant by nickname
      exa config tenants            # which nicknames exist

    -t takes a tenant NICKNAME or FQDN. It is not a subcommand -- `exa auth -t
    list` looks for a tenant literally named "list". Use `exa config tenants`.
    """
    import time

    try:
        client = _make_client(tenant)
        ttl = int(client._expires_at - time.time())
        console.print(
            "Authentication successful", style="green",
        )
        console.print(f"  Token expires in {ttl}s")
        console.print(f"  API server: {client.base_url}", style="dim")
        client.close()
    except Exception as e:
        console.print(f"Authentication failed: {e}", style="red")
        raise typer.Exit(1)


# -- Version ------------------------------------------------------------------

@app.command()
def version() -> None:
    """Show exa-tools version."""
    from importlib.metadata import version as _version
    console.print(f"exa-tools {_version('exa-tools')}")


@app.command()
def commands(
    search: Annotated[
        str | None,
        typer.Argument(help="Only show commands matching this text [default: show all]"),
    ] = None,
) -> None:
    """List every command, including subcommands, in one flat searchable list.

    `exa --help` shows the 22 top-level groups but none of the ~90 subcommands
    beneath them, so a command you half-remember is effectively unfindable --
    you have to guess which group owns it and run `--help` again. This searches
    names and descriptions in one pass.

    \b
    Examples:
      exa commands              # everything
      exa commands tenant       # anything mentioning tenants
      exa commands ai           # the AI/LLM surface
      exa commands rule         # rule-related commands across every group
    """
    needle = (search or "").strip().lower()
    rows: list[tuple[str, str]] = []

    def _help_of(obj: object) -> str:
        text = getattr(obj, "help", None) or (getattr(obj, "callback", None).__doc__ or "")
        return " ".join(str(text).split()).split(". ")[0][:90]

    for cmd in app.registered_commands:
        name = cmd.name or (cmd.callback.__name__ if cmd.callback else "")
        rows.append((f"exa {name}", _help_of(cmd)))

    for group in app.registered_groups:
        inner = group.typer_instance
        if inner is None:
            continue
        gname = inner.info.name
        if not isinstance(gname, str):
            continue
        if getattr(inner.info, "hidden", False):
            continue
        for cmd in inner.registered_commands:
            cname = cmd.name or (cmd.callback.__name__ if cmd.callback else "")
            rows.append((f"exa {gname} {cname}", _help_of(cmd)))
        # Sub-groups, e.g. `exa tables records list`
        for sub in inner.registered_groups:
            si = sub.typer_instance
            if si is None or not isinstance(si.info.name, str):
                continue
            for cmd in si.registered_commands:
                cname = cmd.name or (cmd.callback.__name__ if cmd.callback else "")
                rows.append((f"exa {gname} {si.info.name} {cname}", _help_of(cmd)))

    if needle:
        rows = [r for r in rows if needle in r[0].lower() or needle in r[1].lower()]

    if not rows:
        console.print(f"No commands match '{search}'.", style="yellow")
        console.print("Run 'exa commands' with no argument to see all.", style="dim")
        raise typer.Exit(1)

    width = max(len(r[0]) for r in rows)
    for name, desc in sorted(rows):
        console.print(f"  [cyan]{name:<{width}}[/cyan]  {desc}")
    suffix = f" matching '{search}'" if search else ""
    console.print(f"\n  {len(rows)} command(s){suffix}", style="dim")


# -- Context tables -----------------------------------------------------------

from exa.cli.tables import tables_app  # noqa: E402

app.add_typer(tables_app)


# -- AI/LLM ------------------------------------------------------------------

from exa.cli.aillm import aillm_app  # noqa: E402

app.add_typer(aillm_app)

from exa.cli.dashboard import dashboard_app  # noqa: E402

app.add_typer(dashboard_app)

from exa.cli.assess import assess_app  # noqa: E402

app.add_typer(assess_app)


# -- Health / licence --------------------------------------------------------

from exa.cli.health import health_app  # noqa: E402

app.add_typer(health_app)

# -- Threat Center (cases + alerts + case triage) ----------------------------

from exa.cli.case import case_app  # noqa: E402
from exa.cli.cases import alerts_app, cases_app  # noqa: E402

app.add_typer(cases_app)
app.add_typer(alerts_app)
app.add_typer(case_app)


# -- Detection rules ----------------------------------------------------------

from exa.cli.detection import detection_app  # noqa: E402

app.add_typer(detection_app)


# -- Endpoint audit -----------------------------------------------------------

from exa.cli.endpoint import endpoint_app  # noqa: E402

app.add_typer(endpoint_app)


# -- Search -------------------------------------------------------------------

_SEARCH_DEFAULT_API_FIELDS = ["user", "host", "activity_type", "outcome"]
_SEARCH_DEFAULT_DISPLAY_FIELDS = ["timestamp"] + _SEARCH_DEFAULT_API_FIELDS

_OUTCOME_STYLES: dict[str, str] = {
    "success": "green", "allow": "green", "allowed": "green",
    "fail": "red", "failure": "red", "blocked": "red", "deny": "red", "denied": "red",
}
_PARSED_STYLES: dict[str, str] = {"yes": "green", "no": "red"}


def _style_cell(col: str, value: str) -> str:
    """Return Rich markup for a table cell, applying colour rules."""
    col_lower = col.lower()
    if col_lower == "outcome":
        style = _OUTCOME_STYLES.get(value.lower())
        if style:
            return f"[{style}]{value}[/{style}]"
    elif col_lower == "parsed":
        style = _PARSED_STYLES.get(value.lower())
        if style:
            return f"[{style}]{value}[/{style}]"
    return value


@app.command()
def search(
    filter_str: Annotated[
        str,
        typer.Argument(
            help=(
                "EQL filter string. "
                "Omit or pass '' for catch-all. "
            ),
        ),
    ] = "",
    lookback_days: Annotated[
        int,
        typer.Option("--lookback", help="Days to search back (default 1)"),
    ] = 1,
    limit: Annotated[
        int | None,
        typer.Option("--limit", help="Max events (default varies by mode: table=100, unique/count/csv=10000, json=100)"),
    ] = None,
    fields: Annotated[
        str | None,
        typer.Option(
            "--fields",
            metavar="FIELD[,FIELD...]",
            help=(
                "Comma-separated CIM fields to return "
                "(default: timestamp,user,host,activity_type,outcome). "
                "Ignored when --unique is set."
            ),
        ),
    ] = None,
    unique: Annotated[
        str | None,
        typer.Option("--unique", metavar="FIELD", help="Show value frequency table for a single field"),
    ] = None,
    count: Annotated[
        bool,
        typer.Option("--count", help="Print matched event count only"),
    ] = False,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Output NDJSON to stdout (compatible with jq)"),
    ] = False,
    csv_path: Annotated[
        str | None,
        typer.Option("--csv", metavar="PATH", help="Write results to CSV file"),
    ] = None,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Search Exabeam events using EQL.

    \b
    Examples:
      exa search 'activity_type:"authentication"' --lookback 7
      exa search 'parsed:"No"' --fields parsed,m_collector_name,error_detail
      exa search 'activity_type:"authentication"' --unique user --lookback 30
      exa search 'outcome:"fail"' --count --lookback 7
      exa search 'user:"jsmith"' --json | jq .
      exa search 'activity_type:"authentication"' --csv auth.csv --lookback 30
    """
    import csv as _csv
    import json as _json
    import sys
    from collections import Counter
    from datetime import UTC, datetime, timedelta

    from rich import box
    from rich.table import Table

    from exa.search import search_events

    # ── Mutex conflict detection (before any API call) ─────────────────────
    if as_json and csv_path:
        console.print("x Cannot combine --json and --csv", style="red")
        raise typer.Exit(1)
    if unique and count:
        console.print("x Cannot combine --unique and --count", style="red")
        raise typer.Exit(1)
    if csv_path and count:
        console.print("x --count produces no rows; use without --csv", style="red")
        raise typer.Exit(1)
    if unique and fields:
        console.print("  --fields ignored when --unique is set", style="yellow")

    # ── Mode-dependent auto-limit ──────────────────────────────────────────
    user_set_limit = limit is not None
    if unique or count or csv_path:
        resolved_limit = limit if user_set_limit else 10_000
    elif as_json:
        resolved_limit = limit if user_set_limit else 100
    else:
        resolved_limit = limit if user_set_limit else 100  # table mode

    # ── Determine fields to fetch and display ──────────────────────────────
    if unique:
        fetch_fields: list[str] = [unique]
        display_fields: list[str] = [unique]
    elif fields:
        requested = [f.strip() for f in fields.split(",") if f.strip()]
        # "timestamp" is derived from approxLogTime — don't send to API
        fetch_fields = [f for f in requested if f != "timestamp"]
        display_fields = requested
    else:
        fetch_fields = _SEARCH_DEFAULT_API_FIELDS.copy()
        display_fields = _SEARCH_DEFAULT_DISPLAY_FIELDS.copy()

    # ── API call ───────────────────────────────────────────────────────────
    client = _make_client(tenant)
    try:
        events = search_events(
            client,
            filter_str,  # "" verified working on sademodev22 2026-05-08
            fields=fetch_fields if fetch_fields else None,
            lookback_days=lookback_days,
            limit=resolved_limit,
        )
    finally:
        client.close()

    n = len(events)
    hit_limit = (not user_set_limit) and n >= resolved_limit

    # ── --count mode ───────────────────────────────────────────────────────
    if count:
        if as_json:
            sys.stdout.write(_json.dumps({"count": n}) + "\n")
        else:
            suffix = "+" if hit_limit else ""
            console.print(f"  {n:,}{suffix} events matched")
        return

    # ── --unique mode ──────────────────────────────────────────────────────
    if unique:
        counter: Counter[str] = Counter()
        null_count = 0
        for row in events:
            v = row.get(unique)
            if v is None or v == "":
                null_count += 1
            else:
                counter[str(v)] += 1

        sorted_items = counter.most_common()
        total_distinct = len(sorted_items) + (1 if null_count else 0)

        if as_json:
            for value, cnt in sorted_items:
                sys.stdout.write(_json.dumps({"value": value, "count": cnt}) + "\n")
            if null_count:
                sys.stdout.write(_json.dumps({"value": None, "count": null_count}) + "\n")
        else:
            tbl = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold")
            tbl.add_column("value", overflow="fold")
            tbl.add_column("count", justify="right")
            for value, cnt in sorted_items:
                tbl.add_row(str(value), f"{cnt:,}")
            if null_count:
                tbl.add_row("[dim](null)[/dim]", f"{null_count:,}")
            console.print(tbl)

            scanned_note = ""
            if hit_limit:
                scanned_note = " (fetch limit - results may be partial)"
            elif user_set_limit:
                scanned_note = " (user-set limit)"
            console.print(
                f"  {total_distinct} distinct values | {n:,} events scanned{scanned_note}",
                style="dim",
            )
        return

    # ── --json mode ────────────────────────────────────────────────────────
    if as_json:
        for row in events:
            row.pop("approxLogTime", None)
            sys.stdout.write(_json.dumps(row) + "\n")
        return

    # ── --csv mode ─────────────────────────────────────────────────────────
    if csv_path:
        # Build column list; "timestamp" is always first if present in display
        csv_cols = list(display_fields)
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = _csv.DictWriter(fh, fieldnames=csv_cols, extrasaction="ignore")
            writer.writeheader()
            for row in events:
                row.pop("approxLogTime", None)
                writer.writerow({col: row.get(col, "") for col in csv_cols})
        console.print(f"  {n:,} events written to {csv_path}", style="dim")
        return

    # ── Default table mode ─────────────────────────────────────────────────
    # Sort by timestamp ascending (approxLogTime is added by search_events)
    events.sort(key=lambda r: r.get("approxLogTime", 0))

    # Suppress entirely-null/empty columns
    cols_to_show = []
    for col in display_fields:
        api_col = "timestamp" if col == "timestamp" else col
        if any(row.get(api_col) not in (None, "") for row in events):
            cols_to_show.append(col)

    tbl = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold")
    for col in cols_to_show:
        tbl.add_column(col, overflow="fold")

    for row in events:
        cells = []
        for col in cols_to_show:
            api_col = "timestamp" if col == "timestamp" else col
            raw = row.get(api_col)
            val = "" if raw is None else str(raw)
            if len(val) > 80:
                val = val[:79] + "~"
            cells.append(_style_cell(col, val))
        tbl.add_row(*cells)

    console.print(tbl)

    now_dt = datetime.now(UTC)
    start_dt = now_dt - timedelta(days=lookback_days)
    console.print(
        f"  {n:,} events | lookback: {lookback_days}d | "
        f"scanned {start_dt.strftime('%Y-%m-%d')} to {now_dt.strftime('%Y-%m-%d')}",
        style="dim",
    )


# -- Frameworks ---------------------------------------------------------------

@app.command()
def frameworks() -> None:
    """List all built-in compliance frameworks and their SIEM coverage.

    Shows each framework ID, full name, and the number of SIEM-testable
    controls (those with evidence queries in ControlQueries JSON). Use
    framework IDs with 'exa compliance audit --framework <ID>' and
    'exa compliance sync-ootb --framework <ID>'.

    \b
    Examples:
      uv run exa frameworks
    """
    from exa.compliance.frameworks import (
        AVAILABLE_FRAMEWORKS,
        load_control_queries,
        load_framework,
    )

    for fw_id in AVAILABLE_FRAMEWORKS:
        try:
            fw = load_framework(fw_id)
            queries = load_control_queries(fw_id)
            testable = len(fw.testable_controls(set(queries.keys())))
            console.print(
                f"  {fw_id:<20} {fw.name:<35} "
                f"({testable} testable controls)",
            )
        except Exception:
            console.print(
                f"  {fw_id:<20} (load error)", style="red",
            )


# -- Compliance ---------------------------------------------------------------

from exa.cli.compliance import compliance_app  # noqa: E402

app.add_typer(compliance_app)


# -- MCP ---------------------------------------------------------------------

from exa.cli.mcp import mcp_app  # noqa: E402

app.add_typer(mcp_app)


# -- Selftest ----------------------------------------------------------------

from exa.cli.selftest import selftest_app  # noqa: E402

app.add_typer(selftest_app)


# -- HotKey -------------------------------------------------------------------

from exa.cli.hotkey import hotkey_app  # noqa: E402

app.add_typer(hotkey_app)


# -- Zones --------------------------------------------------------------------

from exa.cli.zones import zones_app  # noqa: E402

app.add_typer(zones_app)


# -- Config -------------------------------------------------------------------

from exa.cli.config import config_app  # noqa: E402

app.add_typer(config_app)


# -- Update -------------------------------------------------------------------

from exa.cli.update import update_app  # noqa: E402

app.add_typer(update_app)


# -- Splunk -------------------------------------------------------------------

from exa.cli.splunk_convert import splunk_app  # noqa: E402

app.add_typer(splunk_app)


# -- Sigma --------------------------------------------------------------------

from exa.cli.sigma import sigma_app  # noqa: E402

app.add_typer(sigma_app)


# -- Simulate -----------------------------------------------------------------

from exa.cli.simulate import simulate_app  # noqa: E402

app.add_typer(simulate_app)

# Short aliases: exa sc → exa sigma convert, exa sd → exa sigma deploy
sc_app = typer.Typer(
    name="sc", hidden=True, invoke_without_command=True,
)
sd_app = typer.Typer(
    name="sd", hidden=True, invoke_without_command=True,
)


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

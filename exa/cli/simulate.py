"""Detection validation CLI — generate and ship synthetic attack telemetry."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

simulate_app = typer.Typer(
    name="simulate",
    help="Validate detection content by generating and sending synthetic events.",
    no_args_is_help=True,
)
console = Console()

_TENANT_HELP = "Tenant nickname or FQDN (default: saved default)"
_TOKEN_ENV = "EXA_WEBHOOK_TOKEN"
_TOKEN_KEYRING_SERVICE = "exa-webhook"


def _check_would_fire(client, behaviors, events) -> dict[str, str]:
    """Evaluate each event against its rule's live EQL, offline.

    Rules are resolved by NAME rather than by the rule IDs recorded in the
    scenario definitions: names are stable across tenants, IDs are not, so
    this keeps the check meaningful when a customer runs it against their
    own deployment.
    """
    from exa.correlation.rules import get_rules
    from exa.simulate.eqlmatch import EQLMatchError, matches_eql

    try:
        deployed = get_rules(client)
    except Exception as e:  # noqa: BLE001 - reported per-row, not fatal
        return {b.key: f"lookup failed: {str(e)[:30]}" for b in behaviors}

    by_name = {
        (r.get("name") or "").strip().casefold(): r
        for r in deployed
        if isinstance(r, dict)
    }

    results: dict[str, str] = {}
    for behavior, event in zip(behaviors, events, strict=False):
        rule = by_name.get((behavior.rule_name or "").strip().casefold())
        if rule is None:
            results[behavior.key] = "rule not deployed"
            continue
        seqs = rule.get("sequencesConfig", {}).get("sequences") or []
        if not seqs:
            results[behavior.key] = "rule has no query"
            continue
        try:
            hit = matches_eql(event, seqs[0].get("query", ""))
        except EQLMatchError as e:
            results[behavior.key] = f"uncheckable: {str(e)[:30]}"
            continue
        results[behavior.key] = "would fire" if hit else "WOULD NOT FIRE"
    return results


def _token_users(tenant: str | None, fmt: str | None) -> list[str]:
    """Keyring usernames to try, most specific first.

    A tenant can have more than one Webhook Cloud Collector — e.g. a raw
    Zscaler collector and a generic JSON collector — each with its OWN token.
    They differ by ingest format, so we look up '<tenant>-<fmt>' before the
    plain '<tenant>', letting both tokens coexist in the credential store.
    """
    users: list[str] = []
    if tenant and fmt:
        users.append(f"{tenant}-{fmt}")
    if tenant:
        users.append(tenant)
    users.append("default")
    return users


def _resolve_token(
    no_prompt: bool = False, *, tenant: str | None = None, fmt: str | None = None
) -> str:
    """Get the webhook collector token from env, the OS credential store, or a prompt.

    Resolution order: the EXA_WEBHOOK_TOKEN env var, then the OS keyring
    (service 'exa-webhook', username '<tenant>-<fmt>', then '<tenant>', then
    'default'), then an interactive masked prompt. Never written to a file or
    config — the credential store is the sanctioned resting place, same as
    ClientSecret. Store per-collector tokens (outside any logged command) with:
        keyring set exa-webhook <tenant>-raw     # a raw/Zscaler collector
        keyring set exa-webhook <tenant>-json    # a JSON collector
        keyring set exa-webhook <tenant>         # a single/default collector
    """
    token = os.environ.get(_TOKEN_ENV, "").strip()
    if token:
        return token

    # OS credential store — the sanctioned resting place for secrets.
    try:
        import keyring

        for user in _token_users(tenant, fmt):
            stored = keyring.get_password(_TOKEN_KEYRING_SERVICE, user)
            if stored:
                return stored.strip()
    except Exception:  # noqa: BLE001 — keyring is optional; fall through to prompt
        pass

    hint_user = f"{tenant}-{fmt}" if (tenant and fmt) else (tenant or "<tenant>")
    if no_prompt:
        console.print(
            f"No token available. Set {_TOKEN_ENV}, store it with "
            f"'keyring set {_TOKEN_KEYRING_SERVICE} {hint_user}', "
            "or omit --no-prompt.",
            style="red",
        )
        raise typer.Exit(1)

    from rich.prompt import Prompt

    console.print(
        "Webhook collector token (created with the Webhook Cloud Collector "
        f"in the tenant UI). Set {_TOKEN_ENV} or store it with "
        f"'keyring set {_TOKEN_KEYRING_SERVICE} {hint_user}' "
        "to skip this prompt.",
        style="dim",
    )
    token = Prompt.ask("Webhook token", password=True)
    if not token:
        console.print("Token cannot be empty.", style="red")
        raise typer.Exit(1)
    return token


def _aba_field_coverage(events: list[dict]) -> dict[str, set[str]]:
    """Map each CIM2 field the ABA parser extracts to the events supplying it.

    Analytics rules are profiled/fact features, not EQL, so they cannot be
    pre-evaluated the way correlation rules can. Field coverage is the
    meaningful pre-flight: a rule whose requiredFields are absent cannot fire.
    """
    # source JSON path -> CIM2 field, per the published ABA parser
    mapping = {
        "type": "operation", "session": "conversation_id", "agent": "ai_agent_name",
        "framework": "agent_name", "model": "model_name", "tool": "ai_tool_name",
        "text": "llm_request", "response": "llm_response",
        "in": "ai_token_in_count", "out": "ai_token_out_count",
        "cost_usd": "cost", "host": "src_host", "user": "user",
    }
    covered: dict[str, set[str]] = {}
    for ev in events:
        for src, cim in mapping.items():
            if ev.get(src) not in (None, "", [], {}):
                covered.setdefault(cim, set()).add(ev.get("type", "?"))
        data = ev.get("data") or {}
        for src, cim in (("action", "operation_type"), ("result", "result"),
                         ("total_tokens", "ai_token_count")):
            if data.get(src) not in (None, "", [], {}):
                covered.setdefault(cim, set()).add(ev.get("type", "?"))
    return covered


@simulate_app.command("aba")
def aba_simulation(
    scenario: Annotated[
        str | None,
        typer.Option("--scenario", "-s", help="ABA scenario key (omit to list)"),
    ] = None,
    event: Annotated[
        str | None,
        typer.Option("--event", "-e", help="Single event key instead of a scenario"),
    ] = None,
    tenant: Annotated[
        str | None, typer.Option("--tenant", "-t", help=_TENANT_HELP)
    ] = None,
    hostname: Annotated[
        str, typer.Option("--hostname", help="Synthetic host [default: atlas-agent-01]")
    ] = "atlas-agent-01",
    user: Annotated[
        str, typer.Option("--user", help="Synthetic user [default: svc-atlas-agent]")
    ] = "svc-atlas-agent",
    marker: Annotated[
        str, typer.Option("--marker", help="Tag in sim_marker [default: EXA-SIMULATION]")
    ] = "EXA-SIMULATION",
    schema: Annotated[
        str,
        typer.Option(
            "--schema",
            help="Wire schema marker. 'observra:1.0' is verified working; "
            "'aba-1.0' targets the published CIM2 parser "
            "[default: observra:1.0]",
        ),
    ] = "observra:1.0",
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run/--no-dry-run",
                     help="Build without sending [default: dry-run]"),
    ] = True,
    out: Annotated[
        Path | None, typer.Option("--out", help="Write generated events to a JSON file")
    ] = None,
    no_prompt: Annotated[
        bool,
        typer.Option("--no-prompt/--prompt", help="Fail instead of prompting for token"),
    ] = False,
) -> None:
    """Generate ABA / Observra AI-agent telemetry that parses without a transform.

    Emits the sensor wire schema directly, so all three parser match conditions
    ("type", "framework", "schema") are satisfied. The observra library's own
    output does NOT satisfy them and lands unparsed.

    Targets OOTB *analytics* rules (profiled/fact features), not correlation
    rules, so pre-flight reports CIM2 field coverage rather than an EQL verdict.

    Examples:
      uv run exa simulate aba
      uv run exa simulate aba --scenario aba-injection
      uv run exa simulate aba --scenario aba-lifecycle --out events.json
      uv run exa simulate aba --scenario aba-injection --no-dry-run --tenant sademodev22
    """
    from exa.simulate.aba import (
        ABA_SCENARIOS,
        UNMAPPED,
        build_aba_events,
        dropped_at_extraction,
        list_aba_events,
    )
    from exa.simulate.webhook import resolve_ingest_url, send_events

    if scenario is None and event is None:
        console.print("[bold]ABA scenarios[/bold]\n")
        for sc in ABA_SCENARIOS.values():
            console.print(f"[bold]{sc.key}[/bold] — {sc.title}")
            console.print(f"  {sc.description}", style="dim")
            t = Table(show_header=True, header_style="bold")
            t.add_column("Event")
            t.add_column("activity_type")
            t.add_column("Targets rule family")
            for e in sc.events:
                t.add_row(e.key, e.activity, e.targets)
            console.print(t)
        console.print(
            "Pick one with --scenario, or --event for a single event.", style="dim")
        return

    try:
        events = build_aba_events(
            scenario, event_key=event, hostname=hostname, user=user,
            marker=marker, schema=schema,
        )
        defs = ([e for e in list_aba_events(scenario) if e.key == event]
                if event else list_aba_events(scenario))
    except ValueError as e:
        console.print(str(e), style="red")
        raise typer.Exit(1) from None

    table = Table(title=f"ABA events ({len(events)})", show_header=True,
                  header_style="bold")
    table.add_column("#", width=3)
    table.add_column("Event")
    table.add_column("type")
    table.add_column("Targets")
    for i, (d, ev) in enumerate(zip(defs, events, strict=False), start=1):
        table.add_row(str(i), d.key, ev.get("type", "-"), d.targets)
    console.print(table)

    cov = _aba_field_coverage(events)
    ct = Table(title="CIM2 field coverage (pre-flight)", show_header=True,
               header_style="bold")
    ct.add_column("CIM2 field")
    ct.add_column("Supplied by event types")
    for f in sorted(cov):
        ct.add_row(f, ", ".join(sorted(cov[f])))
    console.print(ct)

    # Everything below reaches the collector and parses, then is discarded
    # before it becomes a CIM2 field — so no rule can reference it, however
    # the rule is written. This is the evidence for extending the parser.
    dropped = dropped_at_extraction(events)
    if dropped:
        dt = Table(title="Dropped at extraction - no CIM2 destination",
                   show_header=True, header_style="bold red")
        dt.add_column("Emitted field")
        dt.add_column("Present on")
        dt.add_column("Detection family blocked")
        for f in sorted(dropped):
            dt.add_row(f, ", ".join(sorted(dropped[f])), UNMAPPED.get(f, "-"))
        console.print(dt)
        console.print(
            f"[yellow]{len(dropped)} emitted field(s) have no CIM2 destination in the "
            "published ABA parser. They will parse successfully and be discarded.[/yellow]"
        )

    missing = {"llm_request", "result", "ai_tool_name", "ai_token_in_count"} - set(cov)
    if missing:
        console.print(
            f"Not exercised in this batch: {', '.join(sorted(missing))} — "
            "rules requiring those fields cannot fire.", style="yellow")

    if out is not None:
        out.write_text(json.dumps(events, indent=2), encoding="utf-8")
        console.print(f"Wrote {len(events)} events to {out}", style="green")

    from exa.cli.app import _make_client

    client = _make_client(tenant)
    try:
        url = resolve_ingest_url(client)
    except ValueError as e:
        console.print(str(e), style="red")
        raise typer.Exit(1) from None

    if dry_run:
        console.print(f"\nDry run — nothing sent. Target would be:\n  {url}",
                      style="yellow")
        console.print("Re-run with --no-dry-run to send.", style="dim")
        return

    token = _resolve_token(no_prompt=no_prompt, tenant=tenant, fmt="json")
    console.print(f"\nSending {len(events)} events to {url} ...")

    from exa.exceptions import ExaAPIError

    try:
        result = send_events(client, events, token=token)
    except ExaAPIError as e:
        console.print(f"Ingest failed: {e}", style="red")
        raise typer.Exit(1) from None

    console.print(f"Sent {result['sent']} events in {result['batches']} batch(es).",
                  style="green")
    console.print(
        "Analytics rules are profiled features — allow ~40 min for triggers, "
        "then search msg_type:\"exabeam-nganalytics-json-rule-trigger-success-"
        "nganalytics\" AND src_product:\"Observra\".", style="dim")


@simulate_app.command("vendor")
def vendor_simulation(
    pack: Annotated[
        str,
        typer.Option(
            "--pack", "-p",
            help="Vendor pack key, e.g. 'Zscaler/Zscaler Internet Access'",
        ),
    ] = "Zscaler/Zscaler Internet Access",
    tenant: Annotated[
        str | None, typer.Option("--tenant", "-t", help=_TENANT_HELP)
    ] = None,
    marker: Annotated[
        str,
        typer.Option("--marker", help="Tag written to location= [default: EXA-SIMULATION]"),
    ] = "EXA-SIMULATION",
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run/--no-dry-run",
                     help="Build without sending [default: dry-run]"),
    ] = True,
    out: Annotated[
        Path | None, typer.Option("--out", help="Write the raw log lines to a file")
    ] = None,
    no_prompt: Annotated[
        bool,
        typer.Option("--no-prompt/--prompt", help="Fail instead of prompting for token"),
    ] = False,
) -> None:
    """Emit vendor-shaped AI traffic so the AI/LLM context tables have values to find.

    Renders raw log lines from the pack's wire_template and refuses to send anything
    that would fail the parser's match conditions -- that failure is invisible after
    the fact (parsed:false, no fields, HTTP 200).

    One Zscaler event feeds six tables: Web Domains, Public AI Domains and Risk, Web
    Categories, Proxy Categories, Applications and DLP Rulesets.

    Examples:
      uv run exa simulate vendor --tenant sademodev22
      uv run exa simulate vendor --tenant sademodev22 --no-dry-run
    """
    from exa.simulate.vendor import (
        ConditionsNotMetError,
        NoTemplateError,
        ai_seed_rows,
        get_pack,
        render_many,
    )
    from exa.simulate.webhook import resolve_ingest_url, send_events

    try:
        vpack = get_pack(pack)
        events = render_many(pack, ai_seed_rows(marker=marker))
    except (ValueError, NoTemplateError) as e:
        console.print(str(e), style="red")
        raise typer.Exit(1) from None
    except ConditionsNotMetError as e:
        console.print(f"[red]Refusing to send:[/red] {e}")
        raise typer.Exit(1) from None

    console.print(f"[bold]{pack}[/bold]  parser: {vpack.parser}")
    console.print(f"  conditions: {' | '.join(vpack.parser_conditions)}", style="dim")

    table = Table(title=f"Vendor events ({len(events)})", show_header=True,
                  header_style="bold")
    table.add_column("#", width=3)
    table.add_column("web_domain")
    table.add_column("app")
    table.add_column("category")
    for i, ev in enumerate(events, start=1):
        x = ev.expects
        table.add_row(str(i), x.get("web_domain", "-"), x.get("app", "-"),
                      x.get("category", "-"))
    console.print(table)

    if out is not None:
        out.write_text("\n".join(e.raw for e in events), encoding="utf-8")
        console.print(f"Wrote {len(events)} log lines to {out}", style="green")

    from exa.cli.app import _make_client

    client = _make_client(tenant)
    try:
        url = resolve_ingest_url(client, fmt="raw")
    except ValueError as e:
        console.print(str(e), style="red")
        raise typer.Exit(1) from None

    if dry_run:
        console.print(f"\nDry run -- nothing sent. Target would be:\n  {url}",
                      style="yellow")
        console.print("Re-run with --no-dry-run to send.", style="dim")
        return

    token = _resolve_token(no_prompt=no_prompt, tenant=tenant, fmt="raw")
    console.print(f"\nSending {len(events)} log lines to {url} ...")

    from exa.exceptions import ExaAPIError

    try:
        result = send_events(client, [e.raw for e in events], token=token, fmt="raw")
    except ExaAPIError as e:
        console.print(f"Ingest failed: {e}", style="red")
        raise typer.Exit(1) from None

    console.print(f"Sent {result['sent']} line(s) in {result['batches']} batch(es).",
                  style="green")
    console.print(
        "HTTP 200 only means ingest accepted them. Confirm they PARSED before "
        "concluding anything:\n"
        f"  exa search 'web_domain:\"claude.ai\"' --fields web_domain,category,app "
        f"--tenant {tenant or '<tenant>'}\n"
        "Request the fields explicitly -- an unrequested field is indistinguishable "
        "from an empty one.", style="dim")


@simulate_app.command("list")
def list_scenarios() -> None:
    """List available scenarios and the rules each behavior exercises.

    Examples:
      uv run exa simulate list
    """
    from exa.simulate.scenarios import SCENARIOS

    for scenario in SCENARIOS.values():
        console.print(f"\n[bold]{scenario.key}[/bold] — {scenario.title}")
        console.print(f"  {scenario.description}", style="dim")

        table = Table(show_header=True, header_style="bold")
        table.add_column("Behavior")
        table.add_column("ATT&CK")
        table.add_column("Stage")
        table.add_column("Expected rule")
        for b in scenario.behaviors:
            table.add_row(b.key, b.attack, b.stage, b.rule_name or "-")
        console.print(table)
        notes = [b for b in scenario.behaviors if b.notes]
        for b in notes:
            console.print(f"  note ({b.key}): {b.notes}", style="yellow")


@simulate_app.command("run")
def run_simulation(
    scenario: Annotated[
        str | None,
        typer.Option("--scenario", "-s", help="Scenario key (see 'simulate list')"),
    ] = None,
    behavior: Annotated[
        str | None,
        typer.Option("--behavior", "-b", help="Single behavior key instead of a chain"),
    ] = None,
    tenant: Annotated[
        str | None, typer.Option("--tenant", "-t", help=_TENANT_HELP)
    ] = None,
    hostname: Annotated[
        str, typer.Option("--hostname", help="Synthetic hostname [default: SIM-CLINICAL-01]")
    ] = "SIM-CLINICAL-01",
    user: Annotated[
        str,
        typer.Option("--user", help="Synthetic user [default: HOSPITAL\\svc_imaging]"),
    ] = "HOSPITAL\\svc_imaging",
    marker: Annotated[
        str,
        typer.Option(
            "--marker",
            help="Tag written into RuleName so simulated events stay "
            "identifiable [default: EXA-SIMULATION]",
        ),
    ] = "EXA-SIMULATION",
    fmt: Annotated[
        str, typer.Option("--format", help="Ingest format: json or raw [default: json]")
    ] = "json",
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run/--no-dry-run",
            help="Build and show events without sending [default: dry-run]",
        ),
    ] = True,
    out: Annotated[
        Path | None,
        typer.Option("--out", help="Also write the generated events to a JSON file"),
    ] = None,
    no_prompt: Annotated[
        bool,
        typer.Option(
            "--no-prompt/--prompt",
            help="Fail instead of prompting for the token [default: prompt]",
        ),
    ] = False,
    check: Annotated[
        bool,
        typer.Option(
            "--check/--no-check",
            help="Evaluate each event against the deployed rule's EQL offline "
            "[default: check]",
        ),
    ] = True,
) -> None:
    """Generate synthetic events and optionally send them to a tenant.

    Defaults to --dry-run so nothing reaches a tenant by accident; pass
    --no-dry-run to actually ship the events.

    Examples:
      uv run exa simulate run --scenario healthcare
      uv run exa simulate run --scenario healthcare --out events.json
      uv run exa simulate run --scenario healthcare --no-dry-run --tenant sademodev22
      uv run exa simulate run --behavior bcdedit-recovery-off --no-dry-run
    """
    from exa.simulate.scenarios import build_events, list_behaviors
    from exa.simulate.webhook import resolve_ingest_url, send_events

    if scenario is None and behavior is None:
        console.print(
            "Specify --scenario or --behavior (see 'exa simulate list').",
            style="red",
        )
        raise typer.Exit(1)

    try:
        events = build_events(
            scenario,
            behavior_key=behavior,
            hostname=hostname,
            user=user,
            marker=marker,
        )
        behaviors = (
            [b for b in list_behaviors(scenario) if b.key == behavior]
            if behavior
            else list_behaviors(scenario)
        )
    except ValueError as e:
        console.print(str(e), style="red")
        raise typer.Exit(1) from None

    if out is not None:
        out.write_text(json.dumps(events, indent=2), encoding="utf-8")
        console.print(f"Wrote {len(events)} events to {out}", style="green")

    from exa.cli.app import _make_client

    client = _make_client(tenant)

    verdicts = _check_would_fire(client, behaviors, events) if check else {}

    table = Table(title=f"Synthetic events ({len(events)})", show_header=True,
                  header_style="bold")
    table.add_column("#", width=3)
    table.add_column("Behavior")
    table.add_column("Process")
    table.add_column("Expected rule to fire")
    if check:
        table.add_column("Pre-flight")
    for i, (b, ev) in enumerate(zip(behaviors, events, strict=False), start=1):
        row = [str(i), b.key, ev["OriginalFileName"], b.rule_name or "-"]
        if check:
            verdict = verdicts.get(b.key, "-")
            style = "green" if verdict == "would fire" else "yellow"
            if verdict == "WOULD NOT FIRE":
                style = "red"
            row.append(f"[{style}]{verdict}[/{style}]")
        table.add_row(*row)
    console.print(table)

    if check and any(v == "WOULD NOT FIRE" for v in verdicts.values()):
        console.print(
            "Some events do not satisfy their rule's EQL — sending them would "
            "prove nothing. Investigate before shipping.",
            style="red",
        )

    try:
        url = resolve_ingest_url(client, fmt=fmt)
    except ValueError as e:
        console.print(str(e), style="red")
        raise typer.Exit(1) from None

    if dry_run:
        console.print(f"\nDry run — nothing sent. Target would be:\n  {url}", style="yellow")
        console.print("Re-run with --no-dry-run to send.", style="dim")
        return

    token = _resolve_token(no_prompt=no_prompt, tenant=tenant, fmt=fmt)
    console.print(f"\nSending {len(events)} events to {url} ...")

    from exa.exceptions import ExaAPIError

    try:
        result = send_events(client, events, token=token, fmt=fmt)
    except ExaAPIError as e:
        console.print(f"Ingest failed: {e}", style="red")
        if e.status_code == 401:
            console.print(
                "401 usually means the token is not a Webhook Cloud Collector "
                "token. The tenant OAuth token will not work here.",
                style="yellow",
            )
        raise typer.Exit(1) from None

    console.print(
        f"Sent {result['sent']} events in {result['batches']} batch(es).",
        style="green",
    )

    # Record a run manifest so `exa simulate timing` can measure end-to-end
    # detection latency (MTTD) against this exact send and its true send time.
    if scenario:
        from exa.config import get_default_tenant
        from exa.simulate.ledger import new_run, write_run

        run = new_run(
            tenant=tenant or get_default_tenant(),
            kind="scenario",
            marker=marker,
            scenario=scenario,
            host=hostname,
            user=user,
            event_count=int(result.get("sent", len(events))),
        )
        write_run(run)
        console.print(
            f"  Recorded run {run.run_id} for detection timing. Measure MTTD with:\n"
            f"    exa simulate timing --attach {run.run_id} "
            f"--tenant {tenant or '<tenant>'}",
            style="dim",
        )

    console.print(
        "Ingestion is asynchronous — allow a few minutes, then run "
        "'exa simulate verify'.",
        style="dim",
    )


@simulate_app.command("verify")
def verify_simulation(
    scenario: Annotated[
        str | None, typer.Option("--scenario", "-s", help="Scenario key to verify")
    ] = None,
    tenant: Annotated[
        str | None, typer.Option("--tenant", "-t", help=_TENANT_HELP)
    ] = None,
    marker: Annotated[
        str, typer.Option("--marker", help="Marker used at send time [default: EXA-SIMULATION]")
    ] = "EXA-SIMULATION",
    lookback: Annotated[
        int, typer.Option("--lookback", help="Hours to search back [default: 4]")
    ] = 4,
) -> None:
    """Check whether simulated events landed and were parsed correctly.

    Confirms the events arrived AND that process_name was populated — the
    field the converted Sigma rules match on. Events that land unparsed will
    show up here as ingested but unmatched.

    Examples:
      uv run exa simulate verify --scenario healthcare
      uv run exa simulate verify --scenario healthcare --tenant sademodev22
    """
    from exa.simulate.scenarios import list_behaviors

    try:
        behaviors = list_behaviors(scenario)
    except ValueError as e:
        console.print(str(e), style="red")
        raise typer.Exit(1) from None

    from exa.cli.app import _make_client
    from exa.search.events import search_events

    client = _make_client(tenant)

    table = Table(title=f"Simulation verification (last {lookback}h)",
                  show_header=True, header_style="bold")
    table.add_column("Behavior")
    table.add_column("Process")
    table.add_column("Events")
    table.add_column("process_name")
    table.add_column("Status")

    any_found = False
    for b in behaviors:
        exe = b.image.rsplit("\\", 1)[-1]
        eql = f'process_name:"{exe}"'
        try:
            rows = search_events(client, eql, lookback_hours=lookback, limit=50)
            rows = rows if isinstance(rows, list) else rows.get("rows", [])
        except Exception as e:
            table.add_row(b.key, exe, "-", "-", f"error: {str(e)[:40]}")
            continue

        named = sum(1 for r in rows if r.get("process_name"))
        if rows and named:
            status, style = "parsed OK", "green"
            any_found = True
        elif rows:
            status, style = "ingested, process_name empty", "yellow"
            any_found = True
        else:
            status, style = "not found", "red"
        table.add_row(b.key, exe, str(len(rows)), str(named),
                      f"[{style}]{status}[/{style}]")

    console.print(table)
    if not any_found:
        console.print(
            "\nNo simulated events found. Ingestion can take a few minutes; "
            "if it stays empty, confirm the Webhook Cloud Collector is running "
            "and that events matched a Sysmon parser.",
            style="yellow",
        )
    console.print(f"Marker used for these events: {marker}", style="dim")


@simulate_app.command("timing")
def timing_simulation(
    attach: Annotated[
        str | None,
        typer.Option(
            "--attach",
            help="Measure an existing recorded run: a run id, or 'latest'",
        ),
    ] = None,
    scenario: Annotated[
        str | None,
        typer.Option(
            "--scenario",
            "-s",
            help="Scenario to measure (records a run stamped now if not --attach)",
        ),
    ] = None,
    tenant: Annotated[
        str | None, typer.Option("--tenant", "-t", help=_TENANT_HELP)
    ] = None,
    deadline: Annotated[
        int,
        typer.Option("--deadline", help="Max seconds to wait for detections [default: 900]"),
    ] = 900,
    interval: Annotated[
        int,
        typer.Option("--interval", help="Seconds between polls [default: 30]"),
    ] = 30,
    lookback: Annotated[
        int,
        typer.Option("--lookback", help="Days of alerts/cases to scan [default: 1]"),
    ] = 1,
    once: Annotated[
        bool,
        typer.Option(
            "--once/--poll",
            help="Single snapshot instead of polling to the deadline [default: poll]",
        ),
    ] = False,
    out: Annotated[
        Path | None,
        typer.Option("--out", "-o", help="Report path base [default: reports/timing/...]"),
    ] = None,
    pdf: Annotated[
        bool,
        typer.Option("--pdf/--no-pdf", help="Also render a PDF [default: no-pdf]"),
    ] = False,
) -> None:
    """Measure end-to-end detection time (MTTD) for a simulate run.

    Reads a recorded run (what was sent + which rules it should fire) and polls
    Threat Center alerts and cases until every expected rule is detected or the
    deadline passes, reporting the inject->alert and inject->case latency per
    rule. READ-ONLY against the tenant.

    Record a run first by sending a scenario:
      exa simulate run --scenario healthcare --no-dry-run --tenant sademodev22

    Examples:
      uv run exa simulate timing --attach latest --tenant sademodev22
      uv run exa simulate timing --scenario healthcare --once --tenant sademodev22
      uv run exa simulate timing --attach latest --deadline 1200 --pdf
    """
    from exa.cli.app import _make_client
    from exa.config import get_default_tenant
    from exa.simulate.ledger import (
        latest_run,
        list_runs,
        load_run,
        new_run,
    )
    from exa.simulate.timing import poll_detections, render_timing_html

    name = tenant or get_default_tenant()

    if attach:
        if attach == "latest":
            path = latest_run(name)
        else:
            path = next((p for p in list_runs(name) if p.stem == attach), None)
        if path is None:
            console.print(
                f"No recorded run '{attach}' for {name}. Send one first with "
                "'exa simulate run --scenario <s> --no-dry-run'.",
                style="red",
            )
            raise typer.Exit(1)
        run = load_run(path)
    elif scenario:
        run = new_run(tenant=name, kind="scenario", marker="EXA-SIMULATION",
                      scenario=scenario)
        console.print(
            f"  No --attach: measuring '{scenario}' from now. For accurate MTTD, "
            "record the run at send time via 'exa simulate run'.",
            style="yellow",
        )
    else:
        console.print("Specify --attach <run-id|latest> or --scenario.", style="red")
        raise typer.Exit(1)

    if not run.expected_rules:
        console.print(
            f"Run '{run.run_id}' has no rule-firing behaviors to time "
            "(it only feeds context tables).",
            style="yellow",
        )
        raise typer.Exit(0)

    console.rule(f"Detection timing -- {run.scenario or run.kind} ({name})")
    console.print(
        f"  Expecting {len(run.expected_rules)} rule(s); "
        f"{'single check' if once else f'polling every {interval}s up to {deadline}s'}.",
        style="dim",
    )

    def _on_poll(rep) -> None:
        console.print(
            f"  {rep.detected_count}/{rep.total_expected} detected "
            f"(mean MTTD alert {rep.mean_mttd_alert or '--'}s)",
            style="dim",
        )

    client = _make_client(tenant)
    try:
        report = poll_detections(
            client,
            run,
            deadline_seconds=0 if once else deadline,
            interval_seconds=interval,
            lookback_days=lookback,
            on_poll=_on_poll,
        )
    finally:
        client.close()

    tbl = Table(show_header=True, header_style="bold")
    tbl.add_column("Behavior", style="cyan")
    tbl.add_column("Expected rule")
    tbl.add_column("Detected")
    tbl.add_column("MTTD alert", justify="right")
    tbl.add_column("MTTD case", justify="right")
    for o in report.outcomes:
        det = "[green]yes[/]" if o.detected else "[red]no[/]"
        a = f"{o.mttd_alert_seconds:.0f}s" if o.mttd_alert_seconds is not None else "-"
        c = f"{o.mttd_case_seconds:.0f}s" if o.mttd_case_seconds is not None else "-"
        tbl.add_row(o.behavior, o.rule_name.replace("[Sigma] ", ""), det, a, c)
    console.print(tbl)
    console.print(
        f"\n  {report.detected_count}/{report.total_expected} rules detected"
        + (f", mean MTTD {report.mean_mttd_alert}s (alert)" if report.mean_mttd_alert else "")
    )

    date_str = time.strftime("%Y-%m-%d")
    base = out or Path("reports") / "timing" / f"{name}-{run.run_id}-{date_str}"
    base = Path(base)
    base.parent.mkdir(parents=True, exist_ok=True)
    json_path = base.with_suffix(".json")
    html_path = base.with_suffix(".html")
    json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    html_path.write_text(render_timing_html(report), encoding="utf-8")
    console.print(f"  Report: {json_path}", style="green")
    console.print(f"          {html_path}", style="green")
    if pdf:
        from exa.report.pdf import PdfUnavailableError, html_str_to_pdf

        try:
            pdf_path = html_str_to_pdf(render_timing_html(report), base.with_suffix(".pdf"))
            console.print(f"          {pdf_path}", style="green")
        except PdfUnavailableError as exc:
            console.print(f"  [yellow]PDF skipped:[/] {exc}")

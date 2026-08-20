"""`exa selftest` — live preflight for the MCP tool surface.

Exercises every read MCP tool against a real tenant exactly as Claude Desktop would
(through ``dispatch_tool``), measuring wall-clock per tool and classifying each against
a Desktop-latency budget:

    ok       completed under the slow threshold
    slow     completed, but slow enough to look "stuck" in Desktop (demo risk)
    timeout  exceeded the hard ceiling — Desktop would hang / fail the call
    error    returned an error result or raised

It writes a findings JSON (errors, timeouts, durations, result sizes) so a bad tool is
caught BEFORE a demo or before a new user hits it — not live in front of a customer.

Intended to run:
  * ad-hoc before a demo:      exa selftest --tenant sademodev22
  * as a Claude Scheduled Task / cron, writing dated findings JSON
  * for every new skill/MCP tool added (part of the tool-creation process)

Read-only and safe: the four write tools are never invoked. Renders are exercised with
``render=True`` so the report path is validated too.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console

selftest_app = typer.Typer(name="selftest", no_args_is_help=False)
console = Console()
err_console = Console(stderr=True)

# Minimal, representative arguments per read tool. Renders are on so the report-write
# path is covered. Kept in one place so adding a tool here is the "for every new tool"
# checklist step.
_TOOL_ARGS: dict[str, dict[str, Any]] = {
    "get_active_tenant": {},
    "list_tenants": {},
    "get_license_consumption": {},
    "get_app_status": {},
    "list_collectors": {},
    "parser_health": {"lookback_days": 7},
    "identity_health": {"lookback_days": 7},
    "context_table": {},
    "aillm_sources": {"lookback_days": 7},
    "aillm_validate": {"lookback_days": 30},
    "aillm_rules": {"lookback_days": 30},
    "aillm_risk": {"lookback_days": 30},
    "aillm_gaps": {"lookback_days": 30},
    "ai_domain_lookup": {"domains": ["chat.openai.com", "claude.ai"]},
    "list_detection_rules": {"limit": 25},
    "soc_kpis": {"lookback_days": 30, "render": True},
    "tuning_report": {"lookback_days": 30, "top_n": 20, "render": True},
    "ingest_value": {"lookback_days": 7, "top_n": 15, "render": True},
    "source_detail": {"vendor": "*", "lookback_days": 7},
}


async def _run_one(client: Any, name: str, args: dict, *, hard_s: float, slow_s: float) -> dict:
    from exa.mcp.tools import dispatch_tool

    t0 = time.monotonic()
    status, note, size = "ok", "", 0
    try:
        out = await asyncio.wait_for(
            dispatch_tool(client, name, args, read_only=True), timeout=hard_s
        )
        text = out[0].text if out and getattr(out[0], "text", None) else ""
        size = len(text.encode("utf-8"))
        if text.startswith('{"error"') or '"error":' in text[:60]:
            status, note = "error", text[:200]
        elif (time.monotonic() - t0) > slow_s:
            status = "slow"
    except asyncio.TimeoutError:
        status, note = "timeout", f">{hard_s:.0f}s — Claude Desktop would hang or fail this call"
    except Exception as e:  # noqa: BLE001 — a selftest must survive any tool blowing up
        status, note = "error", f"{type(e).__name__}: {e}"[:200]
    return {
        "tool": name,
        "args": args,
        "seconds": round(time.monotonic() - t0, 1),
        "result_bytes": size,
        "status": status,
        "note": note,
    }


@selftest_app.callback(invoke_without_command=True)
def selftest(
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help="Tenant nickname to test [default: saved default]"),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write findings JSON here [default: reports/selftest/<tenant>-<date>.json]"),
    ] = None,
    slow_s: Annotated[
        float,
        typer.Option("--slow-seconds", help="Duration above which a tool is flagged 'slow' (demo risk)"),
    ] = 25.0,
    hard_s: Annotated[
        float,
        typer.Option("--timeout-seconds", help="Hard ceiling; above this a tool is 'timeout' (Desktop would hang)"),
    ] = 55.0,
    only: Annotated[
        str | None,
        typer.Option("--only", help="Comma-separated subset of tool names to run (default: all read tools)"),
    ] = None,
) -> None:
    """Run the live MCP preflight and write a findings JSON.

    \b
    Examples:
      exa selftest --tenant sademodev22
      exa selftest -t sademodev22 --only aillm_validate,aillm_gaps
      exa selftest -t sademodev22 -o preflight.json
    """
    from exa.client import ExaClient

    client = ExaClient(tenant=tenant) if tenant else ExaClient()
    tname = getattr(client, "tenant", None) or "default"

    names = [n.strip() for n in only.split(",")] if only else list(_TOOL_ARGS)
    unknown = [n for n in names if n not in _TOOL_ARGS]
    if unknown:
        raise typer.BadParameter(f"unknown tool(s): {', '.join(unknown)}")

    err_console.print(
        f"  selftest: {len(names)} tools vs '{tname}' "
        f"(slow>{slow_s:.0f}s, timeout>{hard_s:.0f}s)\n",
        style="dim",
    )

    async def _run_all() -> list[dict]:
        results = []
        for name in names:
            r = await _run_one(client, name, _TOOL_ARGS[name], hard_s=hard_s, slow_s=slow_s)
            tone = {"ok": "green", "slow": "yellow", "timeout": "red", "error": "red"}[r["status"]]
            console.print(
                f"  {name:22} {r['seconds']:6.1f}s  [{tone}]{r['status'].upper():8}[/{tone}] "
                f"{r['note'][:80]}"
            )
            results.append(r)
        return results

    results = asyncio.run(_run_all())

    counts = {s: sum(1 for r in results if r["status"] == s) for s in ("ok", "slow", "timeout", "error")}
    verdict = "PASS" if counts["timeout"] == 0 and counts["error"] == 0 else "FAIL"
    findings = {
        "tenant": tname,
        "date": time.strftime("%Y-%m-%d"),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "slow_threshold_s": slow_s,
        "hard_timeout_s": hard_s,
        "verdict": verdict,
        "counts": counts,
        "results": results,
    }

    if output is None:
        base = Path("reports") / "selftest"
        base.mkdir(parents=True, exist_ok=True)
        output = base / f"{tname}-{findings['date']}.json"
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    tone = "green" if verdict == "PASS" else "red"
    console.print(
        f"\n  [{tone}]{verdict}[/{tone}] - ok:{counts['ok']} slow:{counts['slow']} "
        f"timeout:{counts['timeout']} error:{counts['error']}"
    )
    console.print(f"  findings -> {output}", style="dim")
    if verdict == "FAIL":
        raise typer.Exit(code=1)

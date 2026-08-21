"""Assess a tenant and populate the OOTB context tables so its dashboards work.

`exa assess` is the repeatable engine: discover what the tenant sends, derive
which context table+field each OOTB dashboard/rule requires (live, not a frozen
list), measure the gap, and -- gated -- write the missing values so the exact
`field IN table` panel filters start matching. Same input -> same output.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

assess_app = typer.Typer(
    name="assess",
    help="Assess a tenant and populate OOTB context tables so dashboards work.",
    no_args_is_help=False,
)
console = Console()
_TENANT_HELP = "Tenant nickname or FQDN (default: saved default)"
_ASSESS_DIR = Path.home() / ".exa" / "assessments"


_GOLDEN_DEFAULT = Path("tests") / "data" / "classifier_golden.jsonl"


@assess_app.command("benchmark")
def benchmark_cmd(
    golden: Annotated[
        Path,
        typer.Option("--golden", help="Labelled golden corpus (.jsonl)"),
    ] = _GOLDEN_DEFAULT,
    model: Annotated[
        str,
        typer.Option("--model", help="heuristic | claude | chatgpt | gemini [default: heuristic]"),
    ] = "heuristic",
    out: Annotated[
        Path | None,
        typer.Option("--out", "-o", help="Scorecard base path [default: reports/assess/scorecard]"),
    ] = None,
) -> None:
    """Score the classifier on known data + prove the learn loop. No tenant needed.

    \b
    Examples:
      uv run exa assess benchmark
      uv run exa assess benchmark --golden tests/data/classifier_golden.jsonl
    """
    from exa.aillm.benchmark import (
        load_golden,
        render_scorecard_html,
        score_golden,
        simulate_learn_loop,
    )

    if not golden.exists():
        console.print(f"[red]Golden corpus not found: {golden}[/]")
        raise typer.Exit(1)
    if model != "heuristic":
        console.print(
            f"[yellow]LLM backend '{model}' not yet wired (exa/aillm/llm.py pending) "
            "-- scoring the deterministic heuristic.[/]"
        )
        model = f"heuristic (requested {model})"

    entries = load_golden(golden)
    result = score_golden(entries, model=model)

    console.rule("Classifier scorecard")
    console.print(f"  corpus: {result.n} labelled values")
    console.print(f"  per-verdict: {result.per_verdict}")
    _fmt = lambda v: "n/a" if v is None else f"{v:.3f}"  # noqa: E731
    console.print(
        f"  [bold]auto-promote precision[/] (leak metric, target 1.000): "
        f"{_fmt(result.auto_promote_precision)}"
    )
    console.print(
        f"  [bold]PII-withhold recall[/] (safety, target 1.000): "
        f"{_fmt(result.pii_withhold_recall)}"
    )
    console.print(f"  AI recall (don't withhold real AI): {_fmt(result.ai_recall)}")
    if result.leaks:
        console.print(f"  [red]LEAKS ({len(result.leaks)}):[/] {result.leaks}")
    else:
        console.print("  [green]zero leaks in the auto-promote tier[/]")

    # Learn-loop proof (A->E) from a small controlled set of generic values.
    def _p(v, reason="ai-category"):
        return {"value": v, "field": "category", "table": "t", "reason": reason,
                "redacted": False, "live_values": 1}
    pii = _p('{"pii":"leak@hospital.org"}', "ai-classified")
    customers = [
        [_p("catA"), _p("appA", "ai-classified"), _p("domA", "ai-classified"), pii],
        [_p("catB"), _p("appB", "ai-classified"), _p("catA"), pii],
        [_p("catC"), _p("catA"), _p("catB"), pii],
        [_p("catA"), _p("catB"), _p("catC"), pii],
        [_p("e1"), _p("e2"), _p("e3"), _p("e4"), _p("catA"), pii],
    ]
    loop = simulate_learn_loop(customers)
    console.print(
        f"\n  Learn loop A->E: new/customer {loop.curve} · coverage {loop.coverage_growth} · "
        f"{'[green]zero leaked[/]' if not loop.leaked else f'[red]{len(loop.leaked)} leaked[/]'}"
    )

    base = Path(out) if out else Path("reports") / "assess" / "scorecard"
    base.parent.mkdir(parents=True, exist_ok=True)
    payload = {"results": [result.to_dict()], "learn_loop": loop.__dict__}
    base.with_suffix(".json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    base.with_suffix(".html").write_text(
        render_scorecard_html([result], loop), encoding="utf-8"
    )
    verdict = "PASS" if (result.pii_withhold_recall in (1.0, None)
                         and not result.leaks and not loop.leaked) else "FAIL"
    console.print(f"\n  Verdict: [bold]{verdict}[/]  scorecard -> {base.with_suffix('.html')}")
    if verdict != "PASS":
        raise typer.Exit(1)


def _load_dashboard_configs(path: Path | None) -> list[dict]:
    if path is None:
        return []
    files = sorted(path.rglob("*.config")) if path.is_dir() else [path]
    out = []
    for f in files:
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    return out


@assess_app.callback(invoke_without_command=True)
def assess_main(
    ctx: typer.Context,
    dashboards: Annotated[
        Path | None,
        typer.Option(
            "--dashboards",
            help="Folder of OOTB dashboard .config files to derive requirements "
            "from (in addition to the tenant's deployed rules)",
        ),
    ] = None,
    lookback: Annotated[
        int,
        typer.Option("--lookback", help="Days of tenant history to sample [default: 30]"),
    ] = 30,
    apply: Annotated[
        bool,
        typer.Option("--apply/--no-apply", help="Write the proposed values [default: no-apply]"),
    ] = False,
    promote_learned: Annotated[
        bool,
        typer.Option(
            "--promote/--no-promote",
            help="Promote newly-learned GENERIC knowledge to the shared base "
            "(auto-tier only unless --approve-reviews) [default: no-promote]",
        ),
    ] = False,
    approve_reviews: Annotated[
        bool,
        typer.Option(
            "--approve-reviews",
            help="With --promote, also promote the review-tier candidates",
        ),
    ] = False,
    confirm: Annotated[
        bool,
        typer.Option(
            "--confirm/--dry-run",
            help="With --apply, actually write; without, preview [default: dry-run]",
        ),
    ] = False,
    out: Annotated[
        Path | None,
        typer.Option("--out", "-o", help="Assessment record path [default: ~/.exa/assessments/..]"),
    ] = None,
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
) -> None:
    """Discover -> derive requirements -> gap -> [apply] -> record. READ-ONLY unless --apply.

    \b
    Examples:
      uv run exa assess --tenant sademodev22
      uv run exa assess --tenant sademodev22 --dashboards ./ootb_dashboards
      uv run exa assess --tenant sademodev22 --apply --confirm
    """
    if ctx.invoked_subcommand is not None:
        return  # a subcommand (e.g. `benchmark`) handles it

    from exa.aillm.gaps import analyze_gaps, apply_gaps, gap_report_to_dict
    from exa.aillm.requirements import derive_requirements
    from exa.aillm.sources import collect_sources
    from exa.cli.aillm import _make_client
    from exa.config import get_default_tenant
    from exa.detection.rules import get_detection_rules

    name = tenant or get_default_tenant()
    date_str = time.strftime("%Y-%m-%d")
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    cfgs = _load_dashboard_configs(dashboards)

    client = _make_client(tenant)
    try:
        console.rule(f"Assess -- {name}")

        # 1. Discover sources
        inv = collect_sources(client)
        ai_sources = [s for s in inv.sources if getattr(s, "ai_relevant", False)]
        console.print(
            f"  Sources: {len(inv.sources)} vendor/product pairs "
            f"({len(ai_sources)} AI-relevant); missing roles: "
            f"{', '.join(inv.missing_roles()) or 'none'}",
            style="dim",
        )

        # 2. Derive requirements live (rules + dashboards)
        try:
            rules = get_detection_rules(client)
        except Exception:  # noqa: BLE001
            rules = []
        reqs = derive_requirements(rules=rules, dashboard_configs=cfgs, client=client)
        rtbl = Table(show_header=True, header_style="bold", title="Required (table <- field)")
        rtbl.add_column("Context table", style="cyan")
        rtbl.add_column("Field(s)")
        rtbl.add_column("Consumed by", style="dim")
        for tname, r in sorted(reqs.items()):
            rtbl.add_row(tname, ", ".join(sorted(r.fields)) or "-",
                         ", ".join(sorted(r.consumers)) or "-")
        console.print(rtbl)

        # 3. Gap analysis (what the tenant emits that the tables miss)
        report = analyze_gaps(client, lookback_days=lookback)
        gaps_dict = gap_report_to_dict(report)
        gaps_path = Path("reports") / "assess" / f"{name}-gaps-{date_str}.json"
        gaps_path.parent.mkdir(parents=True, exist_ok=True)
        gaps_path.write_text(json.dumps(gaps_dict, indent=2), encoding="utf-8")

        gtbl = Table(show_header=True, header_style="bold", title="Gap (values to add)")
        gtbl.add_column("Context table", style="cyan")
        gtbl.add_column("Propose", justify="right", style="green")
        gtbl.add_column("Withhold", justify="right", style="yellow")
        total_propose = 0
        for t in gaps_dict.get("tables", []):
            prop = len(t.get("propose", []))
            wh = sum(t.get("withheld_by_reason", {}).values()) if t.get("withheld_by_reason") else 0
            total_propose += prop
            if prop or wh:
                gtbl.add_row(t.get("table", "?"), str(prop), str(wh))
        console.print(gtbl)
        console.print(f"  Reviewable gaps written: {gaps_path}", style="dim")

        # 3b. Learn: capture NEW generic knowledge (customer data stripped)
        from exa.aillm.learn import (
            AUTO,
            LOCAL,
            REVIEW,
            extract_learn_candidates,
            promote,
            write_learn_file,
        )
        cands = extract_learn_candidates(gaps_dict)
        learn_path = write_learn_file(name, cands)
        n_auto = sum(1 for c in cands if c.verdict == AUTO)
        n_review = sum(1 for c in cands if c.verdict == REVIEW)
        n_local = sum(1 for c in cands if c.verdict == LOCAL)
        console.print(
            f"  Learned (new to exa-tools): {n_auto} auto-promote · {n_review} review · "
            f"{n_local} local-only -> {learn_path}",
            style="dim",
        )
        promoted_added = []
        if promote_learned and (n_auto or (approve_reviews and n_review)):
            promoted_added = promote(cands, approve_reviews=approve_reviews)
            console.print(
                f"  Promoted {len(promoted_added)} generic value(s) to the shared "
                "knowledge base (customer data never promoted).",
                style="green",
            )

        # 4. Assessment record
        record = {
            "tenant": name,
            "assessed_at": ts,
            "sources": {"total": len(inv.sources), "ai_relevant": len(ai_sources),
                        "missing_roles": inv.missing_roles()},
            "requirements": {t: {"fields": sorted(r.fields),
                                 "consumers": sorted(r.consumers)}
                             for t, r in reqs.items()},
            "gap_summary": {t.get("table"): len(t.get("propose", []))
                            for t in gaps_dict.get("tables", [])},
            "total_proposed": total_propose,
            "learned": {"auto_promote": n_auto, "review": n_review,
                        "local_only": n_local, "promoted": len(promoted_added)},
        }
        rec_path = Path(out) if out else _ASSESS_DIR / name / f"{ts}.json"
        rec_path.parent.mkdir(parents=True, exist_ok=True)
        rec_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        console.print(f"  Assessment record: {rec_path}", style="green")

        # 5. Apply (gated)
        if apply:
            if total_propose == 0:
                console.print("  Nothing to apply.", style="dim")
            else:
                results = apply_gaps(client, gaps_path, dry_run=not confirm)
                written = sum(getattr(r, "written", 0) for r in results)
                verb = "would write" if not confirm else "wrote"
                console.print(f"  {verb} {written} value(s) across {len(results)} table(s).",
                              style="green" if confirm else "yellow")
                if not confirm:
                    console.print("  Preview only -- re-run with --confirm.", style="yellow")
        else:
            console.print(
                f"  {total_propose} value(s) proposed. Re-run with --apply --confirm to write.",
                style="dim",
            )
    finally:
        client.close()

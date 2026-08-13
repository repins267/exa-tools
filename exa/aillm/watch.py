"""Run the AI/LLM report across every configured tenant in one pass.

`report` answers "what changed here". `watch` answers "which of my ten accounts
need me this week", which is the question a TAM actually starts Monday with.

Three design decisions, each covering a way this could quietly under-report:

ONE TENANT'S FAILURE MUST NOT END THE RUN. A watch that aborts on tenant 3 of 10
reports on 2 and looks like it reported on everything. Failures are collected and
surfaced, never raised.

"NO BASELINE" IS NOT "QUIET". A first run has nothing to compare against. Folding
that into "nothing changed" turns "we cannot answer yet" into "we checked and it
is fine" -- the same substitution that makes an empty dashboard panel look like an
absence of activity.

LOWER BOUNDS DO NOT SUM. Where a tenant's live sample was truncated its counts
are floors, so a cross-tenant total built from them is a floor too and is labelled
as one rather than printed as a figure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.aillm.report import AILLMReport

# Index states. Deliberately three, not two.
MOVED = "moved"
QUIET = "quiet"
NO_BASELINE = "no-baseline"
FAILED = "failed"


@dataclass
class TenantWatch:
    """One tenant's outcome. A failure is an outcome, not an absence."""

    tenant: str
    state: str
    report_path: Path | None = None
    changed_tables: int = 0
    total_records: int = 0
    missing_tables: list[str] = field(default_factory=list)
    drift_count: int = 0
    lower_bound: bool = False
    error: str = ""

    @property
    def needs_attention(self) -> bool:
        """Worth a human look. Quiet tenants are not."""
        return self.state in (MOVED, FAILED) or bool(self.missing_tables)


@dataclass
class WatchRun:
    """Every tenant attempted, including the ones that failed."""

    started_at: str
    tenants: list[TenantWatch] = field(default_factory=list)
    drift_enabled: bool = False

    def by_state(self, state: str) -> list[TenantWatch]:
        return [t for t in self.tenants if t.state == state]

    @property
    def attempted(self) -> int:
        return len(self.tenants)

    @property
    def any_lower_bound(self) -> bool:
        return any(t.lower_bound for t in self.tenants)

    @property
    def ordered(self) -> list[TenantWatch]:
        """Attention first, quiet last -- the reading order, not the run order."""
        rank = {FAILED: 0, MOVED: 1, NO_BASELINE: 2, QUIET: 3}
        return sorted(self.tenants, key=lambda t: (rank.get(t.state, 9), t.tenant))


def configured_tenants() -> list[str]:
    """Every tenant nickname in ~/.exa/config.json, sorted.

    Same source `exa config tenants` reads, so what watch covers is always what
    the user can see -- a divergence here would silently skip accounts.
    """
    from exa.config import _read_config_file

    return sorted((_read_config_file().get("tenants") or {}).keys())


def _classify(report: AILLMReport) -> str:
    if not report.has_baseline:
        return NO_BASELINE
    return MOVED if any(c.moved for c in report.changes) else QUIET


def watch_tenants(
    tenants: list[str],
    *,
    out_dir: Path,
    lookback_days: int = 30,
    drift: bool = False,
    save_baselines: bool = True,
) -> WatchRun:
    """Report on each tenant in turn, collecting failures rather than raising.

    Args:
        tenants: Tenant nicknames to visit.
        out_dir: Directory for the per-tenant HTML reports and the index.
        lookback_days: Days of tenant history to sample.
        drift: Include drift analysis. Off by default -- it costs roughly ten API
            calls per tenant, which is a different order of expense across ten
            accounts than it is against one.
        save_baselines: Store each run as the next run's comparison point.

    Returns:
        WatchRun covering every tenant attempted, failures included.
    """
    from exa.aillm.report import build_report, save_baseline, save_html_report

    out_dir.mkdir(parents=True, exist_ok=True)
    run = WatchRun(
        started_at=datetime.now(UTC).isoformat(timespec="seconds"),
        drift_enabled=drift,
    )

    for name in tenants:
        client = None
        try:
            from exa.cli.app import _make_client

            client = _make_client(name)
            report = build_report(
                client, name, lookback_days=lookback_days, include_drift=drift
            )
        except Exception as exc:  # noqa: BLE001
            # Deliberately broad. Auth failure, DNS, a tenant deleted upstream, a
            # malformed response -- all of it is one tenant's problem and none of
            # it is a reason to stop visiting the other nine.
            run.tenants.append(
                TenantWatch(tenant=name, state=FAILED, error=f"{type(exc).__name__}: {exc}")
            )
            continue
        finally:
            if client is not None:
                client.close()

        path = out_dir / f"{name}-aillm.html"
        save_html_report(report, path)
        if save_baselines:
            save_baseline(report)

        run.tenants.append(
            TenantWatch(
                tenant=name,
                state=_classify(report),
                report_path=path,
                changed_tables=sum(1 for c in report.changes if c.moved),
                total_records=report.total_records,
                missing_tables=report.missing_tables,
                drift_count=len(report.drift),
                lower_bound=report.counts_are_lower_bound,
            )
        )

    return run


def watch_to_dict(run: WatchRun) -> dict[str, Any]:
    return {
        "started_at": run.started_at,
        "attempted": run.attempted,
        "drift_enabled": run.drift_enabled,
        "counts_are_lower_bound": run.any_lower_bound,
        "states": {
            s: [t.tenant for t in run.by_state(s)]
            for s in (FAILED, MOVED, NO_BASELINE, QUIET)
        },
        "tenants": [
            {
                "tenant": t.tenant,
                "state": t.state,
                "report": str(t.report_path) if t.report_path else None,
                "changed_tables": t.changed_tables,
                "total_records": t.total_records,
                "missing_tables": t.missing_tables,
                "drift": t.drift_count,
                "counts_are_lower_bound": t.lower_bound,
                "error": t.error,
                "needs_attention": t.needs_attention,
            }
            for t in run.ordered
        ],
    }


_CSS = """
:root{--bg:#fff;--fg:#1a1d21;--muted:#5c6470;--line:#e3e6ea;--panel:#f7f8fa;
--ok:#2e7d32;--warn:#F0AD4E;--bad:#E53E3E}
@media(prefers-color-scheme:dark){:root{--bg:#15181c;--fg:#e8eaed;--muted:#9aa3ad;
--line:#2a2f36;--panel:#1c2026}}
*{box-sizing:border-box}
body{margin:0;padding:32px;background:var(--bg);color:var(--fg);
font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:940px;margin:0 auto}
h1{font-size:25px;margin:0 0 4px}
.sub{color:var(--muted);font-size:13px;margin-bottom:22px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}
.card{flex:1 1 130px;background:var(--panel);border:1px solid var(--line);
border-radius:8px;padding:14px}
.card .v{font-size:25px;font-weight:600;font-variant-numeric:tabular-nums}
.card .l{color:var(--muted);font-size:12px;margin-top:2px}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);
vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;
letter-spacing:.04em}
td.n{text-align:right;font-variant-numeric:tabular-nums}
.pill{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;
font-weight:600}
.p-moved{background:rgba(240,173,78,.18);color:var(--warn)}
.p-quiet{background:rgba(46,125,50,.15);color:var(--ok)}
.p-none{background:rgba(92,100,112,.18);color:var(--muted)}
.p-failed{background:rgba(229,62,62,.15);color:var(--bad)}
a{color:inherit}
.note{background:var(--panel);border-left:3px solid var(--warn);padding:11px 14px;
border-radius:0 6px 6px 0;margin:14px 0;font-size:13.5px;color:var(--muted)}
"""

_PILL = {MOVED: "p-moved", QUIET: "p-quiet", NO_BASELINE: "p-none", FAILED: "p-failed"}
_LABEL = {
    MOVED: "moved",
    QUIET: "quiet",
    NO_BASELINE: "no baseline",
    FAILED: "failed",
}


def _esc(text: Any) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def generate_index_html(run: WatchRun) -> str:
    """One page answering which accounts need attention this week."""
    rows = []
    for t in run.ordered:
        if t.state == FAILED:
            detail = f"<span class='p-failed'>{_esc(t.error)}</span>"
        elif t.state == NO_BASELINE:
            detail = "first run -- stored as the baseline, nothing to compare yet"
        elif t.state == MOVED:
            detail = f"{t.changed_tables} table(s) changed"
        else:
            detail = "no record counts moved"
        if t.missing_tables:
            detail += (
                f" &middot; <strong>{len(t.missing_tables)} table(s) absent:</strong> "
                + _esc(", ".join(t.missing_tables))
            )
        link = (
            f"<a href='{_esc(t.report_path.name)}'>{_esc(t.tenant)}</a>"
            if t.report_path
            else _esc(t.tenant)
        )
        bound = "+" if t.lower_bound else ""
        rows.append(
            "<tr>"
            f"<td>{link}</td>"
            f"<td><span class='pill {_PILL[t.state]}'>{_LABEL[t.state]}</span></td>"
            f"<td class='n'>{t.total_records:,}{bound}</td>"
            f"<td>{detail}</td></tr>"
        )

    attention = [t for t in run.tenants if t.needs_attention]
    notes = []
    if not run.drift_enabled:
        notes.append(
            "<div class='note'><strong>Drift was not collected.</strong> "
            "Run with --drift to see values these tenants emit that neither their "
            "context tables nor the reference data know about. It costs roughly "
            "ten API calls per tenant, which is why it is off by default across a "
            "whole estate.</div>"
        )
    if run.any_lower_bound:
        notes.append(
            "<div class='note'><strong>Some counts are lower bounds.</strong> "
            "Where a tenant's live sample was truncated its figures are floors, "
            "marked with <code>+</code>. They are deliberately not summed into an "
            "estate total -- a total built from floors is a floor, and would read "
            "as exact.</div>"
        )
    if run.by_state(NO_BASELINE):
        notes.append(
            "<div class='note'><strong>"
            f"{len(run.by_state(NO_BASELINE))} tenant(s) have no baseline.</strong> "
            "This run stored one. They are not reported as quiet, because "
            "&quot;cannot compare yet&quot; is not &quot;nothing changed&quot;.</div>"
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI/LLM Watch</title><style>{_CSS}</style></head><body><div class="wrap">
<h1>AI/LLM Watch</h1>
<div class="sub">{_esc(run.started_at)} &middot; {run.attempted} tenant(s) attempted</div>

<div class="cards">
  <div class="card"><div class="v">{len(attention)}</div>
    <div class="l">Need attention</div></div>
  <div class="card"><div class="v">{len(run.by_state(MOVED))}</div>
    <div class="l">Moved</div></div>
  <div class="card"><div class="v">{len(run.by_state(QUIET))}</div>
    <div class="l">Quiet</div></div>
  <div class="card"><div class="v">{len(run.by_state(NO_BASELINE))}</div>
    <div class="l">No baseline</div></div>
  <div class="card"><div class="v">{len(run.by_state(FAILED))}</div>
    <div class="l">Failed</div></div>
</div>

{"".join(notes)}

<div class="scroll"><table><thead><tr><th>Tenant</th><th>State</th>
<th>Records</th><th>Detail</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></div>
</div></body></html>"""


def save_index(run: WatchRun, out_dir: Path) -> Path:
    path = out_dir / "index.html"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(generate_index_html(run), encoding="utf-8")
    return path

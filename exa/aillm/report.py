"""AI/LLM engagement report: state now, what changed, and what is drifting in.

Three questions a TAM gets asked at every sync, in the order they get asked:

    STATE    what do the tables hold, and are the dashboards fed?
    CHANGES  what moved since the last time we looked?
    DRIFT    what is the tenant emitting that nothing yet knows about?

Drift is the one that has no other home. A value the tenant emits that appears
in neither the context tables nor the shipped reference data is, by definition,
something no dashboard filters on and no rule matches. It renders as absence
everywhere -- which is why it needs a report that asks for it by name rather
than a panel that would show it if only it were configured to.

State snapshots are written to ~/.exa/aillm-reports/<tenant>/ so the next run
has something to diff against. Without a stored baseline "what changed" is
unanswerable, and the honest output is to say so rather than to imply nothing
changed.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

SNAPSHOT_DIR = Path.home() / ".exa" / "aillm-reports"


@dataclass
class TableState:
    """One context table as it stands right now."""

    name: str
    table_id: str | None
    key_attr: str
    records: int
    present: bool = True
    consumers: list[str] = field(default_factory=list)


@dataclass
class TableChange:
    """How one table moved between two snapshots."""

    name: str
    before: int
    after: int

    @property
    def delta(self) -> int:
        return self.after - self.before

    @property
    def moved(self) -> bool:
        return self.delta != 0


@dataclass
class DriftItem:
    """A live value that neither the tables nor the reference data know about."""

    field_name: str
    value: str
    sources: list[str] = field(default_factory=list)


@dataclass
class AILLMReport:
    """State + changes + drift for one tenant at one point in time."""

    tenant: str
    collected_at: str
    lookback_days: int
    tables: list[TableState] = field(default_factory=list)
    changes: list[TableChange] = field(default_factory=list)
    drift: list[DriftItem] = field(default_factory=list)
    baseline_at: str | None = None
    reference_summary: str = ""
    reference_stale: bool = False
    truncated_fields: list[str] = field(default_factory=list)

    @property
    def has_baseline(self) -> bool:
        return self.baseline_at is not None

    @property
    def counts_are_lower_bound(self) -> bool:
        """Drift is a lower bound wherever the live sample was truncated.

        A drift list presented as complete retires a question that is still
        open, so this rides alongside every count derived from it.
        """
        return bool(self.truncated_fields)

    @property
    def total_records(self) -> int:
        return sum(t.records for t in self.tables if t.present)

    @property
    def missing_tables(self) -> list[str]:
        return [t.name for t in self.tables if not t.present]


def _snapshot_path(tenant: str) -> Path:
    return SNAPSHOT_DIR / tenant / "state.json"


def load_baseline(tenant: str) -> dict[str, Any] | None:
    """The last stored snapshot for this tenant, or None on the first run."""
    path = _snapshot_path(tenant)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        # A corrupt baseline must not read as "nothing changed" -- the caller
        # treats None as "no baseline" and says so in the output.
        return None


def save_baseline(report: AILLMReport) -> Path:
    """Store this run's state so the next run has something to diff against."""
    path = _snapshot_path(report.tenant)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "tenant": report.tenant,
        "collected_at": report.collected_at,
        "tables": [asdict(t) for t in report.tables],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def collect_state(client: ExaClient) -> list[TableState]:
    """Read every AI/LLM context table's real key attribute and record count."""
    from exa.aillm.validate import TABLE_SPECS
    from exa.context.tables import get_tables, resolve_table_schema

    live: dict[str, dict[str, Any]] = {}
    for t in get_tables(client):
        name = (t.get("displayName") or t.get("name") or "").strip()
        if name:
            live[name] = t

    states: list[TableState] = []
    for name, spec in TABLE_SPECS.items():
        table = live.get(name)
        if table is None:
            states.append(
                TableState(
                    name=name,
                    table_id=None,
                    key_attr="",
                    records=0,
                    present=False,
                    consumers=sorted(spec.consumers),
                )
            )
            continue
        key_attr, _ = resolve_table_schema(client, table)
        states.append(
            TableState(
                name=name,
                table_id=str(table.get("id") or ""),
                key_attr=key_attr,
                # totalItems, never numRecords -- numRecords does not exist and
                # reads as 0 for every table.
                records=int(table.get("totalItems") or 0),
                consumers=sorted(spec.consumers),
            )
        )
    return states


def diff_state(
    baseline: dict[str, Any] | None, current: list[TableState]
) -> list[TableChange]:
    """Record-count movement per table since the baseline.

    Returns an empty list when there is no baseline. The caller must not render
    that as "nothing changed" -- see AILLMReport.has_baseline.
    """
    if not baseline:
        return []
    before = {t["name"]: int(t.get("records") or 0) for t in baseline.get("tables", [])}
    return [
        TableChange(name=t.name, before=before.get(t.name, 0), after=t.records)
        for t in current
        if t.name in before or t.records
    ]


def collect_drift(
    client: ExaClient, *, lookback_days: int = 30, refresh: bool = False
) -> tuple[list[DriftItem], list[str]]:
    """Live values present in neither the context tables nor the reference data.

    Deliberately reuses the gap analysis rather than re-querying: gaps already
    normalises through the vendor packs, and comparing raw strings here would
    re-propose the 19,134 Purview values that normalise to 2.

    Drift is narrower than a gap. A gap is anything missing from a table; drift
    is missing from the table AND unknown to the shipped reference data, i.e.
    genuinely new to us rather than merely not yet applied.

    Returns:
        (drift items, names of fields whose live sample was truncated)
    """
    from exa.aillm.gaps import analyze_gaps
    from exa.aillm.reference import load_reference_data

    report = analyze_gaps(client, lookback_days=lookback_days, refresh=refresh)

    ref = load_reference_data()
    known: set[str] = set()
    for bucket in (
        ref.public_domains,
        ref.web_domains,
        ref.applications,
        ref.dlp_rulesets,
        ref.proxy_categories,
        ref.web_categories,
    ):
        for row in bucket:
            value = row.get("key")
            if value:
                known.add(str(value).strip().lower())

    drift: list[DriftItem] = []
    for table in report.tables:
        for proposal in table.propose:
            if not proposal.value:
                continue
            if proposal.value.strip().lower() in known:
                continue
            drift.append(
                DriftItem(
                    field_name=proposal.field_name,
                    value=proposal.value,
                    sources=list(proposal.sources),
                )
            )
    return drift, list(report.truncated_fields)


def build_report(
    client: ExaClient,
    tenant: str,
    *,
    lookback_days: int = 30,
    refresh: bool = False,
    include_drift: bool = True,
) -> AILLMReport:
    """Assemble state, changes and drift for one tenant."""
    from exa.aillm.reference import reference_freshness

    states = collect_state(client)
    baseline = load_baseline(tenant)

    drift: list[DriftItem] = []
    truncated: list[str] = []
    if include_drift:
        drift, truncated = collect_drift(
            client, lookback_days=lookback_days, refresh=refresh
        )

    fresh = reference_freshness()
    return AILLMReport(
        tenant=tenant,
        collected_at=datetime.now(UTC).isoformat(timespec="seconds"),
        lookback_days=lookback_days,
        tables=states,
        changes=diff_state(baseline, states),
        drift=drift,
        baseline_at=baseline.get("collected_at") if baseline else None,
        reference_summary=fresh.summary,
        reference_stale=fresh.stale,
        truncated_fields=truncated,
    )


def report_to_dict(report: AILLMReport) -> dict[str, Any]:
    """Serialise, with every count that could mislead labelled as bounded."""
    return {
        "tenant": report.tenant,
        "collected_at": report.collected_at,
        "lookback_days": report.lookback_days,
        "baseline_at": report.baseline_at,
        "has_baseline": report.has_baseline,
        "reference_data": report.reference_summary,
        "reference_stale": report.reference_stale,
        "counts_are_lower_bound": report.counts_are_lower_bound,
        "truncated_fields": report.truncated_fields,
        "total_records": report.total_records,
        "missing_tables": report.missing_tables,
        "tables": [asdict(t) for t in report.tables],
        "changes": [
            {**asdict(c), "delta": c.delta} for c in report.changes if c.moved
        ],
        "drift": [asdict(d) for d in report.drift],
    }


# -- HTML ---------------------------------------------------------------------


def _esc(text: Any) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


_CSS = """
:root{--bg:#fff;--fg:#1a1d21;--muted:#5c6470;--line:#e3e6ea;--accent:#0b5fff;
--ok:#2e7d32;--warn:#F0AD4E;--bad:#E53E3E;--panel:#f7f8fa}
@media(prefers-color-scheme:dark){:root{--bg:#15181c;--fg:#e8eaed;--muted:#9aa3ad;
--line:#2a2f36;--panel:#1c2026}}
*{box-sizing:border-box}
body{margin:0;padding:32px;background:var(--bg);color:var(--fg);
font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1000px;margin:0 auto}
h1{font-size:26px;margin:0 0 4px}
h2{font-size:17px;margin:34px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.sub{color:var(--muted);font-size:13px;margin-bottom:22px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}
.card{flex:1 1 150px;background:var(--panel);border:1px solid var(--line);
border-radius:8px;padding:14px}
.card .v{font-size:26px;font-weight:600;font-variant-numeric:tabular-nums}
.card .l{color:var(--muted);font-size:12px;margin-top:2px}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);
vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;
letter-spacing:.04em}
td.n{text-align:right;font-variant-numeric:tabular-nums}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.note{background:var(--panel);border-left:3px solid var(--warn);padding:11px 14px;
border-radius:0 6px 6px 0;margin:14px 0;font-size:13.5px;color:var(--muted)}
.note.bad{border-left-color:var(--bad)}
code{background:var(--panel);padding:1px 5px;border-radius:4px;font-size:13px}
"""


def generate_html_report(report: AILLMReport) -> str:
    """Render the report as a self-contained HTML page."""
    r = report

    def rows(items: list[str]) -> str:
        return "".join(items)

    state_rows = rows(
        [
            "<tr>"
            f"<td>{_esc(t.name)}</td>"
            f"<td><code>{_esc(t.key_attr or '-')}</code></td>"
            f"<td class='n'>{t.records:,}</td>"
            f"<td>{_esc(', '.join(t.consumers) or '-')}</td>"
            + (
                "<td class='bad'>not on tenant</td>"
                if not t.present
                else (
                    "<td class='bad'>empty</td>"
                    if t.records == 0
                    else "<td class='ok'>populated</td>"
                )
            )
            + "</tr>"
            for t in r.tables
        ]
    )

    moved = [c for c in r.changes if c.moved]
    if not r.has_baseline:
        changes_block = (
            "<div class='note'>No previous snapshot for this tenant, so there is "
            "nothing to compare against. This run has been stored as the "
            "baseline &mdash; the next one will show movement.</div>"
        )
    elif not moved:
        changes_block = (
            f"<div class='note'>No record counts moved since "
            f"{_esc(r.baseline_at)}.</div>"
        )
    else:
        changes_block = (
            "<div class='scroll'><table><thead><tr><th>Table</th>"
            "<th>Before</th><th>After</th><th>Change</th></tr></thead><tbody>"
            + rows(
                [
                    "<tr>"
                    f"<td>{_esc(c.name)}</td>"
                    f"<td class='n'>{c.before:,}</td>"
                    f"<td class='n'>{c.after:,}</td>"
                    f"<td class='n {"ok" if c.delta > 0 else "bad"}'>"
                    f"{c.delta:+,}</td></tr>"
                    for c in moved
                ]
            )
            + "</tbody></table></div>"
        )

    if r.drift:
        drift_block = (
            "<div class='scroll'><table><thead><tr><th>Field</th><th>Value</th>"
            "<th>Seen on</th></tr></thead><tbody>"
            + rows(
                [
                    "<tr>"
                    f"<td><code>{_esc(d.field_name)}</code></td>"
                    f"<td>{_esc(d.value)}</td>"
                    f"<td>{_esc(', '.join(d.sources) or '-')}</td></tr>"
                    for d in r.drift
                ]
            )
            + "</tbody></table></div>"
        )
    else:
        drift_block = (
            "<div class='note'>Nothing drifting: every AI-related value this "
            "tenant emits is already known to the tables or the reference "
            "data.</div>"
        )

    bound_note = ""
    if r.counts_are_lower_bound:
        bound_note = (
            "<div class='note bad'><strong>Every count below is a lower "
            "bound.</strong> The live sample was truncated for "
            f"{_esc(', '.join(r.truncated_fields))}, so a value absent here may "
            "still be present on the tenant.</div>"
        )

    stale_note = ""
    if r.reference_stale:
        stale_note = (
            "<div class='note'><strong>Reference data is stale.</strong> "
            f"{_esc(r.reference_summary)}. Drift is measured against it, so a "
            "service that became an AI product recently reads as ordinary "
            "traffic and will not appear below.</div>"
        )

    missing_note = ""
    if r.missing_tables:
        missing_note = (
            "<div class='note bad'><strong>Tables absent from this tenant:</strong> "
            f"{_esc(', '.join(r.missing_tables))}. Panels and rules reading them "
            "render empty rather than erroring.</div>"
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI/LLM Report &mdash; {_esc(r.tenant)}</title>
<style>{_CSS}</style></head><body><div class="wrap">
<h1>AI/LLM Landscape Report</h1>
<div class="sub">{_esc(r.tenant)} &middot; {_esc(r.collected_at)} &middot;
{r.lookback_days}-day lookback &middot; reference data:
{_esc(r.reference_summary)}</div>

{bound_note}{stale_note}{missing_note}

<div class="cards">
  <div class="card"><div class="v">{len(r.tables)}</div>
    <div class="l">Context tables</div></div>
  <div class="card"><div class="v">{r.total_records:,}</div>
    <div class="l">Records held</div></div>
  <div class="card"><div class="v">{len(moved)}</div>
    <div class="l">Tables changed</div></div>
  <div class="card"><div class="v">{len(r.drift)}{"+" if r.counts_are_lower_bound else ""}</div>
    <div class="l">Drifting values</div></div>
</div>

<h2>State</h2>
<div class="scroll"><table><thead><tr><th>Table</th><th>Key attribute</th>
<th>Records</th><th>Read by</th><th>Status</th></tr></thead>
<tbody>{state_rows}</tbody></table></div>

<h2>Changes</h2>
{changes_block}

<h2>Drift &mdash; emitted here, unknown to tables and reference data</h2>
{drift_block}
</div></body></html>"""


def default_report_path(tenant: str, date_str: str | None = None) -> Path:
    """reports/<tenant>-aillm-<date>.html, matching the compliance convention."""
    date_str = date_str or time.strftime("%Y-%m-%d")
    return Path("reports") / f"{tenant}-aillm-{date_str}.html"


def save_html_report(report: AILLMReport, path: str | Path) -> None:
    """Render and write the HTML report."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(generate_html_report(report), encoding="utf-8")

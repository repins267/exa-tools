"""SOC KPIs from the Threat Center case model.

Aggregates cases into the metrics a SOC analyst/manager tracks: cases opened,
worked-by (assignee), backlog by stage/priority/queue, close rate, mean-time-to-
close (MTTR, proxied by lastModified on closed cases), average open age, top
firing rules, and notable users. Read-only.

Timestamps are microseconds since epoch.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from exa.client import ExaClient

_CLOSED = ("CLOSED", "RESOLVED", "DISMISS")


def _is_closed(stage: str) -> bool:
    s = str(stage or "").upper()
    return any(k in s for k in _CLOSED)


def _ts_s(v) -> float | None:
    try:
        n = float(v)
    except (TypeError, ValueError):
        return None
    # normalize micro/nano/milli to seconds
    while n > 1e11:
        n /= 1000.0
    return n


@dataclass
class SocKpis:
    tenant: str | None = None
    lookback_days: int = 30
    opened: int = 0
    closed: int = 0
    by_stage: list[tuple[str, int]] = field(default_factory=list)
    by_priority: list[tuple[str, int]] = field(default_factory=list)
    by_assignee: list[tuple[str, int]] = field(default_factory=list)
    by_queue: list[tuple[str, int]] = field(default_factory=list)
    top_rules: list[tuple[str, int]] = field(default_factory=list)
    notable_users: list[tuple[str, int]] = field(default_factory=list)
    mttr_hours: float | None = None
    avg_open_age_hours: float | None = None
    truncated: bool = False
    note: str = ""

    @property
    def close_rate(self) -> float:
        return round(100 * self.closed / self.opened, 1) if self.opened else 0.0

    @property
    def open_backlog(self) -> int:
        return self.opened - self.closed


def collect_soc_kpis(client: "ExaClient", *, lookback_days: int = 30, limit: int = 5000) -> SocKpis:
    """Read-only SOC KPI rollup over cases in the window."""
    from exa.case.cases import search_cases

    k = SocKpis(tenant=getattr(client, "tenant", None), lookback_days=lookback_days)
    try:
        cases = search_cases(client, filter=None, lookback_days=lookback_days, limit=limit)
    except Exception as exc:
        k.note = f"case query failed: {exc}"
        return k
    cases = cases if isinstance(cases, list) else []
    k.truncated = len(cases) >= limit
    k.opened = len(cases)

    stage_c: Counter = Counter()
    prio_c: Counter = Counter()
    asg_c: Counter = Counter()
    q_c: Counter = Counter()
    rule_c: Counter = Counter()
    user_c: Counter = Counter()
    mttr_samples: list[float] = []
    open_ages: list[float] = []
    now = time.time()

    for c in cases:
        stage = c.get("stage")
        stage_c[str(stage or "?")] += 1
        prio_c[str(c.get("priority") or "?")] += 1
        asg_c[str(c.get("assignee") or "Unassigned")] += 1
        q_c[str(c.get("queue") or "Unassigned")] += 1
        if c.get("name"):
            rule_c[str(c.get("name"))] += 1
        if c.get("user"):
            user_c[str(c.get("user"))] += 1

        created = _ts_s(c.get("caseCreationTimestamp"))
        if _is_closed(stage):
            k.closed += 1
            modified = _ts_s(c.get("lastModifiedTimestamp"))
            if created and modified and modified >= created:
                mttr_samples.append((modified - created) / 3600.0)
        elif created:
            open_ages.append((now - created) / 3600.0)

    k.by_stage = stage_c.most_common()
    k.by_priority = prio_c.most_common()
    k.by_assignee = asg_c.most_common(15)
    k.by_queue = q_c.most_common(10)
    k.top_rules = rule_c.most_common(10)
    k.notable_users = user_c.most_common(10)
    if mttr_samples:
        k.mttr_hours = round(sum(mttr_samples) / len(mttr_samples), 1)
    if open_ages:
        k.avg_open_age_hours = round(sum(open_ages) / len(open_ages), 1)
    return k


def soc_kpis_summary(k: SocKpis) -> dict:
    def pairs(rows):
        return [{"value": v, "count": n} for v, n in rows]

    return {
        "tenant": k.tenant,
        "lookback_days": k.lookback_days,
        "opened": k.opened,
        "closed": k.closed,
        "open_backlog": k.open_backlog,
        "close_rate_pct": k.close_rate,
        "mttr_hours": k.mttr_hours,
        "avg_open_age_hours": k.avg_open_age_hours,
        "by_stage": pairs(k.by_stage),
        "by_priority": pairs(k.by_priority),
        "worked_by": pairs(k.by_assignee),
        "by_queue": pairs(k.by_queue),
        "top_rules": pairs(k.top_rules),
        "notable_users": pairs(k.notable_users),
        "sampled": k.truncated,
        "note": k.note or None,
    }


def render_soc_kpis(k: SocKpis) -> str:
    """Branded SOC KPI report."""
    from exa.report import coverage_bar, data_table, page, panel, stat_card

    cards = [
        {"label": "Tenant", "value": k.tenant or "—", "hint": f"last {k.lookback_days}d"},
        {"label": "Cases opened", "value": k.opened, "hint": f"last {k.lookback_days}d"},
        {"label": "Open backlog", "value": k.open_backlog,
         "status": "bad" if k.open_backlog > 50 else "warn" if k.open_backlog else "good"},
        {"label": "Close rate", "value": f"{k.close_rate}%",
         "status": "good" if k.close_rate >= 70 else "warn" if k.close_rate >= 40 else "bad"},
        {"label": "MTTR", "value": f"{k.mttr_hours}h" if k.mttr_hours is not None else "—",
         "hint": "avg time to close"},
        {"label": "Avg open age", "value": f"{k.avg_open_age_hours}h" if k.avg_open_age_hours is not None else "—",
         "status": "warn" if (k.avg_open_age_hours or 0) > 72 else "", "hint": "unworked backlog"},
    ]
    cards_html = "".join(stat_card(c["label"], c["value"], c.get("status", ""), c.get("hint", "")) for c in cards)

    def tbl(rows, a, b):
        return data_table([{a: v, b: n} for v, n in rows], f"t{hash(a) & 0xffff}") if rows else '<div class="footer-note">none</div>'

    panels = "".join([
        panel("Close rate", coverage_bar(k.close_rate) +
              f'<div class="footer-note">{k.closed} of {k.opened} cases closed in the window.</div>',
              half=True),
        panel("Worked by (assignee)", tbl(k.by_assignee, "Analyst", "Cases"),
              "case load per analyst", half=True),
        panel("By priority", tbl(k.by_priority, "Priority", "Cases"), half=True),
        panel("By stage", tbl(k.by_stage, "Stage", "Cases"), half=True),
        panel("By queue", tbl(k.by_queue, "Queue", "Cases"), half=True),
        panel("Top firing rules", tbl(k.top_rules, "Rule / alert", "Cases"), half=True),
        panel("Notable users", tbl(k.notable_users, "User", "Cases"),
              "entities generating the most cases", half=True),
    ])
    meta = [k.tenant or "—", f"last {k.lookback_days}d", "SOC KPIs · read-only"]
    return page(
        f"exa-tools · {k.tenant or ''} · SOC KPIs",
        f"Case metrics · last {k.lookback_days}d",
        cards_html, panels, "".join(f"<div>{m}</div>" for m in meta), initial_theme="dark",
    )

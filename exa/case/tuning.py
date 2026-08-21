"""NYMM ("Not Your Momma's Mouton") — detection tuning insight for New-Scale
Analytics, the replacement for the legacy Mouton rules analysis.

Mouton (deprecated, Advanced Analytics) ranked rules by NotableReductionOnDeletion:
how many notables would vanish if a rule were disabled -- the noisy tune/disable
candidates. NSA has no notables/histograms; it has alerts -> cases. The analog:
rank alert drivers by volume vs. how rarely they escalate to a case (low escalation
+ high volume + low risk = noise). Read-only.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from exa.client import ExaClient


@dataclass
class AlertDriver:
    name: str = ""
    count: int = 0
    pct_of_all: float = 0.0
    avg_risk: float = 0.0
    escalated: int = 0
    escalation_rate: float = 0.0
    top_priority: str = ""
    recommendation: str = "Keep"


@dataclass
class TuningReport:
    tenant: str | None = None
    lookback_days: int = 30
    total_alerts: int = 0
    escalated_alerts: int = 0
    drivers: list[AlertDriver] = field(default_factory=list)
    silent_rules: list[str] = field(default_factory=list)
    enabled_rules: int = 0
    truncated: bool = False
    note: str = ""

    @property
    def escalation_rate(self) -> float:
        return round(100 * self.escalated_alerts / self.total_alerts, 1) if self.total_alerts else 0.0


def _classify(pct: float, esc_rate: float, avg_risk: float) -> str:
    """The NotableReductionOnDeletion analog: high volume + rarely escalates = noise."""
    if pct >= 5 and esc_rate < 5:
        return "Tune / disable"       # drives lots of alerts, almost none become cases
    if pct >= 5 and esc_rate < 20:
        return "Review"               # noisy, low escalation
    if avg_risk < 40 and esc_rate < 10:
        return "Review"               # low value
    return "Keep"                      # escalates / high risk


def collect_tuning(client: "ExaClient", *, lookback_days: int = 30, top_n: int = 20) -> TuningReport:
    """Read-only detection-tuning rollup for an NSA tenant."""
    from exa.case.alerts import search_alerts

    tr = TuningReport(tenant=getattr(client, "tenant", None), lookback_days=lookback_days)
    try:
        alerts = search_alerts(client, filter=None, lookback_days=lookback_days, limit=5000)
    except Exception as exc:
        tr.note = f"alert query failed: {exc}"
        return tr
    alerts = alerts if isinstance(alerts, list) else []
    tr.truncated = len(alerts) >= 5000
    tr.total_alerts = len(alerts)

    agg: dict[str, dict] = {}
    for a in alerts:
        name = str(a.get("name") or "?")
        d = agg.setdefault(name, {"count": 0, "risk": 0.0, "esc": 0, "prio": Counter()})
        d["count"] += 1
        try:
            d["risk"] += float(a.get("riskScore") or 0)
        except (TypeError, ValueError):
            pass
        if a.get("caseId"):
            d["esc"] += 1
        d["prio"][str(a.get("priority") or "?")] += 1

    tr.escalated_alerts = sum(d["esc"] for d in agg.values())
    for name, d in agg.items():
        cnt = d["count"]
        pct = round(100 * cnt / tr.total_alerts, 1) if tr.total_alerts else 0.0
        avg_risk = round(d["risk"] / cnt, 1) if cnt else 0.0
        esc_rate = round(100 * d["esc"] / cnt, 1) if cnt else 0.0
        tr.drivers.append(AlertDriver(
            name=name, count=cnt, pct_of_all=pct, avg_risk=avg_risk,
            escalated=d["esc"], escalation_rate=esc_rate,
            top_priority=(d["prio"].most_common(1)[0][0] if d["prio"] else ""),
            recommendation=_classify(pct, esc_rate, avg_risk),
        ))
    tr.drivers.sort(key=lambda x: -x.count)
    tr.drivers = tr.drivers[:top_n]

    # "silent rules" -- enabled but not reachable = the never-converge analog.
    try:
        from exa.detection.rules import get_detection_rules
        rules = get_detection_rules(client)
        tr.enabled_rules = sum(1 for r in rules if r.get("isEnabled") is True)
    except Exception:
        pass
    return tr


def tuning_summary(tr: TuningReport) -> dict:
    return {
        "tenant": tr.tenant,
        "lookback_days": tr.lookback_days,
        "total_alerts": tr.total_alerts,
        "escalated_alerts": tr.escalated_alerts,
        "escalation_rate_pct": tr.escalation_rate,
        "enabled_rules": tr.enabled_rules,
        "sampled": tr.truncated,
        "drivers": [
            {
                "name": d.name, "count": d.count, "pct_of_all": d.pct_of_all,
                "avg_risk": d.avg_risk, "escalation_rate_pct": d.escalation_rate,
                "top_priority": d.top_priority, "recommendation": d.recommendation,
            }
            for d in tr.drivers
        ],
        "note": tr.note or None,
    }


def render_tuning(tr: TuningReport) -> str:
    """Branded tuning report."""
    from exa.report import coverage_bar, data_table, page, panel, stat_card

    noisy = [d for d in tr.drivers if d.recommendation != "Keep"]
    cards = "".join([
        stat_card("Tenant", tr.tenant or "—", "", f"last {tr.lookback_days}d"),
        stat_card("Alerts", f"{tr.total_alerts:,}", "", f"top {len(tr.drivers)} drivers"),
        stat_card("Escalation rate", f"{tr.escalation_rate}%",
                  "good" if tr.escalation_rate >= 20 else "warn" if tr.escalation_rate >= 5 else "bad",
                  "alerts that became cases"),
        stat_card("Tune candidates", len(noisy), "warn" if noisy else "good",
                  "noisy / low-escalation drivers"),
    ])
    rows = [{
        "Alert / rule": d.name,
        "Alerts": d.count,
        "% of all": f"{d.pct_of_all}%",
        "Avg risk": d.avg_risk,
        "Escalation %": f"{d.escalation_rate}%",
        "Priority": d.top_priority,
        "Rec": d.recommendation,
    } for d in tr.drivers]
    note = (
        "Mouton analog: rank alert drivers by volume vs. how rarely they escalate to a "
        "case. High volume + low escalation + low risk = noise (tune/disable) -- the NSA "
        "stand-in for NotableReductionOnDeletion. Recommendations are mechanical; a TAM "
        "confirms against the account before disabling a rule."
    )
    panels = (
        panel("Overall escalation", coverage_bar(tr.escalation_rate) +
              f'<div class="footer-note">{tr.escalated_alerts} of {tr.total_alerts} alerts '
              f'escalated to a case ({tr.escalation_rate}%). {tr.enabled_rules} rules enabled.</div>',
              "how much of the alert volume is actionable")
        + panel(f"Top alert drivers ({len(rows)})", data_table(rows, "tblTune"), note)
    )
    meta = [tr.tenant or "—", f"last {tr.lookback_days}d", "tuning · read-only"]
    return page(
        f"NYMM · {tr.tenant or ''} · Detection Tuning",
        f"Not Your Momma's Mouton — NSA tuning insight · last {tr.lookback_days}d",
        cards, panels, "".join(f"<div>{m}</div>" for m in meta), initial_theme="dark",
    )

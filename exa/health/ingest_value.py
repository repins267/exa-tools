"""Ingest value / overage analysis.

Top log sources by ingest volume vs. whether they feed enabled detection rules,
so a TAM can find high-volume, low-value sources to trim during an overage. All
read-only. Packages the analysis validated live on baystate.

Signals per source (vendor/product):
  - events in the window (volume) and % of total ingest
  - unparsed count / % (unparsed logs are billed but feed no detection)
  - the activity_types it emits, and whether any is consumed by an ENABLED rule
  - a mechanical Keep / Review / Trim recommendation (a TAM applies judgement)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from exa.client import ExaClient


@dataclass
class SourceIngest:
    vendor: str = ""
    product: str = ""
    events: int = 0
    unparsed: int = 0
    activity_types: list[str] = field(default_factory=list)
    feeds_rules: bool = False
    pct_of_ingest: float = 0.0
    recommendation: str = "Keep"

    @property
    def source(self) -> str:
        s = f"{self.vendor} · {self.product}".strip(" ·")
        return s or "(unattributed)"

    @property
    def unparsed_pct(self) -> float:
        return round(100 * self.unparsed / self.events, 1) if self.events else 0.0


@dataclass
class IngestValue:
    tenant: str | None = None
    lookback_days: int = 7
    entitled_gb: float | None = None
    consumed_gb_today: float | None = None
    avg_gb: float | None = None
    days_over: int | None = None
    days_total: int | None = None
    total_events: int = 0
    unparsed_total: int = 0
    enabled_rules: int = 0
    rule_activity_count: int = 0
    sources: list[SourceIngest] = field(default_factory=list)
    truncated: bool = False
    note: str = ""

    @property
    def unparsed_pct(self) -> float:
        return round(100 * self.unparsed_total / self.total_events, 2) if self.total_events else 0.0


def _classify(pct: float, feeds_rules: bool, unparsed_pct: float) -> str:
    """Mechanical Keep/Review/Trim. A TAM overrides with account knowledge."""
    if unparsed_pct >= 50:
        return "Trim"  # mostly billed waste
    if not feeds_rules and pct >= 1:
        return "Trim"  # meaningful volume feeding no enabled rule
    if not feeds_rules:
        return "Review"  # small, no rule value
    if pct >= 20:
        return "Review"  # feeds rules but dominates ingest -- is all of it needed?
    return "Keep"


def collect_ingest_value(
    client: "ExaClient", *, lookback_days: int = 7, top_n: int = 15
) -> IngestValue:
    """Read-only ingest-value analysis. Never writes."""
    from exa.detection.rules import get_detection_rules
    from exa.health.consumption import get_license_details
    from exa.search.events import search_events

    iv = IngestValue(tenant=getattr(client, "tenant", None), lookback_days=lookback_days)

    # license: entitled vs consumed, days over
    try:
        lic = get_license_details(client)
        d = lic.get("logIngestionDetails", lic) if isinstance(lic, dict) else {}
        iv.entitled_gb = d.get("entitledIngestGbPerDay")
        iv.consumed_gb_today = d.get("consumedIngestGbForToday")
        hist = d.get("historicalLogIngestionInGb") or []
        vals = [
            h.get("ingestGb")
            for h in hist
            if isinstance(h, dict) and h.get("ingestGb") is not None
        ][-lookback_days:]
        if vals:
            iv.avg_gb = round(sum(vals) / len(vals), 1)
            iv.days_total = len(vals)
            if iv.entitled_gb:
                iv.days_over = sum(1 for v in vals if v > iv.entitled_gb)
    except Exception as exc:
        iv.note = f"license unavailable: {exc}"

    # enabled rules -> the set of activity_types they consume
    rule_acts: set[str] = set()
    try:
        for r in get_detection_rules(client):
            if r.get("isEnabled") is True:
                iv.enabled_rules += 1
                for ev in r.get("applicableEvents") or []:
                    rule_acts.update(str(a) for a in (ev.get("activity_type") or []))
    except Exception as exc:
        iv.note = (iv.note + " | " if iv.note else "") + f"rules unavailable: {exc}"
    iv.rule_activity_count = len(rule_acts)

    # volume + parsed by source
    agg: dict[tuple[str, str], dict] = {}
    try:
        rows = search_events(
            client, "",
            fields=["vendor", "product", "parsed", "count(id)"],
            group_by=["vendor", "product", "parsed"],
            lookback_days=lookback_days, limit=2000,
        )
        iv.truncated = isinstance(rows, list) and len(rows) >= 2000
        for r in rows or []:
            key = (str(r.get("vendor") or ""), str(r.get("product") or ""))
            n = int(r.get("f0_") or 0)
            a = agg.setdefault(key, {"events": 0, "unparsed": 0, "acts": set()})
            a["events"] += n
            pv = r.get("parsed")
            if pv is False or str(pv).lower() in ("false", "no"):
                a["unparsed"] += n
    except Exception as exc:
        iv.note = (iv.note + " | " if iv.note else "") + f"volume query failed: {exc}"

    # activity_types by source
    try:
        rows = search_events(
            client, "",
            fields=["vendor", "product", "activity_type", "count(id)"],
            group_by=["vendor", "product", "activity_type"],
            lookback_days=lookback_days, limit=4000,
        )
        for r in rows or []:
            key = (str(r.get("vendor") or ""), str(r.get("product") or ""))
            act = r.get("activity_type")
            if key in agg and act:
                agg[key]["acts"].add(str(act))
    except Exception:
        pass

    iv.total_events = sum(a["events"] for a in agg.values())
    iv.unparsed_total = sum(a["unparsed"] for a in agg.values())

    srcs: list[SourceIngest] = []
    for (vendor, product), a in agg.items():
        s = SourceIngest(
            vendor=vendor, product=product, events=a["events"], unparsed=a["unparsed"],
            activity_types=sorted(a["acts"]), feeds_rules=bool(a["acts"] & rule_acts),
        )
        s.pct_of_ingest = round(100 * s.events / iv.total_events, 2) if iv.total_events else 0.0
        s.recommendation = _classify(s.pct_of_ingest, s.feeds_rules, s.unparsed_pct)
        srcs.append(s)
    srcs.sort(key=lambda x: -x.events)
    iv.sources = srcs[:top_n]
    return iv


def ingest_value_summary(iv: IngestValue) -> dict:
    """JSON-friendly summary for the MCP tool."""
    return {
        "tenant": iv.tenant,
        "lookback_days": iv.lookback_days,
        "license": {
            "entitled_gb_per_day": iv.entitled_gb,
            "consumed_gb_today": iv.consumed_gb_today,
            "avg_gb_per_day": iv.avg_gb,
            "days_over": iv.days_over,
            "days_total": iv.days_total,
        },
        "total_events": iv.total_events,
        "unparsed_total": iv.unparsed_total,
        "unparsed_pct": iv.unparsed_pct,
        "enabled_rules": iv.enabled_rules,
        "rule_activity_types": iv.rule_activity_count,
        "sampled": iv.truncated,
        "note": iv.note or None,
        "sources": [
            {
                "source": s.source,
                "events": s.events,
                "pct_of_ingest": s.pct_of_ingest,
                "unparsed_pct": s.unparsed_pct,
                "feeds_enabled_rule": s.feeds_rules,
                "recommendation": s.recommendation,
            }
            for s in iv.sources
        ],
    }


def render_ingest_value(iv: IngestValue) -> str:
    """Branded self-contained HTML report for an IngestValue analysis."""
    from exa.report import report_from_spec

    over = (
        iv.avg_gb is not None and iv.entitled_gb is not None and iv.avg_gb > iv.entitled_gb
    )
    cards = [
        {"label": "Tenant", "value": iv.tenant or "—", "hint": f"last {iv.lookback_days}d"},
        {"label": "Entitled", "value": f"{iv.entitled_gb} GB/day" if iv.entitled_gb else "—"},
        {"label": "Avg consumed", "value": f"{iv.avg_gb} GB/day" if iv.avg_gb is not None else "—",
         "status": "bad" if over else "good",
         "hint": (f"{iv.days_over}/{iv.days_total} days over" if iv.days_over is not None else "")},
        {"label": "Unparsed", "value": f"{iv.unparsed_pct}%",
         "status": "bad" if iv.unparsed_pct >= 5 else "warn" if iv.unparsed_pct >= 1 else "good",
         "hint": f"{iv.unparsed_total:,} events"},
        {"label": "Total events", "value": f"{iv.total_events:,}", "hint": f"last {iv.lookback_days}d"},
        {"label": "Enabled rules", "value": iv.enabled_rules, "hint": f"{iv.rule_activity_count} activity types"},
    ]
    table = [
        {
            "Source": s.source,
            "Events": f"{s.events:,}",
            "% ingest": f"{s.pct_of_ingest}%",
            "Unparsed %": f"{s.unparsed_pct}%",
            "Feeds a rule?": "Yes" if s.feeds_rules else "No",
            "Rec": s.recommendation,
        }
        for s in iv.sources
    ]
    trim = [s.source for s in iv.sources if s.recommendation == "Trim"]
    note = (
        "Recommendations are mechanical: Trim = high volume feeding no enabled rule, or mostly "
        "unparsed; Review = feeds rules but dominates ingest (is all of it needed?) or low-value; "
        "Keep = feeds rules at reasonable volume. A TAM applies account knowledge."
        + (f" Trim candidates: {', '.join(trim)}." if trim else "")
    )
    spec = {
        "title": f"exa-tools · {iv.tenant or ''} · Ingest Value",
        "subtitle": f"Overage analysis · last {iv.lookback_days}d · read-only",
        "cards": cards,
        "sections": [
            {"title": f"Top sources by ingest value ({len(table)})", "table": table, "note": note}
        ],
        "meta": [iv.tenant or "—", f"last {iv.lookback_days}d", "exa-tools · read-only"],
    }
    return report_from_spec(spec)

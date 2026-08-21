"""Deep-dive on a single log source: what it emits and whether it earns its ingest.

Packages the manual "dig into Check Point" flow (top msg_types, action mix,
activity types, parsed ratio, and which ENABLED rules consume it) into one
read-only call, so a TAM can judge value vs waste without six hand-built queries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from exa.client import ExaClient


@dataclass
class SourceDetail:
    tenant: str | None = None
    vendor: str = ""
    product: str = ""
    lookback_days: int = 7
    total_events: int = 0
    unparsed: int = 0
    msg_types: list[tuple[str, int]] = field(default_factory=list)
    actions: list[tuple[str, int]] = field(default_factory=list)
    activity_types: list[tuple[str, int]] = field(default_factory=list)
    feeding_rules: list[str] = field(default_factory=list)
    feeding_rule_types: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def source(self) -> str:
        return f"{self.vendor} · {self.product}".strip(" ·")

    @property
    def unparsed_pct(self) -> float:
        return round(100 * self.unparsed / self.total_events, 1) if self.total_events else 0.0


def collect_source_detail(
    client: "ExaClient", vendor: str, product: str = "", *, lookback_days: int = 7, top: int = 15
) -> SourceDetail:
    """Read-only breakdown of one source. Never writes."""
    from exa.detection.rules import get_detection_rules
    from exa.search.events import search_events

    sd = SourceDetail(
        tenant=getattr(client, "tenant", None), vendor=vendor, product=product,
        lookback_days=lookback_days,
    )
    filt = f'vendor:"{vendor}"' + (f' product:"{product}"' if product else "")

    def agg(field_name: str) -> list[tuple[str, int]]:
        try:
            rows = search_events(
                client, filt, fields=[field_name, "count(id)"], group_by=[field_name],
                lookback_days=lookback_days, limit=200,
            )
            out = [(str(r.get(field_name)), int(r.get("f0_") or 0)) for r in rows or []]
            return sorted(out, key=lambda x: -x[1])
        except Exception as exc:
            sd.note = (sd.note + " | " if sd.note else "") + f"{field_name}: {exc}"
            return []

    sd.msg_types = agg("msg_type")[:top]
    sd.actions = agg("action")[:top]
    sd.activity_types = agg("activity_type")[:top]
    parsed = agg("parsed")

    sd.total_events = sum(n for _, n in sd.activity_types) or sum(n for _, n in sd.msg_types)
    sd.unparsed = sum(n for v, n in parsed if str(v).lower() in ("false", "no"))

    src_acts = {a for a, _ in sd.activity_types}
    types: set[str] = set()
    try:
        for r in get_detection_rules(client):
            if r.get("isEnabled") is not True:
                continue
            racts: set[str] = set()
            for ev in r.get("applicableEvents") or []:
                racts.update(str(a) for a in (ev.get("activity_type") or []))
            if racts & src_acts:
                sd.feeding_rules.append(str(r.get("name")))
                if r.get("type"):
                    types.add(str(r.get("type")))
    except Exception as exc:
        sd.note = (sd.note + " | " if sd.note else "") + f"rules: {exc}"
    sd.feeding_rule_types = sorted(types)
    return sd


def render_source_detail(sd: SourceDetail) -> str:
    """Branded, self-contained HTML deep-dive report for one source."""
    from exa.report import coverage_bar, data_table, page, panel, stat_card

    total = sd.total_events or 1
    parsed_pct = round(100 - sd.unparsed_pct, 1)

    cards = "".join([
        stat_card("Tenant", sd.tenant or "—", "", f"last {sd.lookback_days}d"),
        stat_card("Source", sd.source or "—", "", "top talker deep-dive"),
        stat_card("Events", f"{sd.total_events:,}", "", f"last {sd.lookback_days}d"),
        stat_card("Parsed", f"{parsed_pct}%",
                  "good" if parsed_pct >= 95 else "warn" if parsed_pct >= 80 else "bad",
                  f"{sd.unparsed_pct}% unparsed"),
        stat_card("Feeds rules", len(sd.feeding_rules),
                  "good" if sd.feeding_rules else "warn",
                  "enabled rules that consume it"),
    ])

    def tbl(rows, label, tid):
        data = [{label: v, "Events": f"{n:,}", "% of source": f"{round(100 * n / total, 1)}%"}
                for v, n in rows]
        return data_table(data, tid) if data else '<div class="footer-note">none</div>'

    if sd.feeding_rules:
        rlist = (f'<div class="footer-note">Rule types: '
                 f'{", ".join(sd.feeding_rule_types) or "—"}</div>'
                 + "<ul>" + "".join(f"<li>{r}</li>" for r in sd.feeding_rules[:20]) + "</ul>"
                 + (f'<div class="footer-note">+{len(sd.feeding_rules) - 20} more</div>'
                    if len(sd.feeding_rules) > 20 else ""))
    else:
        rlist = ('<div class="empty">No enabled rule consumes this source\'s activity_types — '
                 'high volume here is ingest cost with no detection return. A Trim candidate '
                 'unless kept for compliance/hunting.</div>')

    verdict = (
        "Value read: this source feeds "
        f"{len(sd.feeding_rules)} enabled rule(s). "
        + ("Its volume earns detection return. " if sd.feeding_rules
           else "Its volume earns NO detection return today. ")
        + (f"{sd.unparsed_pct}% is unparsed — that share is ingest you pay for but can't detect on; "
           "check the parser before trimming. " if sd.unparsed_pct >= 5 else "")
        + "Pair with ingest_value to weigh volume vs. entitlement. Read-only — recommendations "
        "are mechanical; confirm against the account before trimming a source."
    )

    panels = "".join([
        panel("Parsed ratio", coverage_bar(parsed_pct) +
              f'<div class="footer-note">{sd.total_events - sd.unparsed:,} of {sd.total_events:,} '
              f'events parsed ({parsed_pct}%). {sd.unparsed:,} unparsed.</div>',
              "unparsed volume is ingest you can't detect on", half=True),
        panel(f"Rules this source feeds ({len(sd.feeding_rules)})", rlist,
              "enabled rules consuming its activity_types", half=True),
        panel(f"Top message types ({len(sd.msg_types)})", tbl(sd.msg_types, "msg_type", "tMsg"),
              "what the source is actually sending", half=True),
        panel("Action mix", tbl(sd.actions, "action", "tAct"),
              "e.g. Drop vs Accept — noise vs signal", half=True),
        panel(f"Activity types ({len(sd.activity_types)})",
              tbl(sd.activity_types, "activity_type", "tAct2"),
              "the CIM2 activities rules match on"),
        panel("Verdict", f'<div class="footer-note">{verdict}</div>'
              + (f'<div class="disc">note: {sd.note}</div>' if sd.note else "")),
    ])
    meta = [sd.tenant or "—", sd.source, f"last {sd.lookback_days}d", "source deep-dive · read-only"]
    return page(
        f"exa-tools · {sd.tenant or ''} · Source Deep-Dive",
        f"{sd.source} · last {sd.lookback_days}d",
        cards, panels, "".join(f"<div>{m}</div>" for m in meta), initial_theme="dark",
    )


def source_detail_summary(sd: SourceDetail) -> dict:
    """JSON-friendly summary for the MCP tool."""
    total = sd.total_events or 1

    def pct(rows):
        return [{"value": v, "events": n, "pct": round(100 * n / total, 1)} for v, n in rows]

    return {
        "tenant": sd.tenant,
        "source": sd.source,
        "lookback_days": sd.lookback_days,
        "total_events": sd.total_events,
        "unparsed_pct": sd.unparsed_pct,
        "msg_types": pct(sd.msg_types),
        "actions": pct(sd.actions),
        "activity_types": pct(sd.activity_types),
        "feeds_enabled_rules": len(sd.feeding_rules),
        "feeding_rule_types": sd.feeding_rule_types,
        "feeding_rules_sample": sd.feeding_rules[:20],
        "note": sd.note or None,
    }

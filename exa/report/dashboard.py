"""Preview an Exabeam dashboard .config as a branded, chart-rendered mockup.

Exabeam dashboards import only through the UI (Dashboards -> Import), not the API.
`exa aillm dashboard` (and hand-built dashboards) produce a .config JSON of panels.
This draws each panel as its actual visualization (bar / pie / table), laid out
like a dashboard, so an analyst can SEE it, iterate on the JSON in Claude, and
export the edited .config for the manual import.

When an authenticated client is passed, each panel is populated with SAMPLE data
from the tenant (group-by the panel's dimension over its lookback). The panel's
context-table filter is approximated (the Exabeam UI filter format is not EQL), so
the numbers are illustrative of shape, not the exact scoped values.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

_SLICE_COLORS = ["#4CDB00", "#27B2FF", "#B383FF", "#fbbf24", "#fb7185", "#9fb1c6", "#009D00", "#8300D8"]


def _viz(el: dict) -> str:
    return str((el.get("vis_config") or {}).get("type") or el.get("type") or "table")


def _dims(fields: list) -> list[str]:
    out = []
    for f in fields or []:
        name = str(f)
        if name.endswith("count") or name == "event.count":
            continue
        out.append(name.split(".", 1)[-1] if name.startswith("event.") else name)
    return out


def _lookback(el: dict) -> int:
    expr = json.dumps(el)
    m = re.search(r"approx_log_time[^0-9]{0,6}(\d+)\s*day", expr, re.I)
    return int(m.group(1)) if m else 30


def _esc_local(v) -> str:
    from exa.report.theme import _esc
    return _esc(v)


def _bar(pairs: list[tuple[str, int]]) -> str:
    mx = max((v for _, v in pairs), default=1) or 1
    rows = "".join(
        f'<div class="row"><div class="lbl" title="{_esc_local(l)}">{_esc_local(l)}</div>'
        f'<div class="track"><div class="fill" style="width:{round(100 * v / mx, 1)}%"></div></div>'
        f'<div class="val">{v:,}</div></div>'
        for l, v in pairs
    )
    return f'<div class="chart">{rows}</div>'


def _pie(pairs: list[tuple[str, int]]) -> str:
    total = sum(v for _, v in pairs) or 1
    stops, legend, acc = [], [], 0
    for i, (label, v) in enumerate(pairs):
        c = _SLICE_COLORS[i % len(_SLICE_COLORS)]
        start = acc / total * 100
        acc += v
        end = acc / total * 100
        stops.append(f"{c} {start:.1f}% {end:.1f}%")
        legend.append(
            f'<div class="r"><span class="sw" style="background:{c}"></span>'
            f'{_esc_local(label)} — {round(100 * v / total, 1)}%</div>'
        )
    disc = f'<div class="disc" style="background:conic-gradient({",".join(stops)})"></div>'
    return f'<div class="pie">{disc}<div class="legend">{"".join(legend)}</div></div>'


def _text_of(el: dict) -> str:
    t = el.get("text") or (el.get("vis_config") or {}).get("text") or el.get("body") or ""
    return re.sub(r"[#*_>`]", "", str(t)).strip() or "Section"


def _render_panel(el: dict, client: "ExaClient | None", limit: int) -> str:
    from exa.report.theme import data_table, panel

    title = el.get("title") or "(untitled)"
    viz = _viz(el)
    dims = _dims(el.get("fields") or [])
    lb = _lookback(el)
    sub = f"{viz} · {', '.join(dims) or '—'} · {lb}d · SAMPLE"

    if not client:
        return panel(title, '<div class="empty">no tenant connected — layout only</div>', sub, half=True)
    if not dims:
        return panel(title, '<div class="empty">no chart dimension</div>', sub, half=True)

    from exa.search.events import search_events

    try:
        if "table" in viz or len(dims) > 2:
            rows = search_events(client, "", fields=[*dims, "count(id)"], group_by=dims,
                                 lookback_days=lb, limit=200)
            data = [{**{d: r.get(d) for d in dims}, "count": r.get("f0_")} for r in (rows or [])]
            data.sort(key=lambda x: -(x.get("count") or 0))
            chart = (data_table(data[:15], f"t{id(el) & 0xffff}") if data
                     else '<div class="empty">no data in window</div>')
        else:
            primary = dims[0]
            rows = search_events(client, "", fields=[primary, "count(id)"], group_by=[primary],
                                 lookback_days=lb, limit=200)
            pairs = [(str(r.get(primary)), int(r.get("f0_") or 0)) for r in (rows or [])]
            pairs = [p for p in pairs if p[0] and p[0] != "None"]
            pairs.sort(key=lambda x: -x[1])
            pairs = pairs[:limit]
            if not pairs:
                chart = '<div class="empty">no data in window</div>'
            elif "pie" in viz:
                chart = _pie(pairs)
            else:
                chart = _bar(pairs)
    except Exception as exc:
        chart = f'<div class="empty">query failed: {_esc_local(str(exc)[:70])}</div>'
    return panel(title, chart, sub, half=True)


def dashboard_preview_html(
    config: dict[str, Any], client: "ExaClient | None" = None, sample_limit: int = 8
) -> str:
    """Render a dashboard config to a branded, chart-drawn preview HTML string."""
    from exa.report.theme import _esc, page, panel, stat_card

    els = config.get("dashboardElements") or config.get("elements") or []
    vis = [e for e in els if e.get("type") == "vis"]
    texts = [e for e in els if e.get("type") == "text"]
    viz_types = sorted({_viz(e) for e in vis})
    tenant = getattr(client, "tenant", None) if client else None

    cards = "".join([
        stat_card("Dashboard", config.get("title") or "—"),
        stat_card("Panels", len(vis), "", f"{len(texts)} headers"),
        stat_card("Data", f"live: {tenant}" if tenant else "no tenant",
                  "good" if tenant else "warn",
                  "sampled · filter approx" if tenant else "layout only"),
        stat_card("Visualizations", ", ".join(viz_types) or "—"),
    ])
    body = []
    if config.get("description"):
        body.append(panel("About", f'<div class="footer-note">{_esc(config["description"])}</div>'))
    for el in els:
        if el.get("type") == "text":
            body.append(panel(_text_of(el), "", half=False))
        elif el.get("type") == "vis":
            body.append(_render_panel(el, client, sample_limit))
    body.append(panel(
        "Import & caveat",
        '<div class="footer-note">Preview only. Data is a <b>sample</b> — each panel is '
        "grouped over its lookback but its context-table filter is approximated, so counts "
        "show shape, not exact scoped values. Edit the .config and re-render to iterate; "
        "import the final file in the Exabeam UI: <b>Dashboards → Import</b>.</div>",
    ))
    meta = [config.get("title") or "dashboard", f"{len(vis)} panels",
            f"live: {tenant}" if tenant else "layout only"]
    return page(
        f"exa-tools · {config.get('title') or 'Dashboard'} · Preview",
        "Exabeam dashboard preview",
        cards, "".join(body), "".join(f"<div>{_esc(m)}</div>" for m in meta),
        initial_theme="dark",
    )

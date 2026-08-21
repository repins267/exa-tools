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


def _is_measure(name: str) -> bool:
    n = str(name).lower()
    # Match aggregate measures without tripping on dimensions that merely contain
    # "count" as a substring -- e.g. geo_src_ip_country (the "country" trap).
    return (
        n == "count"
        or n.endswith((".count", "_count", ".sum"))
        or n.startswith(("count_", "sum_", "avg_", "average_", "count(", "min_", "max_"))
        or "count(" in n
    )


def _is_time(name: str) -> bool:
    n = str(name).lower()
    return any(k in n for k in ("_date", "_hour", "_time", "timestamp", "approx_log"))


def _model_name(el: dict) -> str:
    """The panel's data model. 'datalake' = the event/search model (sampleable);
    'acm_bq' and friends = the alerts/analytics model (a different source)."""
    m = str(el.get("model") or "").strip().lower()
    if m:
        return m
    # no explicit model: infer from a DIMENSION field (skip measures like count_distinct_*)
    for f in el.get("fields") or []:
        if _is_measure(f):
            continue
        head = str(f).split(".", 1)[0].split("__", 1)[0]
        return "datalake" if head == "event" else head
    return "datalake"


def _sampleable(el: dict) -> bool:
    return _model_name(el) == "datalake"


def _split_fields(fields: list) -> tuple[list[str], list[str]]:
    """Return (dimensions, measures) with the 'event.' prefix stripped from dims."""
    dims, measures = [], []
    for f in fields or []:
        name = str(f)
        if _is_measure(name):
            measures.append(name)
        else:
            dims.append(name.split(".", 1)[-1] if name.startswith("event.") else name)
    return dims, measures


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


def _big_number(value: int, label: str = "") -> str:
    return (f'<div class="chart"><div class="value good" style="font-size:34px;font-weight:800">'
            f'{value:,}</div><div class="footer-note">{_esc_local(label)}</div></div>')


def _render_panel(el: dict, client: ExaClient | None, limit: int) -> str:
    from exa.report.theme import data_table, panel

    title = el.get("title") or "(untitled)"
    viz = _viz(el)
    fields = el.get("fields") or []
    dims, measures = _split_fields(fields)
    model = _model_name(el)
    lb = _lookback(el)
    sub = f"{viz} · {', '.join(dims) or measures and 'measure' or '—'} · {lb}d · SAMPLE"

    if not client:
        return panel(title, '<div class="empty">no tenant connected — layout only</div>', sub, half=True)
    if not _sampleable(el):
        return panel(title, f'<div class="empty">{_esc_local(model)} model — not sampled (event/datalake only)</div>', sub, half=True)

    from exa.search.events import search_events

    try:
        # single value: one measure, no dimension -> a big number
        if "single_value" in viz or (not dims and measures):
            rows = search_events(client, "", fields=["count(id)"], lookback_days=lb, limit=1, raw=False)
            n = 0
            if isinstance(rows, list) and rows:
                n = int(rows[0].get("f0_") or rows[0].get("count(id)") or 0)
            return panel(title, _big_number(n, f"events · {lb}d"), sub, half=True)

        if not dims:
            return panel(title, '<div class="empty">no chart dimension</div>', sub, half=True)

        # A geo map draws the country dimension as ranked bars; a bubble draws its
        # category dimension as bars. (heat_map / coverage_map / sankey stay tabular
        # -- a matrix or flow is not honestly a single-axis chart.)
        is_map = "custom_looker_map" in viz
        is_bubble = "bubble" in viz
        is_chart = is_map or is_bubble or any(
            k in viz for k in ("bar", "column", "area", "line", "pie")
        )
        if is_map and dims:
            # prefer a geo dimension if the panel lists one
            geo = next((d for d in dims if "geo" in d or "country" in d or "city" in d), None)
            if geo:
                dims = [geo] + [d for d in dims if d != geo]
        if is_chart and len(dims) <= 2:
            primary = dims[0]
            rows = search_events(client, "", fields=[primary, "count(id)"], group_by=[primary],
                                 lookback_days=lb, limit=200)
            pairs = [(str(r.get(primary)), int(r.get("f0_") or 0)) for r in (rows or [])]
            pairs = [p for p in pairs if p[0] and p[0] != "None"]
            if _is_time(primary):
                pairs.sort(key=lambda x: x[0])            # chronological for time-series
                pairs = pairs[-limit:]
            else:
                pairs.sort(key=lambda x: -x[1])
                pairs = pairs[:limit]
            if not pairs:
                chart = '<div class="empty">no data in window</div>'
            elif "pie" in viz:
                chart = _pie(pairs)
            else:
                chart = _bar(pairs)                        # bar / column / area / line
            return panel(title, chart, sub, half=True)

        # table / bubble / sankey / multi-dim -> table
        rows = search_events(client, "", fields=[*dims, "count(id)"], group_by=dims,
                             lookback_days=lb, limit=200)
        data = [{**{d: r.get(d) for d in dims}, "count": r.get("f0_")} for r in (rows or [])]
        data.sort(key=lambda x: -(x.get("count") or 0))
        chart = (data_table(data[:15], f"t{id(el) & 0xffff}") if data
                 else '<div class="empty">no data in window</div>')
        return panel(title, chart, sub, half=True)
    except Exception as exc:
        return panel(title, f'<div class="empty">query failed: {_esc_local(str(exc)[:70])}</div>', sub, half=True)


def dashboard_preview_html(
    config: dict[str, Any], client: ExaClient | None = None, sample_limit: int = 8
) -> str:
    """Render a dashboard config to a branded, chart-drawn preview HTML string."""
    from exa.report.theme import _esc, page, panel, stat_card

    els = config.get("dashboardElements") or config.get("elements") or []
    if not els and (config.get("fields") or config.get("vis_config")):
        single = dict(config)
        single["type"] = "vis"
        els = [single]
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


# -- .config -> shareable report ------------------------------------------------

# Customer names seen baked into shared dashboard exports. A preview renders only
# the title/description/sample-data (sample data comes from the CONNECTED tenant,
# not the customer), so scrubbing title + description de-identifies the output.
_KNOWN_CUSTOMERS = (
    "Sunpharma", "Sun Pharma", "ECZASA", "Nykaa", "MOMRA", "Momra", "NELC", "SANS",
)


def scrub_config(
    config: dict[str, Any], extra_customers: list[str] | None = None
) -> tuple[dict[str, Any], list[str]]:
    """Return (scrubbed_copy, notes): customer identity removed from title/description.

    Strips a leading ``Customer - ``/``Customer _ `` prefix and replaces any remaining
    whole-word customer-name occurrence with ``Customer``. Does not mutate the input.
    Note: filter *values* may still reference customer domains -- irrelevant to the
    rendered preview (filters are not displayed), but review the raw .config before
    re-sharing it as a file.
    """
    import copy

    customers = [*_KNOWN_CUSTOMERS, *(extra_customers or [])]
    cfg = copy.deepcopy(config)
    notes: list[str] = []

    def _redact(text: str) -> str:
        for c in sorted(customers, key=len, reverse=True):
            text = re.sub(rf"\b{re.escape(c)}\b", "Customer", text, flags=re.I)
        return text

    title = str(cfg.get("title") or "")
    original = title
    for c in sorted(customers, key=len, reverse=True):
        for sep in (" - ", " _ ", " – ", " -", "- ", "_ ", "_", ": ", " "):
            pref = f"{c}{sep}"
            if title.lower().startswith(pref.lower()):
                title = title[len(pref):]
                break
    title = _redact(title).strip(" -_") or "Dashboard"
    if title != original:
        notes.append(f"title '{original}' -> '{title}'")
    cfg["title"] = title

    desc = str(cfg.get("description") or "")
    if desc and any(re.search(rf"\b{re.escape(c)}\b", desc, re.I) for c in customers):
        cfg["description"] = _redact(desc)
        notes.append("description redacted")

    return cfg, notes


def configs_to_gallery(
    named_configs: list[tuple[str, dict[str, Any]]],
    client: ExaClient | None = None,
    sample_limit: int = 8,
    scrub: bool = True,
    title: str = "Exabeam Dashboards — exa-tools Preview Gallery",
) -> str:
    """Render many dashboard configs into one scrollable gallery page with nav.

    Each config is previewed via ``dashboard_preview_html`` (optionally scrubbed);
    their bodies are stitched under a shared stylesheet with anchor navigation.
    """
    from exa.report.theme import _esc

    css, sections, nav = "", [], []
    for i, (name, cfg) in enumerate(named_configs):
        label = name
        if scrub:
            cfg, sn = scrub_config(cfg)
            label = cfg.get("title") or name
        try:
            preview = dashboard_preview_html(cfg, client=client, sample_limit=sample_limit)
        except Exception as exc:  # noqa: BLE001 -- one bad config never kills the gallery
            sections.append(
                f"<section id='d{i}'><h2>{_esc(label)}</h2>"
                f"<p style='color:#f87171'>render error: {_esc(str(exc)[:120])}</p></section>"
            )
            nav.append(f"<a href='#d{i}'>{_esc(label)}</a>")
            continue
        if not css:
            m = re.search(r"<style[^>]*>(.*?)</style>", preview, re.S)
            css = m.group(1) if m else ""
        bm = re.search(r"<body[^>]*>(.*?)</body>", preview, re.S)
        inner = bm.group(1) if bm else preview
        npanel = len([e for e in (cfg.get("dashboardElements") or []) if e.get("type") == "vis"])
        meta_span = f"<span style='opacity:.5;font-size:14px'>· {npanel} panels</span>"
        sections.append(
            f"<section id='d{i}'><h2>{_esc(label)} {meta_span}</h2>{inner}</section>"
        )
        nav.append(f"<a href='#d{i}'>{_esc(label)}</a>")

    navhtml = " · ".join(nav)
    tenant = getattr(client, "tenant", None) if client else None
    data_line = (f"live sample from {tenant}" if tenant else "layout only (no tenant)")
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{_esc(title)}</title><style>{css}\n"
        "body{padding:0}.gwrap{max-width:1100px;margin:0 auto;padding:24px}"
        ".gnav{position:sticky;top:0;background:#0d0f13;border-bottom:1px solid #2a2f36;"
        "padding:12px 24px;font-size:13px;line-height:1.9;z-index:10}"
        ".gnav a{color:#27B2FF;text-decoration:none;margin-right:4px}"
        ".gnav a:hover{text-decoration:underline}"
        "section{border-top:1px solid #2a2f36;padding:22px 0;margin-top:22px}"
        "section h2{font-size:20px;margin:0 0 14px}"
        "h1.gtitle{font-size:26px;margin:0 0 4px}</style></head>"
        f"<body><div class='gnav'><b>Dashboards</b> — {navhtml}</div>"
        f"<div class='gwrap'><h1 class='gtitle'>{_esc(title)}</h1>"
        f"<p style='color:#9aa3ad;font-size:13px'>{len(named_configs)} dashboards via exa-tools "
        f"render_dashboard · {data_line} · panels approximate the context-table filter (SAMPLE)"
        f"{' · customer identity scrubbed' if scrub else ''}.</p>"
        f"{''.join(sections)}</div></body></html>"
    )

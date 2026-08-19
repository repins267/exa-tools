"""Preview an Exabeam dashboard .config as branded HTML.

Exabeam dashboards import only through the UI (Dashboards -> Import), not the API.
`exa aillm dashboard` (and hand-built dashboards) produce a .config JSON of panels.
This renders that JSON to a reviewable preview so an analyst can see the shape,
iterate on it in Claude, and export the edited .config for the manual import.

Not a live dashboard -- it shows each panel's title, visualization, the fields it
groups/plots, its filter, and row limit, grouped under the config's text panels.
"""

from __future__ import annotations

import json
import re
from typing import Any


def _readable_filter(el: dict[str, Any]) -> str:
    """Best-effort human summary of a panel's filter."""
    parts: list[str] = []
    filters = el.get("filters") or {}
    if isinstance(filters, dict):
        for k, v in filters.items():
            parts.append(f"{k}={v}")
    expr = el.get("filter_expression") or ""
    m = re.search(r"#EXPRESSION-START#(.*?)#EXPRESSION-END#", expr, re.S)
    if m:
        try:
            rules = json.loads(m.group(1)).get("rules") or []
            for r in rules:
                fld = (r.get("field") or {}).get("name") or r.get("field")
                ex = r.get("expression")
                if fld and ex is not None:
                    parts.append(f"{fld} {ex}")
        except Exception:
            pass
    return "; ".join(parts) if parts else "—"


def _panel_fields(el: dict[str, Any]) -> str:
    fields = el.get("fields") or []
    return ", ".join(str(f) for f in fields) if fields else "—"


def _viz(el: dict[str, Any]) -> str:
    vc = el.get("vis_config") or {}
    return str(vc.get("type") or el.get("type") or "—")


def dashboard_preview_html(config: dict[str, Any]) -> str:
    """Render an Exabeam dashboard config dict to a branded preview HTML string."""
    from exa.report.theme import _esc, data_table, page, panel, stat_card

    els = config.get("dashboardElements") or config.get("elements") or []
    vis = [e for e in els if (e.get("type") == "vis")]
    texts = [e for e in els if (e.get("type") == "text")]

    # Section = a run of vis panels under the most recent text panel.
    sections: list[tuple[str, list[dict]]] = []
    current_title = "Panels"
    current_rows: list[dict] = []

    def _text_of(el: dict) -> str:
        t = el.get("text") or (el.get("vis_config") or {}).get("text") or ""
        if not t:
            # some configs carry the heading in body/title
            t = el.get("body") or ""
        return re.sub(r"[#*_>`]", "", str(t)).strip() or "Section"

    for el in els:
        if el.get("type") == "text":
            if current_rows:
                sections.append((current_title, current_rows))
                current_rows = []
            current_title = _text_of(el)
        elif el.get("type") == "vis":
            current_rows.append({
                "Panel": el.get("title") or "(untitled)",
                "Viz": _viz(el),
                "Fields": _panel_fields(el),
                "Filter": _readable_filter(el),
                "Limit": el.get("limit") or "—",
            })
    if current_rows:
        sections.append((current_title, current_rows))

    viz_types = sorted({_viz(e) for e in vis})
    cards = "".join([
        stat_card("Dashboard", config.get("title") or "—"),
        stat_card("Panels", len(vis), "", f"{len(texts)} text/header"),
        stat_card("Sections", len(sections)),
        stat_card("Visualizations", ", ".join(viz_types) or "—"),
    ])
    panels_html = ""
    desc = config.get("description")
    if desc:
        panels_html += panel("About", f'<div class="footer-note">{_esc(desc)}</div>')
    for title, rows in sections:
        panels_html += panel(title, data_table(rows, "d" + str(hash(title) & 0xffff)),
                             f"{len(rows)} panel(s)")
    panels_html += panel(
        "Import",
        '<div class="footer-note">This is a preview of the dashboard config, not a live '
        'dashboard. Edit the .config in Claude, re-preview, then import the final file in '
        'the Exabeam UI: <b>Dashboards → Import</b>. Every panel filters through a context '
        'table, so it only lights up once those tables are populated.</div>',
    )
    meta = [config.get("title") or "dashboard", f"{len(vis)} panels", "preview · not imported"]
    return page(
        f"exa-tools · {config.get('title') or 'Dashboard'} · Preview",
        "Exabeam dashboard config preview",
        cards, panels_html, "".join(f"<div>{_esc(m)}</div>" for m in meta),
        initial_theme="dark",
    )

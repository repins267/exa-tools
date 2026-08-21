"""Build a branded report from a simple spec, so any caller (a skill, an MCP
tool, the model) gets the exa-tools house style without writing HTML/CSS.

Spec shape (all optional except title):
  {
    "title": "exa-tools · Baystate · Ingest Overage",
    "subtitle": "US East · Generated 2026-08-19",
    "cards": [{"label","value","status?","hint?"}],   # status: good|warn|bad
    "sections": [
      {"title","subtitle?","note?","coverage_pct?","table?":[{col: val, ...}]}
    ],
    "meta": ["baystate · customer", "read-only"],
    "theme": "dark" | "light" | "auto"
  }
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from exa.report.theme import (
    _esc,
    coverage_bar,
    data_table,
    page,
    panel,
    stat_card,
)


def report_from_spec(spec: dict[str, Any]) -> str:
    """Render a spec dict to a complete self-contained branded HTML string."""
    cards = "".join(
        stat_card(
            c.get("label", ""),
            c.get("value", ""),
            c.get("status", ""),
            c.get("hint", ""),
        )
        for c in (spec.get("cards") or [])
    )
    panels = []
    for i, sec in enumerate(spec.get("sections") or []):
        body = ""
        cov = sec.get("coverage_pct")
        if cov is not None:
            body += coverage_bar(cov)
        if sec.get("note"):
            body += f'<div class="footer-note">{_esc(sec["note"])}</div>'
        rows = sec.get("table")
        if rows:
            body += data_table(rows, f"tbl{i}")
        if not body:
            body = '<div class="footer-note">(no content)</div>'
        panels.append(panel(sec.get("title", ""), body, sec.get("subtitle", "")))
    meta = "".join(f"<div>{_esc(m)}</div>" for m in (spec.get("meta") or []))
    return page(
        spec.get("title", "exa-tools · Report"),
        spec.get("subtitle", ""),
        cards,
        "".join(panels),
        meta,
        initial_theme=spec.get("theme", "dark"),
    )


def _default_path(spec: dict[str, Any]) -> Path:
    slug = re.sub(r"[^a-z0-9]+", "-", str(spec.get("title", "report")).lower()).strip("-")
    slug = slug[:60] or "report"
    return Path("reports") / f"{slug}.html"


def save_report(spec: dict[str, Any], output_path: str | Path | None = None) -> Path:
    """Render the spec and write the HTML file; return the path."""
    path = Path(output_path) if output_path else _default_path(spec)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report_from_spec(spec), encoding="utf-8")
    return path

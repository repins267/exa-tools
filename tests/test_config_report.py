""".config -> shareable report: PII scrub, gallery, map/bubble rendering."""

from __future__ import annotations

import exa.search.events as events_mod
from exa.report.dashboard import (
    _render_panel,
    configs_to_gallery,
    dashboard_preview_html,
    scrub_config,
)


def _panel(viz, fields, model="datalake"):
    return {"type": "vis", "title": "P", "vis_config": {"type": viz},
            "fields": fields, "model": model}


class _Client:
    tenant = "demo"


# -- scrub ---------------------------------------------------------------------

def test_scrub_strips_customer_prefix():
    for title, want in [
        ("Nykaa - AI Tools monitoring", "AI Tools monitoring"),
        ("NELC _ CloudFlare", "CloudFlare"),
        ("Momra_ Phishing", "Phishing"),
        ("SANS - Dashboard 1", "Dashboard 1"),
        ("Sunpharma - Source Code", "Source Code"),
    ]:
        out, notes = scrub_config({"title": title})
        assert out["title"] == want, (title, out["title"])
        assert notes


def test_scrub_leaves_generic_titles():
    out, notes = scrub_config({"title": "SOC - Dashboard 1"})
    assert out["title"] == "SOC - Dashboard 1"
    assert notes == []


def test_scrub_redacts_description_and_does_not_mutate_input():
    src = {"title": "X", "description": "Nykaa upload monitoring for SANS"}
    out, notes = scrub_config(src)
    assert "Nykaa" not in out["description"] and "SANS" not in out["description"]
    assert "Customer" in out["description"]
    assert src["description"] == "Nykaa upload monitoring for SANS"  # unchanged
    assert any("description" in n for n in notes)


# -- map / bubble render as bars (not tables) ----------------------------------

def test_map_panel_renders_as_bar(monkeypatch):
    rows = [{"geo_src_ip_country": "US", "f0_": 10},
            {"geo_src_ip_country": "IR", "f0_": 5}]
    monkeypatch.setattr(events_mod, "search_events", lambda *a, **k: rows)
    el = _panel("custom_looker_map", ["event.geo_src_ip_country", "event.count"])
    html = _render_panel(el, _Client(), 8)
    assert "US" in html and "IR" in html
    assert 'class="fill"' in html  # _bar markup, not a data_table


def test_bubble_panel_renders_as_bar(monkeypatch):
    rows = [{"use_cases": "Phishing", "f0_": 7}, {"use_cases": "Malware", "f0_": 3}]
    monkeypatch.setattr(events_mod, "search_events", lambda *a, **k: rows)
    el = _panel("custom_looker_bubble", ["event.use_cases", "event.count"])
    html = _render_panel(el, _Client(), 8)
    assert "Phishing" in html and 'class="fill"' in html


def test_heatmap_stays_tabular(monkeypatch):
    # a coverage/heat map must NOT be coerced to a single-axis bar
    rows = [{"tactic": "TA0001", "technique": "T1059", "f0_": 4}]
    monkeypatch.setattr(events_mod, "search_events", lambda *a, **k: rows)
    el = _panel("custom_looker_heat_map", ["event.tactic", "event.technique", "event.count"])
    html = _render_panel(el, _Client(), 8)
    assert 'class="fill"' not in html  # rendered as a table, not a bar


# -- gallery -------------------------------------------------------------------

def test_gallery_builds_with_nav_and_scrubs():
    cfgs = [
        ("a", {"title": "Nykaa - AI Tools monitoring",
               "dashboardElements": [_panel("looker_bar", ["event.app", "event.count"])]}),
        ("b", {"title": "SOC - Findings",
               "dashboardElements": [_panel("looker_pie", ["event.user", "event.count"])]}),
    ]
    html = configs_to_gallery(cfgs, client=None, scrub=True)
    assert "AI Tools monitoring" in html and "Nykaa" not in html  # scrubbed
    assert "SOC - Findings" in html
    assert "gnav" in html and html.count("<section") == 2


def test_single_preview_smoke():
    cfg = {"title": "T", "dashboardElements": [
        _panel("custom_looker_map", ["event.geo_dest_ip_country", "event.count"])]}
    html = dashboard_preview_html(cfg, client=None)  # layout only
    assert "<html" in html.lower() and "T" in html

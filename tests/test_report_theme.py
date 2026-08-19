"""Tests for the shared report theme."""

from __future__ import annotations

from exa.report import coverage_bar, data_table, page, panel, stat_card


class TestThemeComponents:
    def test_stat_card_status_class(self):
        assert 'class="value good"' in stat_card("A", "1", "good")
        assert 'class="value bad"' in stat_card("A", "1", "bad")
        # no status -> bare value class, no trailing space
        assert 'class="value"' in stat_card("A", "1")

    def test_stat_card_escapes(self):
        assert "<script>" not in stat_card("x", "<script>alert(1)</script>")

    def test_coverage_bar_clamps(self):
        assert "width:100%" in coverage_bar(250)
        assert "width:0%" in coverage_bar(-5)
        assert "width:91%" in coverage_bar(91)

    def test_data_table_headers_and_rows(self):
        rows = [{"Control": "PR.AC-1", "Status": "Covered"}]
        html = data_table(rows, "t1")
        assert "<th>Control</th>" in html and "<th>Status</th>" in html
        assert "PR.AC-1" in html and 'id="t1"' in html

    def test_data_table_empty(self):
        assert "No rows." in data_table([], "t")

    def test_data_table_truncates(self):
        rows = [{"n": i} for i in range(100)]
        html = data_table(rows, "t", max_rows=10)
        assert "Showing 10 of 100 rows." in html

    def test_panel(self):
        assert "<h2>Coverage</h2>" in panel("Coverage", "<p>x</p>")


class TestPage:
    def test_selfcontained_both_palettes_and_toggle(self):
        html = page("T", "sub")
        assert html.startswith("<!DOCTYPE html>")
        assert "#0b0f14" in html  # dark palette
        assert "#f6f8fb" in html  # light palette
        assert "__toggleTheme" in html
        # no external asset references (logo is embedded or inline text)
        assert "http://" not in html and "https://" not in html

    def test_initial_theme_attr(self):
        assert 'data-theme="light"' in page("T", initial_theme="light")
        assert 'data-theme="dark"' in page("T", initial_theme="dark")
        # auto -> no forced attribute on <html>
        assert "data-theme=" not in page("T", initial_theme="auto").split("</head>")[0].split("<body")[0].split("<style")[0]

    def test_title_escaped(self):
        assert "<img onerror" not in page('<img onerror=x>')


class TestReportFromSpec:
    def test_spec_renders_branded_html(self):
        from exa.report import report_from_spec

        spec = {
            "title": "exa-tools · Baystate · Ingest Overage",
            "subtitle": "US East · read-only",
            "cards": [
                {"label": "Entitled", "value": "500 GB/day"},
                {"label": "Consumed", "value": "518 GB/day", "status": "bad", "hint": "5/7 days over"},
            ],
            "sections": [
                {"title": "Top sources", "coverage_pct": 59,
                 "table": [{"Source": "Check Point NGFW", "% of ingest": "59.3%", "Rec": "Trim"}]},
            ],
            "meta": ["baystate · customer", "read-only"],
        }
        html = report_from_spec(spec)
        assert html.startswith("<!DOCTYPE html>")
        assert "logo-dark" in html and "__toggleTheme" in html  # branded + toggle
        assert "Check Point NGFW" in html and "59.3%" in html
        assert 'data-theme="dark"' in html

    def test_save_report_writes_file(self, tmp_path):
        from exa.report import save_report

        out = tmp_path / "r.html"
        p = save_report({"title": "T", "cards": [], "sections": []}, out)
        assert p == out and out.exists()
        assert out.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


class TestIngestValue:
    def test_classify(self):
        from exa.health.ingest_value import _classify
        assert _classify(60, True, 80) == "Trim"     # mostly unparsed
        assert _classify(5, False, 0) == "Trim"      # volume, no rule
        assert _classify(0.2, False, 0) == "Review"  # tiny, no rule
        assert _classify(30, True, 0) == "Review"    # dominates but feeds rules
        assert _classify(3, True, 0) == "Keep"

    def test_summary_shape(self):
        from exa.health.ingest_value import IngestValue, SourceIngest, ingest_value_summary
        iv = IngestValue(tenant="t", total_events=100, sources=[
            SourceIngest(vendor="V", product="P", events=60, feeds_rules=False, pct_of_ingest=60.0, recommendation="Trim")])
        out = ingest_value_summary(iv)
        assert out["tenant"] == "t"
        assert out["sources"][0]["recommendation"] == "Trim"
        assert out["sources"][0]["feeds_enabled_rule"] is False


class TestSourceDetail:
    def test_summary_pcts_and_shape(self):
        from exa.health.source_detail import SourceDetail, source_detail_summary
        sd = SourceDetail(tenant="t", vendor="Check Point", product="NGFW",
                          total_events=100, unparsed=0,
                          actions=[("accept", 90), ("drop", 10)],
                          activity_types=[("network-traffic", 100)],
                          feeding_rules=["R1", "R2"], feeding_rule_types=["factFeature"])
        out = source_detail_summary(sd)
        assert out["source"] == "Check Point · NGFW"
        assert out["actions"][0] == {"value": "accept", "events": 90, "pct": 90.0}
        assert out["feeds_enabled_rules"] == 2
        assert out["activity_types"][0]["pct"] == 100.0

    def test_render_is_branded_self_contained_html(self):
        from exa.health.source_detail import SourceDetail, render_source_detail
        sd = SourceDetail(tenant="baystate", vendor="Check Point", product="NGFW",
                          total_events=100, unparsed=5,
                          msg_types=[("Log", 100)],
                          actions=[("accept", 90), ("drop", 10)],
                          activity_types=[("network-traffic", 100)],
                          feeding_rules=["R1"], feeding_rule_types=["Correlation"])
        html = render_source_detail(sd)
        assert html.lstrip().startswith("<")
        assert "http://" not in html and "src=\"http" not in html  # self-contained
        assert "Check Point · NGFW" in html
        assert "baystate" in html
        assert "Value read" in html  # verdict present

    def test_render_flags_source_with_no_rules(self):
        from exa.health.source_detail import SourceDetail, render_source_detail
        sd = SourceDetail(tenant="t", vendor="Zscaler", total_events=100,
                          activity_types=[("web-request", 100)], feeding_rules=[])
        html = render_source_detail(sd)
        assert "no detection return" in html.lower() or "Trim candidate" in html


class TestDashboardPreview:
    def test_renders_panels_and_sections(self):
        from exa.report.dashboard import dashboard_preview_html
        cfg = {
            "title": "AI/LLM Landscape",
            "description": "demo",
            "dashboardElements": [
                {"type": "text", "text": "## Shadow AI"},
                {"type": "vis", "title": "Unsanctioned AI domains",
                 "fields": ["event.web_domain", "event.count"],
                 "filters": {"event.category": "AI"}, "limit": "100",
                 "vis_config": {"type": "table"}},
            ],
        }
        html = dashboard_preview_html(cfg)  # no client -> layout only
        assert html.startswith("<!DOCTYPE html>")
        assert "Unsanctioned AI domains" in html          # panel title
        assert "Shadow AI" in html                        # section header
        assert "web_domain" in html                       # dimension in subtitle
        assert "layout only" in html                      # no-tenant state
        assert "Dashboards" in html and "Import" in html  # import note
        assert "http://" not in html and "https://" not in html  # self-contained

    def test_bar_and_pie_helpers(self):
        from exa.report.dashboard import _bar, _pie
        bar = _bar([("a", 10), ("b", 5)])
        assert 'class="fill"' in bar and "width:100.0%" in bar
        pie = _pie([("a", 3), ("b", 1)])
        assert "conic-gradient(" in pie and "75.0%" in pie

    def test_empty_config_safe(self):
        from exa.report.dashboard import dashboard_preview_html
        html = dashboard_preview_html({"title": "Empty"})
        assert html.startswith("<!DOCTYPE html>")


class TestAiDomainLookup:
    def test_lookup_shape(self):
        from unittest.mock import patch
        from exa.aillm import reference
        class R:
            public_domains=[{"key":"chat.openai.com","risk":"medium"}]
            web_domains=[]; applications=[]
        with patch.object(reference, "load_reference_data", return_value=R()):
            out=reference.lookup_ai_domains(["chat.openai.com","foo.example.com"])
        assert out[0]["known_ai"] is True and out[0]["risk"]=="medium"
        assert out[1]["known_ai"] is False

    def test_parent_domain_match(self):
        from unittest.mock import patch
        from exa.aillm import reference
        class R:
            public_domains=[{"key":"openai.com","risk":"high"}]
            web_domains=[]; applications=[]
        with patch.object(reference,"load_reference_data",return_value=R()):
            out=reference.lookup_ai_domains(["chat.openai.com"])
        assert out[0]["known_ai"] is True and out[0]["matched"]=="openai.com"


class TestSocKpis:
    def test_kpi_rollup(self):
        from unittest.mock import patch
        from exa.case import soc_kpis as m
        now_us = 1787000000_000000
        cases = [
            {"stage": "CLOSED", "priority": "HIGH", "assignee": "alice", "queue": "T1",
             "name": "R1", "user": "u1", "caseCreationTimestamp": now_us,
             "lastModifiedTimestamp": now_us + 3600_000000},  # +1h
            {"stage": "NEW", "priority": "CRITICAL", "assignee": "Unassigned", "queue": "T1",
             "name": "R2", "user": "u2", "caseCreationTimestamp": now_us},
        ]
        with patch("exa.case.cases.search_cases", return_value=cases):
            k = m.collect_soc_kpis(object(), lookback_days=30)
        assert k.opened == 2 and k.closed == 1
        assert k.close_rate == 50.0
        assert k.mttr_hours == 1.0                       # the one closed case took ~1h
        assert dict(k.by_priority)["CRITICAL"] == 1
        assert dict(k.by_assignee)["alice"] == 1

    def test_ts_normalizes_micros(self):
        from exa.case.soc_kpis import _ts_s
        assert abs(_ts_s(1787000000_000000) - 1787000000) < 1  # micro -> sec
        assert abs(_ts_s(1787000000) - 1787000000) < 1          # already sec


class TestNymmTuning:
    def test_classify_and_rollup(self):
        from unittest.mock import patch
        from exa.case import tuning as t
        alerts = (
            [{"name": "Noisy", "riskScore": 20, "priority": "MEDIUM"}] * 60 +  # 60% no escalation
            [{"name": "Real", "riskScore": 90, "priority": "CRITICAL", "caseId": "c1"}] * 40
        )
        with patch("exa.case.alerts.search_alerts", return_value=alerts), \
             patch("exa.detection.rules.get_detection_rules", return_value=[]):
            tr = t.collect_tuning(object(), lookback_days=30)
        by = {d.name: d for d in tr.drivers}
        assert by["Noisy"].recommendation == "Tune / disable"   # 60% vol, 0% escalation
        assert by["Real"].recommendation == "Keep"              # escalates, high risk
        assert tr.total_alerts == 100 and tr.escalated_alerts == 40
        assert tr.escalation_rate == 40.0

    def test_report_is_nymm_branded(self):
        from exa.case.tuning import TuningReport, render_tuning
        html = render_tuning(TuningReport(tenant="t", total_alerts=1))
        assert "NYMM" in html and html.startswith("<!DOCTYPE html>")

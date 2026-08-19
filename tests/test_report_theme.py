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

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

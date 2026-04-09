"""Tests for compliance HTML report generation."""

import re

from exa.compliance.audit import AuditReport, ControlResult
from exa.compliance.report import generate_html_report


def _make_report() -> AuditReport:
    """Build a minimal AuditReport for testing."""
    return AuditReport(
        timestamp="2026-04-09T12:00:00+00:00",
        framework="NIST_CSF",
        framework_name="NIST CSF v2.0",
        lookback_days=30,
        minimum_evidence=10,
        total_leaf_controls=106,
        siem_testable_count=60,
        manual_control_count=46,
        controls_pass=45,
        controls_fail=15,
        coverage_pct=75.0,
        total_evidence=1234,
        unique_queries=38,
        control_results=[
            ControlResult(
                control_id="ID.AM-01",
                family="Identify",
                description="Hardware Asset Inventory",
                status="Pass",
                evidence_count=25,
                minimum_evidence=10,
            ),
            ControlResult(
                control_id="PR.AC-01",
                family="Protect",
                description="Access Control Policy",
                status="Fail",
                evidence_count=3,
                minimum_evidence=10,
            ),
        ],
    )


class TestHtmlContainsFrameworkName:
    def test_framework_name_in_header(self):
        html = generate_html_report(_make_report())
        assert "NIST CSF v2.0" in html

    def test_framework_name_in_title(self):
        html = generate_html_report(_make_report())
        assert "<title>" in html
        assert "NIST CSF v2.0" in html.split("<title>")[1].split("</title>")[0]


class TestHtmlContainsPassCount:
    def test_pass_count_present(self):
        html = generate_html_report(_make_report())
        assert ">45<" in html

    def test_fail_count_present(self):
        html = generate_html_report(_make_report())
        assert ">15<" in html

    def test_coverage_percent(self):
        html = generate_html_report(_make_report())
        assert "75.0%" in html


class TestHtmlContainsGapDisclaimer:
    def test_disclaimer_text(self):
        html = generate_html_report(_make_report())
        assert "gap analysis only" in html
        assert "does not represent a compliance audit" in html

    def test_disclaimer_in_styled_div(self):
        html = generate_html_report(_make_report())
        assert 'class="disc"' in html


class TestHtmlIsSelfContained:
    def test_no_external_urls(self):
        """No external http/https URLs in CSS, JS, or link tags."""
        html = generate_html_report(_make_report())
        # Find all URLs in href/src attributes
        urls = re.findall(r'(?:href|src)\s*=\s*"(https?://[^"]+)"', html)
        assert urls == [], f"External URLs found: {urls}"

    def test_no_link_stylesheet(self):
        html = generate_html_report(_make_report())
        assert "<link" not in html.lower()

    def test_no_script_src(self):
        html = generate_html_report(_make_report())
        assert '<script src' not in html.lower()


class TestHtmlContent:
    def test_gap_analysis_shows_failures(self):
        html = generate_html_report(_make_report())
        assert "PR.AC-01" in html
        assert "Access Control Policy" in html

    def test_full_results_shows_all(self):
        html = generate_html_report(_make_report())
        assert "ID.AM-01" in html
        assert "PR.AC-01" in html

    def test_family_coverage_table(self):
        html = generate_html_report(_make_report())
        assert "Identify" in html
        assert "Protect" in html

    def test_exabeam_brand_colors(self):
        html = generate_html_report(_make_report())
        assert "#00C389" in html
        assert "#0078D4" in html

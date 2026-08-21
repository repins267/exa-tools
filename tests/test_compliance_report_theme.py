"""The compliance report renders through the shared theme + emits CSV."""

from __future__ import annotations

from exa.compliance.audit import AuditReport, ControlResult
from exa.compliance.report import generate_html_report, report_to_csv


def _report() -> AuditReport:
    crs = [
        ControlResult("PR.AC-1", "PR", "Identities managed", "Pass", 1204, 10),
        ControlResult("RS.AN-1", "RS", "Notifications investigated", "Fail", 0, 10),
    ]
    return AuditReport(
        timestamp="2026-08-19", framework="NIST_CSF", framework_name="NIST CSF 2.0",
        lookback_days=30, minimum_evidence=10, total_leaf_controls=106,
        siem_testable_count=75, manual_control_count=31, controls_pass=68,
        controls_fail=7, coverage_pct=90.7, total_evidence=250000,
        unique_queries=120, control_results=crs,
    )


class TestComplianceReport:
    def test_html_uses_shared_theme(self):
        html = generate_html_report(_report())
        assert html.startswith("<!DOCTYPE html>")
        assert "__toggleTheme" in html           # theme toggle
        assert "logo-dark" in html and "logo-light" in html  # brand logo
        assert "NIST CSF 2.0" in html
        assert 'data-theme="dark"' in html        # dark default

    def test_html_self_contained(self):
        html = generate_html_report(_report())
        assert "http://" not in html and "https://" not in html

    def test_csv_header_and_rows(self):
        csv = report_to_csv(_report())
        lines = csv.strip().splitlines()
        assert lines[0] == "control_id,family,description,status,evidence_count,minimum_evidence"
        assert len(lines) == 3  # header + 2 controls
        assert "PR.AC-1" in csv and "RS.AN-1" in csv

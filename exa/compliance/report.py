"""Generate self-contained HTML compliance audit reports.

Produces a single-file HTML report with inline CSS — no external
dependencies. Uses Exabeam brand colors (green-to-blue gradient header).
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from exa.compliance.audit import AuditReport

_DISCLAIMER = (
    "This report measures detection rule coverage and constitutes a gap "
    "analysis only. It does not represent a compliance audit or certification."
)


def _load_logo_b64() -> str:
    """Load the embedded Exabeam logo as base64."""
    logo_path = Path(__file__).parent / "_logo_b64.txt"
    if logo_path.exists():
        return logo_path.read_text(encoding="utf-8").strip()
    return ""


def _esc(text: str) -> str:
    """Escape HTML special characters."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _card(cls: str, value: str, label: str) -> str:
    return (
        f'<div class="card {cls}">'
        f'<div class="value">{value}</div>'
        f'<div class="label">{label}</div></div>'
    )


def _coverage_bar(pct: int) -> str:
    color = (
        "#2e7d32" if pct >= 80
        else "#F0AD4E" if pct >= 50
        else "#E53E3E"
    )
    return (
        f'<div class="bar-bg">'
        f'<div class="bar" style="width:{pct}%;'
        f'background:{color}"></div></div> {pct}%'
    )


def generate_html_report(report: "AuditReport") -> str:
    """Self-contained, Exabeam-branded HTML report from an AuditReport.

    Renders through the shared exa.report theme (light/dark, embedded logo) so
    it matches every other exa-tools report.
    """
    from exa.report import coverage_bar, data_table, page, panel, stat_card

    cov = round(report.coverage_pct)
    cov_status = "good" if cov >= 80 else "warn" if cov >= 50 else "bad"
    cards = "".join([
        stat_card("Framework", report.framework_name),
        stat_card("Coverage", f"{cov}%", cov_status,
                  f"{report.controls_pass}/{report.siem_testable_count} testable controls"),
        stat_card("Pass", report.controls_pass, "good"),
        stat_card("Insufficient", report.controls_fail,
                  "bad" if report.controls_fail else "good", "below evidence threshold"),
        stat_card("SIEM-testable", report.siem_testable_count, "",
                  f"of {report.total_leaf_controls} leaf controls"),
        stat_card("Manual controls", report.manual_control_count, "", "not machine-testable"),
        stat_card("Evidence events", f"{report.total_evidence:,}", "",
                  f"last {report.lookback_days}d"),
        stat_card("Min evidence", report.minimum_evidence, "", "per control"),
    ])

    def _rows(results):
        return [{
            "Control": cr.control_id, "Family": cr.family, "Description": cr.description,
            "Status": cr.status, "Evidence": cr.evidence_count, "Min": cr.minimum_evidence,
        } for cr in results]

    cov_panel = panel(
        "Coverage",
        coverage_bar(cov) +
        f'<div class="footer-note">{report.controls_pass} of {report.siem_testable_count} '
        f'testable controls have at least {report.minimum_evidence} supporting events in the last '
        f'{report.lookback_days} days. Coverage is evidence in the window, not a checklist.</div>',
        f"{report.framework_name} â gap analysis",
    )
    failing = [cr for cr in report.control_results if cr.status != "Pass"]
    fail_body = (
        data_table(_rows(failing), "tblFail") if failing
        else '<div class="footer-note">None â all testable controls have sufficient evidence.</div>'
    )
    fail_panel = panel(f"Insufficient / failing controls ({len(failing)})", fail_body,
                       "Controls below the evidence threshold.")
    full_panel = panel(f"All results ({len(report.control_results)})",
                       data_table(_rows(report.control_results), "tblAll"),
                       "Every SIEM-testable control.")
    meta = (
        f"<div>{_esc(report.framework)}</div>"
        f"<div>Generated {_esc(report.timestamp)}</div>"
        f"<div>exa-tools Â· read-only</div>"
    )
    disc = (
        '<div class="disc" style="grid-column:span 12;color:var(--muted);'
        'font-size:11px;margin-top:2px;line-height:1.5">'
        + _esc(_DISCLAIMER) + '</div>'
    )
    return page(
        f"exa-tools · {report.framework_name}",
        f"Compliance gap analysis · Generated {report.timestamp}",
        cards, cov_panel + fail_panel + full_panel + disc, meta, initial_theme="dark",
    )


def report_to_csv(report: "AuditReport") -> str:
    """Control results as CSV text (one row per control)."""
    import csv
    import io

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["control_id", "family", "description", "status",
                "evidence_count", "minimum_evidence"])
    for cr in report.control_results:
        w.writerow([cr.control_id, cr.family, cr.description, cr.status,
                    cr.evidence_count, cr.minimum_evidence])
    return buf.getvalue()


def save_csv_report(report: "AuditReport", path: "str | Path") -> None:
    """Write the control-results CSV to disk."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(report_to_csv(report), encoding="utf-8")

def default_report_path(
    tenant: str,
    framework_name: str,
    date_str: str,
) -> Path:
    """Generate default HTML report path in reports/ folder.

    e.g. reports/sademodev22-nist-csf-v2-0-2026-04-09.html
    """
    import re

    slug = re.sub(r"[^a-z0-9]+", "-", framework_name.lower()).strip("-")
    filename = f"{tenant}-{slug}-{date_str}.html"
    return Path("reports") / filename


def save_html_report(report: AuditReport, path: str | Path) -> None:
    """Generate and save an HTML report to disk."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(generate_html_report(report), encoding="utf-8")

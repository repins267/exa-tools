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


def generate_html_report(report: AuditReport) -> str:
    """Generate a self-contained HTML report from an AuditReport."""
    parts: list[str] = []

    # Family summary
    family_stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {"pass": 0, "fail": 0, "total": 0}
    )
    for cr in report.control_results:
        family_stats[cr.family]["total"] += 1
        if cr.status == "Pass":
            family_stats[cr.family]["pass"] += 1
        else:
            family_stats[cr.family]["fail"] += 1

    # Logo
    logo_b64 = _load_logo_b64()
    logo_html = ""
    if logo_b64:
        logo_html = (
            f'<img src="data:image/png;base64,{logo_b64}" '
            f'alt="Exabeam" style="height:32px;margin-right:16px;'
            f'vertical-align:middle">'
        )

    # --- Build HTML ---
    parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(report.framework_name)} — Gap Analysis Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",
  Roboto,sans-serif;color:#333;background:#f5f6f8}}
.header{{background:linear-gradient(135deg,#009D00,#006BFF);
  color:#fff;padding:32px 40px}}
.header h1{{font-size:24px;font-weight:600;
  display:flex;align-items:center}}
.header .sub{{opacity:.9;margin-top:6px;font-size:14px}}
.wrap{{max-width:1100px;margin:0 auto;padding:24px}}
.cards{{display:grid;
  grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
  gap:16px;margin:24px 0}}
.card{{background:#fff;border-radius:8px;padding:20px;
  box-shadow:0 2px 8px rgba(0,0,0,0.08);text-align:center}}
.card .value{{font-size:32px;font-weight:800}}
.card .label{{font-size:13px;color:#666;margin-top:4px}}
.card.pass .value{{color:#2e7d32}}
.card.fail .value{{color:#c62828}}
.card.cov .value{{color:#006BFF}}
.card.ev .value{{color:#718096}}
h2{{font-size:18px;margin:28px 0 12px;color:#009D00}}
table{{width:100%;border-collapse:collapse;background:#fff;
  border-radius:8px;overflow:hidden;
  box-shadow:0 2px 8px rgba(0,0,0,0.08);margin-bottom:24px}}
th{{background:#e8f5e9;text-align:left;padding:10px 14px;
  font-size:13px;font-weight:600;color:#006400}}
td{{padding:10px 14px;border-top:1px solid #eee;font-size:13px}}
tr:hover{{background:#fafbfc}}
.status-pass{{background:#e8f5e9;color:#2e7d32;font-weight:600}}
.status-fail{{background:#ffebee;color:#c62828;font-weight:600}}
.bar-bg{{display:inline-block;width:80px;height:10px;
  background:#e9ecef;border-radius:5px;vertical-align:middle}}
.bar{{height:10px;border-radius:5px}}
.disc{{background:#fff3cd;border:1px solid #ffc107;
  border-radius:8px;padding:16px 20px;margin:32px 0;
  font-size:13px;color:#664d03}}
.ft{{text-align:center;font-size:12px;color:#999;padding:20px}}
</style>
</head>
<body>""")

    # Header with logo
    ts = _esc(report.timestamp[:19])
    fw = _esc(report.framework_name)
    parts.append(
        f'<div class="header">'
        f"<h1>{logo_html}exa-tools | {fw}</h1>"
        f'<div class="sub">Generated: {ts} UTC '
        f'| Lookback: {report.lookback_days} days</div></div>'
    )

    parts.append('<div class="wrap">')

    # Executive Summary cards
    parts.append("<h2>Executive Summary</h2>")
    parts.append('<div class="cards">')
    parts.append(_card("pass", str(report.controls_pass), "Pass"))
    parts.append(_card("fail", str(report.controls_fail), "Fail"))
    parts.append(
        _card("cov", f"{report.coverage_pct}%", "Coverage")
    )
    parts.append(
        _card("ev", f"{report.total_evidence:,}", "Evidence Events")
    )
    parts.append("</div>")

    # Coverage by Family
    parts.append("<h2>Coverage by Family</h2>")
    parts.append(
        "<table><tr><th>Family</th><th>Controls</th>"
        "<th>Pass</th><th>Fail</th><th>Coverage</th></tr>"
    )
    for fam in sorted(family_stats):
        s = family_stats[fam]
        pct = (
            round(s["pass"] / s["total"] * 100) if s["total"] else 0
        )
        parts.append(
            f"<tr><td>{_esc(fam)}</td><td>{s['total']}</td>"
            f"<td>{s['pass']}</td><td>{s['fail']}</td>"
            f"<td>{_coverage_bar(pct)}</td></tr>"
        )
    parts.append("</table>")

    # Gap Analysis (failures only)
    failures = [
        cr for cr in report.control_results if cr.status == "Fail"
    ]
    parts.append(
        f"<h2>Gap Analysis — Detection Gaps ({len(failures)})</h2>"
    )
    if failures:
        parts.append(
            "<table><tr><th>Control ID</th><th>Title</th>"
            "<th>Family</th><th>Events Found</th>"
            "<th>Min Required</th></tr>"
        )
        for cr in failures:
            parts.append(
                f"<tr><td>{_esc(cr.control_id)}</td>"
                f"<td>{_esc(cr.description)}</td>"
                f"<td>{_esc(cr.family)}</td>"
                f"<td>{cr.evidence_count}</td>"
                f"<td>{cr.minimum_evidence}</td></tr>"
            )
        parts.append("</table>")
    else:
        parts.append(
            '<p style="color:#2e7d32;font-weight:600">'
            "No detection gaps found.</p>"
        )

    # Full Results
    n = len(report.control_results)
    parts.append(f"<h2>Full Results ({n} controls)</h2>")
    parts.append(
        "<table><tr><th>Control ID</th><th>Title</th>"
        "<th>Family</th><th>Status</th><th>Events</th>"
        "<th>Min Required</th></tr>"
    )
    for cr in report.control_results:
        cls = "pass" if cr.status == "Pass" else "fail"
        parts.append(
            f'<tr><td>{_esc(cr.control_id)}</td>'
            f"<td>{_esc(cr.description)}</td>"
            f"<td>{_esc(cr.family)}</td>"
            f'<td class="status-{cls}">{cr.status}</td>'
            f"<td>{cr.evidence_count}</td>"
            f"<td>{cr.minimum_evidence}</td></tr>"
        )
    parts.append("</table>")

    # Disclaimer
    parts.append(f'<div class="disc">{_esc(_DISCLAIMER)}</div>')

    # Footer
    parts.append("</div>")
    parts.append(
        f'<div class="ft">exa-tools | {fw} '
        f"| {_esc(report.timestamp[:10])}</div>"
    )
    parts.append("</body></html>")

    return "\n".join(parts)


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

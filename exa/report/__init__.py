"""Shared report rendering — one house style across every exa-tools report.

Self-contained HTML with a light/dark toggle, embedded logo, KPI cards, panels
and data tables. Palette adapted from the ExabeamLabs MITRE Coverage Report.
"""

from exa.report.build import report_from_spec, save_report
from exa.report.theme import (
    coverage_bar,
    data_table,
    page,
    panel,
    stat_card,
)

__all__ = [
    "page", "stat_card", "panel", "data_table", "coverage_bar",
    "report_from_spec", "save_report",
]

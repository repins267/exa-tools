"""Batch-convert Splunk SPL searches from an Excel file.

Reads a spreadsheet with 'title' and 'search' columns and produces
converted Exabeam correlation rules, ready for API upload or export.

Excel format (sheet 'in'):
  Column A: title  — rule display name
  Column B: search — Splunk SPL search string

Usage:
  from exa.splunk.batch import convert_excel
  results = convert_excel("Master Enabled plays.xlsx")
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from exa.splunk.converter import convert_spl_to_exa_rule, to_api_payload


def convert_excel(
    path: str | Path,
    *,
    sheet: str = "in",
    title_col: str = "title",
    search_col: str = "search",
) -> list[dict[str, Any]]:
    """Read SPL searches from an Excel file and convert each to an Exabeam rule.

    Args:
        path: Path to the .xlsx file.
        sheet: Sheet name to read (default: "in").
        title_col: Column name for rule titles.
        search_col: Column name for SPL searches.

    Returns:
        List of converted rule dicts (from convert_spl_to_exa_rule).
        Rows where title or search is blank are skipped.
    """
    try:
        import pandas as pd  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "pandas is required for Excel conversion. "
            "Install with: pip install pandas openpyxl"
        ) from exc

    path = Path(path)
    df = pd.read_excel(path, sheet_name=sheet, dtype=str)

    # Strip whitespace from column names
    df.columns = [c.strip() for c in df.columns]

    if title_col not in df.columns:
        raise ValueError(
            f"Column '{title_col}' not found. "
            f"Available columns: {list(df.columns)}"
        )
    if search_col not in df.columns:
        raise ValueError(
            f"Column '{search_col}' not found. "
            f"Available columns: {list(df.columns)}"
        )

    results: list[dict[str, Any]] = []
    for _, row in df.iterrows():
        title = str(row[title_col]).strip() if pd.notna(row[title_col]) else ""
        search = str(row[search_col]).strip() if pd.notna(row[search_col]) else ""

        if not title or title == "nan" or not search or search == "nan":
            continue

        rule = convert_spl_to_exa_rule(title, search)
        results.append(rule)

    return results


def export_api_payloads(
    results: list[dict[str, Any]],
    output_path: str | Path,
    *,
    enabled: bool = False,
) -> Path:
    """Write API-ready payloads to a JSON file.

    Args:
        results: Output of convert_excel().
        output_path: Destination .json file path.
        enabled: Whether rules should be enabled on upload (default: False).

    Returns:
        Resolved output path.
    """
    payloads = [to_api_payload(r, enabled=enabled) for r in results]
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payloads, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return output_path


def conversion_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Produce a summary dict of conversion results for display or logging."""
    total = len(results)
    by_index: dict[str, int] = {}
    with_warnings: int = 0
    context_tables_needed: set[str] = set()
    dropped_stages: dict[str, int] = {}

    for r in results:
        idx = r.get("index", "unknown")
        by_index[idx] = by_index.get(idx, 0) + 1

        if r.get("warnings"):
            with_warnings += 1

        for ct in r.get("context_tables", []):
            context_tables_needed.add(ct)

        for stage in r.get("dropped_stages", []):
            dropped_stages[stage] = dropped_stages.get(stage, 0) + 1

    return {
        "total": total,
        "by_index": by_index,
        "rules_with_warnings": with_warnings,
        "context_tables_needed": sorted(context_tables_needed),
        "dropped_stages": dropped_stages,
    }

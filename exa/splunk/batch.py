"""Batch-convert Splunk SPL searches from various input formats.

Reads searches from Excel, CSV, or savedsearches.conf files and produces
converted Exabeam correlation rules, ready for API upload or export.

Supported formats:
  .xlsx / .xls     — Excel spreadsheet with 'title' and 'search' columns
  .csv             — CSV file with 'title' and 'search' columns
  savedsearches.conf — Splunk INI-style saved searches config

Excel/CSV column format:
  Column: title  — rule display name
  Column: search — Splunk SPL search string

savedsearches.conf format:
  [Rule Title]
  search = index=main sourcetype=syslog | stats count by host
  description = Optional description

Usage:
  from exa.splunk.batch import convert_file
  results = convert_file("searches.csv")
  results = convert_file("savedsearches.conf")
  results = convert_file("Master Enabled plays.xlsx")
"""

from __future__ import annotations

import configparser
import json
from pathlib import Path
from typing import Any

from exa.splunk.converter import convert_spl_to_exa_rule, to_api_payload


# ── Format detection ---------------------------------------------------------


def convert_file(
    path: str | Path,
    *,
    sheet: str = "in",
    title_col: str = "title",
    search_col: str = "search",
) -> list[dict[str, Any]]:
    """Auto-detect file format and convert SPL searches to Exabeam rules.

    Dispatches to the appropriate converter based on file extension:
      .xlsx / .xls  → convert_excel()
      .csv          → convert_csv()
      .conf         → convert_savedsearches_conf()

    Args:
        path: Path to the input file.
        sheet: Sheet name for Excel files (default: "in"). Ignored for CSV/conf.
        title_col: Column name for rule titles in Excel/CSV (default: "title").
        search_col: Column name for SPL searches in Excel/CSV (default: "search").

    Returns:
        List of converted rule dicts.
    """
    path = Path(path)
    suffix = path.suffix.lower()

    if suffix in (".xlsx", ".xls"):
        return convert_excel(path, sheet=sheet, title_col=title_col, search_col=search_col)
    elif suffix == ".csv":
        return convert_csv(path, title_col=title_col, search_col=search_col)
    elif suffix == ".conf" or path.name == "savedsearches.conf":
        return convert_savedsearches_conf(path)
    else:
        raise ValueError(
            f"Unsupported file format: '{suffix}'. "
            f"Supported: .xlsx, .xls, .csv, .conf (savedsearches.conf)"
        )


# ── Excel --------------------------------------------------------------------


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
        List of converted rule dicts.
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
    return _convert_dataframe(df, title_col=title_col, search_col=search_col)


# ── CSV ----------------------------------------------------------------------


def convert_csv(
    path: str | Path,
    *,
    title_col: str = "title",
    search_col: str = "search",
    encoding: str = "utf-8-sig",
) -> list[dict[str, Any]]:
    """Read SPL searches from a CSV file and convert each to an Exabeam rule.

    Expects columns named 'title' and 'search' (configurable). UTF-8 with
    BOM is handled automatically (common Splunk CSV export format).

    Args:
        path: Path to the .csv file.
        title_col: Column name for rule titles (default: "title").
        search_col: Column name for SPL searches (default: "search").
        encoding: File encoding (default: "utf-8-sig" handles BOM).

    Returns:
        List of converted rule dicts.
        Rows where title or search is blank are skipped.
    """
    try:
        import pandas as pd  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "pandas is required for CSV conversion. "
            "Install with: pip install pandas"
        ) from exc

    path = Path(path)
    df = pd.read_csv(path, dtype=str, encoding=encoding)
    return _convert_dataframe(df, title_col=title_col, search_col=search_col)


def _convert_dataframe(
    df: Any,
    *,
    title_col: str,
    search_col: str,
) -> list[dict[str, Any]]:
    """Shared conversion logic for Excel and CSV dataframes."""
    try:
        import pandas as pd  # type: ignore[import]
    except ImportError as exc:
        raise ImportError("pandas required") from exc

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


# ── savedsearches.conf -------------------------------------------------------


def convert_savedsearches_conf(
    path: str | Path,
) -> list[dict[str, Any]]:
    """Read SPL searches from a Splunk savedsearches.conf file.

    Parses Splunk's INI-style saved searches config. Each [stanza] becomes
    a rule, using the stanza name as the title and the 'search' key as the
    SPL query. Stanzas without a 'search' key (dashboards, reports with
    no direct search) are skipped.

    Common savedsearches.conf locations:
      $SPLUNK_HOME/etc/apps/<app>/local/savedsearches.conf
      $SPLUNK_HOME/etc/users/<user>/search/local/savedsearches.conf

    Args:
        path: Path to savedsearches.conf (or any .conf file).

    Returns:
        List of converted rule dicts. Stanzas without 'search' are skipped.
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")

    # configparser requires a [DEFAULT] section or a section header first.
    # savedsearches.conf may start directly with [stanza] — that's fine.
    # We prepend a dummy section header only if needed.
    parser = configparser.RawConfigParser()
    parser.read_string(text)

    results: list[dict[str, Any]] = []
    for section in parser.sections():
        # Skip the built-in DEFAULT and Splunk system stanzas
        if section.lower() in ("default", "splunk_audit_logs", "splunk_search_history"):
            continue

        search = parser.get(section, "search", fallback="").strip()

        # Strip leading '= ' that some Splunk exports include
        if search.startswith("= "):
            search = search[2:].strip()

        if not search:
            continue

        # Use stanza name as title, strip common Splunk prefixes/suffixes
        title = section.strip()

        rule = convert_spl_to_exa_rule(title, search)
        results.append(rule)

    return results


# ── Export / Summary ---------------------------------------------------------


def export_api_payloads(
    results: list[dict[str, Any]],
    output_path: str | Path,
    *,
    enabled: bool = False,
) -> Path:
    """Write API-ready payloads to a JSON file.

    Args:
        results: Output of any convert_* function.
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

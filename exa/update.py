"""CIM2 and Content Hub reference data pipeline.

Clones/pulls ExabeamLabs repos, parses markdown tables, and caches
parsed data as JSON for use by the sigma converter and other tools.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from exa.exceptions import ExaConfigError

_DATA_DIR = Path.home() / ".exa"
_CIM2_DIR = _DATA_DIR / "cim2"
_CONTENT_HUB_DIR = _DATA_DIR / "content-hub"
_CACHE_DIR = _DATA_DIR / "cache"

_CIM2_REPO = "https://github.com/ExabeamLabs/Content-Library-CIM2.git"
_CONTENT_HUB_REPO = "https://github.com/ExabeamLabs/new-scale-content-hub.git"

# Markdown files to parse from CIM2 repo
_CIM2_PARSE_TARGETS: dict[str, str] = {
    "data_sources": "Exabeam Data Sources.md",
    "parser_matrix": "ParserNamesMatrix.md",
    "mitre_map": "MitreMap.md",
    "product_categories": "Exabeam Product Categories.md",
    "use_cases": "Exabeam Use Cases.md",
    "correlation_rules": "Exabeam Correlation Rules.md",
}


# -- Git operations -----------------------------------------------------------


def _git_clone(repo_url: str, target_dir: Path) -> str:
    """Clone a git repo. Returns stdout."""
    result = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, str(target_dir)],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr.strip()}")
    return result.stdout


def _git_pull(repo_dir: Path) -> str:
    """Pull latest in an existing repo. Returns stdout."""
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "pull", "--ff-only"],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git pull failed: {result.stderr.strip()}")
    return result.stdout


def _git_head_sha(repo_dir: Path) -> str:
    """Get HEAD commit SHA for a repo."""
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        return "unknown"
    return result.stdout.strip()[:12]


def _sync_repo(
    repo_url: str,
    target_dir: Path,
) -> tuple[str, bool]:
    """Clone or pull a repo. Returns (action_taken, success)."""
    if target_dir.exists() and (target_dir / ".git").is_dir():
        _git_pull(target_dir)
        return "pulled", True
    else:
        target_dir.parent.mkdir(parents=True, exist_ok=True)
        _git_clone(repo_url, target_dir)
        return "cloned", True


# -- Markdown table parsers ---------------------------------------------------


def _parse_md_table(text: str) -> list[dict[str, str]]:
    """Parse a markdown table into a list of dicts.

    Handles the CIM2 markdown format: header row, separator row, data rows.
    """
    lines = text.split("\n")
    rows: list[dict[str, str]] = []
    headers: list[str] = []
    in_table = False

    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("|"):
            if in_table and headers:
                # End of table block
                break
            continue

        cells = [c.strip() for c in stripped.split("|")[1:-1]]

        if not headers:
            headers = cells
            in_table = True
            continue

        # Skip separator row (|---|---|)
        if all(re.match(r"^[-:]+$", c) or c == "" for c in cells):
            continue

        row: dict[str, str] = {}
        for i, h in enumerate(headers):
            row[h] = cells[i] if i < len(cells) else ""
        rows.append(row)

    return rows


def _parse_data_sources(md_path: Path) -> list[dict[str, str]]:
    """Parse 'Exabeam Data Sources.md' → vendor/product list."""
    text = md_path.read_text(encoding="utf-8")
    rows = _parse_md_table(text)

    results: list[dict[str, str]] = []
    for row in rows:
        vendor = row.get("Vendor", "").strip()
        product_cell = row.get("Product", "").strip()
        if not vendor and not product_cell:
            continue
        # Extract product names from markdown links
        products = re.findall(r"\[([^\]]+)\]", product_cell)
        for p in products:
            results.append({"vendor": vendor, "product": p})
        if not products and product_cell:
            results.append({"vendor": vendor, "product": product_cell})
    return results


def _parse_mitre_map(md_path: Path) -> list[dict[str, str]]:
    """Parse 'MitreMap.md' → TTP code / technique / rules count."""
    text = md_path.read_text(encoding="utf-8")
    # Find the second table (TTP Code | Technique | Rules)
    sections = text.split("| TTP Code")
    if len(sections) < 2:
        return []
    table_text = "| TTP Code" + sections[1]
    return _parse_md_table(table_text)


def _parse_correlation_rules(md_path: Path) -> list[dict[str, str]]:
    """Parse 'Exabeam Correlation Rules.md' → rule list."""
    text = md_path.read_text(encoding="utf-8")
    return _parse_md_table(text)


def _parse_use_cases(md_path: Path) -> list[dict[str, str]]:
    """Parse 'Exabeam Use Cases.md' → use case categories."""
    text = md_path.read_text(encoding="utf-8")
    rows = _parse_md_table(text)
    results: list[dict[str, str]] = []
    for row in rows:
        for category, cell in row.items():
            names = re.findall(r"\[([^\]]+)\]", cell)
            for name in names:
                results.append({"category": category.strip(), "use_case": name})
    return results


def _parse_generic_table(md_path: Path) -> list[dict[str, str]]:
    """Parse any markdown file as a simple table."""
    text = md_path.read_text(encoding="utf-8")
    return _parse_md_table(text)


_PARSERS: dict[str, Any] = {
    "data_sources": _parse_data_sources,
    "mitre_map": _parse_mitre_map,
    "correlation_rules": _parse_correlation_rules,
    "use_cases": _parse_use_cases,
    "parser_matrix": _parse_generic_table,
    "product_categories": _parse_generic_table,
}


# -- Cache management ---------------------------------------------------------


@dataclass
class CacheResult:
    """Result of parsing and caching a single file."""

    name: str
    records: int = 0
    error: str = ""
    updated: str = ""


def _cache_parsed_data(
    cim2_dir: Path,
    cache_dir: Path,
) -> list[CacheResult]:
    """Parse CIM2 markdown files and write JSON cache."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    results: list[CacheResult] = []

    for cache_name, md_filename in _CIM2_PARSE_TARGETS.items():
        md_path = cim2_dir / md_filename
        if not md_path.exists():
            results.append(CacheResult(
                name=cache_name, error=f"File not found: {md_filename}",
            ))
            continue

        parser = _PARSERS.get(cache_name, _parse_generic_table)
        try:
            data = parser(md_path)
            cache_file = cache_dir / f"{cache_name}.json"
            cache_file.write_text(
                json.dumps(data, indent=2), encoding="utf-8",
            )
            results.append(CacheResult(
                name=cache_name,
                records=len(data),
                updated=datetime.now(UTC).isoformat()[:19],
            ))
        except Exception as e:
            results.append(CacheResult(name=cache_name, error=str(e)))

    return results


# -- Public API ---------------------------------------------------------------


@dataclass
class UpdateResult:
    """Result of a full update operation."""

    cim2_action: str = ""
    cim2_sha: str = ""
    content_hub_action: str = ""
    content_hub_sha: str = ""
    cache_results: list[CacheResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def update_reference_data(
    *,
    data_dir: Path | None = None,
) -> UpdateResult:
    """Clone/pull CIM2 and content-hub repos, parse and cache.

    Args:
        data_dir: Override base directory (default ~/.exa/).
    """
    base = data_dir or _DATA_DIR
    cim2_dir = base / "cim2"
    content_hub_dir = base / "content-hub"
    cache_dir = base / "cache"

    result = UpdateResult()

    # Sync CIM2
    try:
        action, _ = _sync_repo(_CIM2_REPO, cim2_dir)
        result.cim2_action = action
        result.cim2_sha = _git_head_sha(cim2_dir)
    except Exception as e:
        result.errors.append(f"CIM2: {e}")

    # Sync content-hub
    try:
        action, _ = _sync_repo(_CONTENT_HUB_REPO, content_hub_dir)
        result.content_hub_action = action
        result.content_hub_sha = _git_head_sha(content_hub_dir)
    except Exception as e:
        result.errors.append(f"Content Hub: {e}")

    # Parse and cache
    if cim2_dir.exists():
        result.cache_results = _cache_parsed_data(cim2_dir, cache_dir)

    return result


def check_reference_data(
    *,
    data_dir: Path | None = None,
) -> dict[str, str]:
    """Check current state of reference data without pulling.

    Returns dict with repo names → current SHA or 'not cloned'.
    """
    base = data_dir or _DATA_DIR
    status: dict[str, str] = {}

    cim2_dir = base / "cim2"
    if cim2_dir.exists() and (cim2_dir / ".git").is_dir():
        status["cim2"] = _git_head_sha(cim2_dir)
    else:
        status["cim2"] = "not cloned"

    hub_dir = base / "content-hub"
    if hub_dir.exists() and (hub_dir / ".git").is_dir():
        status["content-hub"] = _git_head_sha(hub_dir)
    else:
        status["content-hub"] = "not cloned"

    return status


def load_cim2_cache(name: str, *, data_dir: Path | None = None) -> list[Any]:
    """Load a parsed CIM2 cache file.

    Args:
        name: Cache name (e.g. 'data_sources', 'mitre_map').
        data_dir: Override base directory.

    Returns:
        Parsed JSON data.

    Raises:
        ExaConfigError: If cache file not found.
    """
    base = data_dir or _DATA_DIR
    cache_file = base / "cache" / f"{name}.json"
    if not cache_file.exists():
        raise ExaConfigError(
            f"CIM2 data not found ({name}). Run 'exa update' first."
        )
    return json.loads(cache_file.read_text(encoding="utf-8"))

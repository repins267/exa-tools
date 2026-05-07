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
_SIGMA_DIR = _DATA_DIR / "sigma"
_AILLM_DOMAINS_DIR = _DATA_DIR / "aillm-domains"
_CACHE_DIR = _DATA_DIR / "cache"

_CIM2_REPO = "https://github.com/ExabeamLabs/Content-Library-CIM2.git"
_CONTENT_HUB_REPO = (
    "https://github.com/ExabeamLabs/new-scale-content-hub.git"
)
_SIGMA_REPO = "https://github.com/SigmaHQ/sigma.git"
_AILLM_DOMAINS_REPO = "https://github.com/repins267/ai-llm-domains.git"

# Markdown files to parse from CIM2 repo
_CIM2_PARSE_TARGETS: dict[str, str] = {
    "data_sources": "Exabeam Data Sources.md",
    "parser_matrix": "ParserNamesMatrix.md",
    "mitre_map": "MitreMap.md",
    "product_categories": "Exabeam Product Categories.md",
    "use_cases": "Exabeam Use Cases.md",
    "correlation_rules": "Exabeam Correlation Rules.md",
}

# Known CIM2 activity_type values — ordered longest-first for unambiguous substring matching
_ORACLE_ACTIVITY_TYPES: list[str] = [
    "audit_policy-modify", "physical_location-access",
    "web-activity-allowed", "web-activity-denied",
    "network-session", "http-session", "http-traffic",
    "alert-trigger", "rule-trigger", "dns-response", "dns-query",
    "process-create", "process-close", "file-create", "file-write",
    "file-delete", "file-read", "file-modify", "file-time-modify",
    "file-stream-create", "authentication", "app-activity",
    "email-send", "printer-activity", "registry-modify",
    "registry-create", "driver-load", "dll-load", "network-connection",
]

_PARSER_NAME_RE = re.compile(r"\bName\s*=\s*(.+?)$", re.MULTILINE)
_PARSER_VENDOR_RE = re.compile(r"\bVendor\s*=\s*(.+?)$", re.MULTILINE)
_PARSER_PRODUCT_RE = re.compile(r"\bProduct\s*=\s*(.+?)$", re.MULTILINE)
_CAPTURE_GROUP_RE = re.compile(r"\(\{(\w+)\}")
_EXA_JSON_FIELD_RE = re.compile(r"exa_json_path=([^\s,]+)[^\n]*?exa_field_name=(\w+)")


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


def _git_set_config(repo_dir: Path, key: str, value: str) -> None:
    """Set a repo-level git config value (persisted to .git/config)."""
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", key, value],
        capture_output=True, text=True, timeout=10,
    )


def _git_pull(repo_dir: Path) -> str:
    """Fetch and hard-reset to origin HEAD.

    Uses fetch + reset --hard instead of pull to handle:
    - Local modifications (content-hub has edited files)
    - Windows NTFS constraints:
        core.longpaths=true  — content-hub has paths > 260 chars
        core.protectNTFS=false — CIM2 has a file with a literal quote
          in its name (ParsersLegacy/"_parsers.md); git skips it cleanly
    These repos are read-only caches so force-resetting is correct.

    The "Could not reset index file" fatal error fires on Windows even
    when all working-tree files are updated successfully (git just can't
    write the index entry for the problematic filename). We treat that
    specific failure as a warning rather than a hard error — the cache
    parsing only needs files on disk, not a clean git index.
    """
    # Persist Windows-safe config before any git operations so fetch
    # and reset both benefit from it.
    _git_set_config(repo_dir, "core.longpaths", "true")
    _git_set_config(repo_dir, "core.protectNTFS", "false")

    # Fetch latest from origin
    fetch = subprocess.run(
        ["git", "-C", str(repo_dir), "fetch", "origin"],
        capture_output=True, text=True, timeout=300,
    )
    if fetch.returncode != 0:
        raise RuntimeError(f"git fetch failed: {fetch.stderr.strip()}")

    # Resolve default branch (main or master)
    branch_result = subprocess.run(
        ["git", "-C", str(repo_dir), "symbolic-ref",
         "refs/remotes/origin/HEAD"],
        capture_output=True, text=True, timeout=30,
    )
    branch = (
        branch_result.stdout.strip().split("/")[-1]
        if branch_result.returncode == 0
        else "main"
    )

    # Hard reset to remote branch, discard local changes
    reset = subprocess.run(
        ["git", "-C", str(repo_dir), "reset", "--hard", f"origin/{branch}"],
        capture_output=True, text=True, timeout=300,
    )

    if reset.returncode != 0:
        # Windows-specific: git can't write the index entry for filenames
        # that are invalid on NTFS (e.g. containing `"`) or exceed MAX_PATH,
        # but the working-tree files are already updated on disk.
        # Treat "unable to create file" index errors as non-fatal warnings.
        if "unable to create file" in reset.stderr:
            pass  # files on disk are correct; index entry skipped by git
        else:
            raise RuntimeError(f"git reset failed: {reset.stderr.strip()}")

    # Clean untracked files and directories that would block future resets
    subprocess.run(
        ["git", "-C", str(repo_dir), "clean", "-fd"],
        capture_output=True, text=True, timeout=60,
    )

    return reset.stdout


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


# -- Field oracle -------------------------------------------------------------


def _strip_dsl_value(raw: str) -> str:
    """Strip surrounding quotes and whitespace from a DSL field value."""
    return raw.strip().strip('"')


def _extract_activity_type(parser_name: str) -> str:
    """Return the CIM2 activity_type encoded in a parser name, or '' if unrecognised."""
    lname = parser_name.lower()
    for at in _ORACLE_ACTIVITY_TYPES:
        if at in lname:
            return at
    # Code42 has a typo: "file-succes" (missing 's') = file-create
    if "file-succes" in lname and "file-success" not in lname:
        return "file-create"
    return ""


def _parse_parser_file(content: str) -> dict[str, Any] | None:
    """Extract metadata from a pC_*.md parser definition file.

    Returns a dict with keys: name, vendor, product, activity_type,
    cim2_fields (list), raw_to_cim2 (dict). Returns None if the file
    does not look like a parser definition.
    """
    name_m = _PARSER_NAME_RE.search(content)
    if not name_m:
        return None
    name = _strip_dsl_value(name_m.group(1))
    if not name:
        return None

    vendor_m = _PARSER_VENDOR_RE.search(content)
    vendor = _strip_dsl_value(vendor_m.group(1)) if vendor_m else ""

    product_m = _PARSER_PRODUCT_RE.search(content)
    product = _strip_dsl_value(product_m.group(1)) if product_m else ""

    activity_type = _extract_activity_type(name)

    # All CIM2 output fields captured in regex groups: ({field_name}...)
    cim2_fields: set[str] = set(_CAPTURE_GROUP_RE.findall(content))

    # Raw→CIM2 from explicit JSON path mappings:
    #   exa_json_path=$.some.path,...,exa_field_name=cim2_field
    raw_to_cim2: dict[str, str] = {}
    for m in _EXA_JSON_FIELD_RE.finditer(content):
        json_path = m.group(1).rstrip(",")
        cim2_field = m.group(2)
        path_key = json_path.lstrip("$").lstrip(".")
        if path_key:
            raw_to_cim2[path_key] = cim2_field
        # Also index by leaf segment for simple field-name lookups
        leaf = path_key.split(".")[-1] if "." in path_key else path_key
        if leaf and leaf not in raw_to_cim2:
            raw_to_cim2[leaf] = cim2_field

    return {
        "name": name,
        "vendor": vendor,
        "product": product,
        "activity_type": activity_type,
        "cim2_fields": sorted(cim2_fields),
        "raw_to_cim2": raw_to_cim2,
    }


def build_field_oracle(
    *,
    data_dir: Path | None = None,
    _ds_dir: Path | None = None,
) -> CacheResult:
    """Walk Content-Library-CIM2/DS/ and build field_oracle.json.

    Parses every pC_*.md parser definition file to extract:
      - CIM2 field names produced per activity_type and vendor/product
      - Raw JSON path → CIM2 field mappings (from exa_json_path= entries)

    Output: ~/.exa/cache/field_oracle.json
    Schema:
      by_activity_type: {activity_type → {cim2_field → [vendor/product, ...]}}
      by_vendor:        {vendor → {activity_type → [cim2_field, ...]}}
      raw_to_cim2:      {raw_path_or_leaf → cim2_field}
      built_at:         ISO timestamp
      stats:            {parsers_processed, parsers_failed}

    Args:
        data_dir: Override base directory (default ~/.exa/).
        _ds_dir:  Override DS/ source directory (for testing).
    """
    base = data_dir or _DATA_DIR
    ds_dir = _ds_dir or (base / "cim2" / "DS")
    cache_dir = base / "cache"

    if not ds_dir.is_dir():
        return CacheResult(
            name="field_oracle",
            error=f"DS/ directory not found at {ds_dir} — run 'exa update' first",
        )

    by_activity_type: dict[str, dict[str, list[str]]] = {}
    by_vendor: dict[str, dict[str, list[str]]] = {}
    raw_to_cim2: dict[str, str] = {}
    parser_count = 0
    error_count = 0

    for parser_file in ds_dir.rglob("pC_*.md"):
        try:
            content = parser_file.read_text(encoding="utf-8", errors="ignore")
            parsed = _parse_parser_file(content)
            if not parsed:
                error_count += 1
                continue

            parser_count += 1
            vendor = parsed["vendor"]
            product = parsed["product"]
            activity_type = parsed["activity_type"]
            cim2_fields: list[str] = parsed["cim2_fields"]
            vendor_product = f"{vendor}/{product}" if vendor and product else vendor

            if activity_type:
                at_entry = by_activity_type.setdefault(activity_type, {})
                for fld in cim2_fields:
                    sources = at_entry.setdefault(fld, [])
                    if vendor_product and vendor_product not in sources:
                        sources.append(vendor_product)

            if vendor:
                vendor_entry = by_vendor.setdefault(vendor, {})
                if activity_type:
                    at_fields = vendor_entry.setdefault(activity_type, [])
                    for fld in cim2_fields:
                        if fld not in at_fields:
                            at_fields.append(fld)

            # Merge raw→CIM2 (first-write wins on conflicts)
            for raw_key, cim2_field in parsed["raw_to_cim2"].items():
                raw_to_cim2.setdefault(raw_key, cim2_field)

        except Exception:
            error_count += 1
            continue

    oracle: dict[str, Any] = {
        "by_activity_type": by_activity_type,
        "by_vendor": by_vendor,
        "raw_to_cim2": raw_to_cim2,
        "built_at": datetime.now(UTC).isoformat(),
        "stats": {
            "parsers_processed": parser_count,
            "parsers_failed": error_count,
        },
    }

    cache_dir.mkdir(parents=True, exist_ok=True)
    oracle_file = cache_dir / "field_oracle.json"
    oracle_file.write_text(json.dumps(oracle, indent=2), encoding="utf-8")

    return CacheResult(
        name="field_oracle",
        records=parser_count,
        updated=datetime.now(UTC).isoformat()[:19],
    )


# -- Public API ---------------------------------------------------------------


def _build_sigma_index(
    sigma_dir: Path,
    cache_dir: Path,
) -> CacheResult:
    """Parse SigmaHQ rules directory and build a rule index."""
    from exa.sigma.parser import parse_sigma_yaml

    cache_dir.mkdir(parents=True, exist_ok=True)
    rules_dir = sigma_dir / "rules"
    if not rules_dir.is_dir():
        return CacheResult(
            name="sigma_index",
            error="rules/ directory not found in sigma repo",
        )

    index: list[dict[str, Any]] = []
    for yml in rules_dir.rglob("*.yml"):
        try:
            text = yml.read_text(encoding="utf-8")
            parsed = parse_sigma_yaml(text)
            title = parsed.get("title", yml.stem)
            tags = parsed.get("tags", [])
            if not isinstance(tags, list):
                tags = [tags] if tags else []
            level = parsed.get("level", "")
            logsource = parsed.get("logsource", {})
            if not isinstance(logsource, dict):
                logsource = {}
            category = logsource.get("category", "")
            product = logsource.get("product", "")
            rel = str(yml.relative_to(sigma_dir)).replace("\\", "/")
            index.append({
                "path": rel,
                "title": str(title) if title else yml.stem,
                "tags": [str(t) for t in tags],
                "level": str(level) if level else "",
                "category": str(category) if category else "",
                "product": str(product) if product else "",
            })
        except Exception:
            continue

    cache_file = cache_dir / "sigma_index.json"
    cache_file.write_text(
        json.dumps(index, indent=2), encoding="utf-8",
    )
    return CacheResult(
        name="sigma_index",
        records=len(index),
        updated=datetime.now(UTC).isoformat()[:19],
    )


@dataclass
class UpdateResult:
    """Result of a full update operation."""

    cim2_action: str = ""
    cim2_sha: str = ""
    content_hub_action: str = ""
    content_hub_sha: str = ""
    sigma_action: str = ""
    sigma_sha: str = ""
    aillm_domains_action: str = ""
    aillm_domains_sha: str = ""
    cache_results: list[CacheResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def update_reference_data(
    *,
    data_dir: Path | None = None,
    include_sigma: bool = True,
) -> UpdateResult:
    """Clone/pull CIM2, content-hub, and SigmaHQ repos; parse and cache.

    Args:
        data_dir: Override base directory (default ~/.exa/).
        include_sigma: Whether to clone/pull SigmaHQ repo.
    """
    base = data_dir or _DATA_DIR
    cim2_dir = base / "cim2"
    content_hub_dir = base / "content-hub"
    sigma_dir = base / "sigma"
    aillm_domains_dir = base / "aillm-domains"
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

    # Sync SigmaHQ
    if include_sigma:
        try:
            action, _ = _sync_repo(_SIGMA_REPO, sigma_dir)
            result.sigma_action = action
            result.sigma_sha = _git_head_sha(sigma_dir)
        except Exception as e:
            result.errors.append(f"SigmaHQ: {e}")

    # Sync ai-llm-domains reference dataset
    try:
        action, _ = _sync_repo(_AILLM_DOMAINS_REPO, aillm_domains_dir)
        result.aillm_domains_action = action
        result.aillm_domains_sha = _git_head_sha(aillm_domains_dir)
    except Exception as e:
        result.errors.append(f"AI/LLM Domains: {e}")

    # Parse and cache CIM2
    if cim2_dir.exists():
        result.cache_results = _cache_parsed_data(cim2_dir, cache_dir)
        # Build field oracle from DS/ parser definitions
        oracle_result = build_field_oracle(data_dir=base)
        result.cache_results.append(oracle_result)

    # Build sigma index
    if include_sigma and sigma_dir.exists():
        sigma_result = _build_sigma_index(sigma_dir, cache_dir)
        result.cache_results.append(sigma_result)

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

    sigma_dir = base / "sigma"
    if sigma_dir.exists() and (sigma_dir / ".git").is_dir():
        status["sigma"] = _git_head_sha(sigma_dir)
    else:
        status["sigma"] = "not cloned"

    aillm_dir = base / "aillm-domains"
    if aillm_dir.exists() and (aillm_dir / ".git").is_dir():
        status["aillm-domains"] = _git_head_sha(aillm_dir)
    else:
        status["aillm-domains"] = "not cloned"

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

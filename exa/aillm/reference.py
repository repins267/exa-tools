"""Load and filter AI/LLM reference data from bundled JSON files.

Applies exclusion filters:
- IPv4 addresses (not valid domain table keys)
- DLP entries that are IOCs rather than named alert strings
"""

from __future__ import annotations

import importlib.resources
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_DLP_IOC_VENDOR_PATTERN = re.compile(r"IOC", re.IGNORECASE)

# External repo data takes precedence over the bundled snapshot when present.
# Populated by `exa update` → ~/.exa/aillm-domains/data/
_EXTERNAL_DATA_DIR = Path.home() / ".exa" / "aillm-domains" / "data"

# Every file _load_json() may read. Freshness is measured across all of them
# because `exa update` refreshes them together, and one lagging file is the
# case worth catching.
_REFERENCE_FILES = (
    "known_ai_domains.json",
    "known_ai_apps.json",
    "known_proxy_categories.json",
    "known_dlp_alert_patterns.json",
)


@dataclass
class ReferenceData:
    """Structured AI/LLM reference data for the 6 context tables."""

    dlp_rulesets: list[dict[str, str]] = field(default_factory=list)
    proxy_categories: list[dict[str, str]] = field(default_factory=list)
    public_domains: list[dict[str, str]] = field(default_factory=list)
    web_domains: list[dict[str, str]] = field(default_factory=list)
    web_categories: list[dict[str, str]] = field(default_factory=list)
    applications: list[dict[str, str]] = field(default_factory=list)
    excluded_domains: int = 0
    excluded_dlp: int = 0


def _load_json(filename: str) -> list[dict[str, Any]]:
    """Load a JSON file, preferring the external repo over the bundled snapshot.

    External path (~/.exa/aillm-domains/data/) is populated by `exa update`
    and always contains the most current data. Falls back to the bundled
    snapshot when the external repo has not been synced yet.
    """
    external = _EXTERNAL_DATA_DIR / filename
    if external.exists():
        return json.loads(external.read_text(encoding="utf-8"))
    data_dir = importlib.resources.files("exa.aillm.data")
    text = (data_dir / filename).read_text(encoding="utf-8-sig")
    return json.loads(text)


def load_reference_data() -> ReferenceData:
    """Load all 4 JSON reference files and build the 6 table datasets."""
    raw_domains = _load_json("known_ai_domains.json")
    raw_apps = _load_json("known_ai_apps.json")
    raw_proxy_cats = _load_json("known_proxy_categories.json")
    raw_dlp = _load_json("known_dlp_alert_patterns.json")

    # Filter domains — exclude IPv4 addresses (invalid domain table keys only)
    filtered_domains: list[dict[str, Any]] = []
    excluded_domains = 0
    for d in raw_domains:
        domain = d.get("domain", "")
        if _IPV4_RE.match(domain):
            excluded_domains += 1
            continue
        filtered_domains.append(d)

    # Filter DLP
    filtered_dlp: list[dict[str, Any]] = []
    excluded_dlp = 0
    for p in raw_dlp:
        if _DLP_IOC_VENDOR_PATTERN.search(p.get("vendor", "")):
            excluded_dlp += 1
            continue
        filtered_dlp.append(p)

    # Build 6 table datasets
    dlp_rulesets = [{"key": p["pattern"]} for p in filtered_dlp]

    seen_cats: set[str] = set()
    proxy_categories: list[dict[str, str]] = []
    for c in raw_proxy_cats:
        cat = c.get("category", "")
        cat_lower = cat.lower()
        if cat_lower not in seen_cats:
            seen_cats.add(cat_lower)
            proxy_categories.append({"key": cat})

    public_domains = [
        {"key": d["domain"], "risk": d.get("risk", "medium")} for d in filtered_domains
    ]
    web_domains = [{"key": d["domain"]} for d in filtered_domains]
    web_categories = list(proxy_categories)  # same data
    applications = [{"key": a["app"]} for a in raw_apps]

    return ReferenceData(
        dlp_rulesets=dlp_rulesets,
        proxy_categories=proxy_categories,
        public_domains=public_domains,
        web_domains=web_domains,
        web_categories=web_categories,
        applications=applications,
        excluded_domains=excluded_domains,
        excluded_dlp=excluded_dlp,
    )


# -- freshness ----------------------------------------------------------------

# The reference data is the source of every "is this AI-related" verdict in the
# module. Stale data does not error -- it silently under-classifies, so a domain
# that became an AI service last month reads as ordinary web traffic and never
# reaches a gap report. That is indistinguishable from a clean result.
STALE_AFTER_DAYS = 30


@dataclass(frozen=True)
class ReferenceFreshness:
    """Where the reference data came from and how old it is."""

    source: str  # "external" or "bundled"
    age_days: int | None  # None when unknown (bundled snapshot)
    path: Path | None = None

    @property
    def stale(self) -> bool:
        """Bundled data is always stale -- it is a snapshot, frozen at release."""
        if self.source == "bundled":
            return True
        return self.age_days is not None and self.age_days > STALE_AFTER_DAYS

    @property
    def summary(self) -> str:
        if self.source == "bundled":
            return (
                "bundled snapshot (frozen at release) -- run 'exa update' to "
                "pull current AI/LLM reference data"
            )
        if self.age_days is None:
            return f"external repo at {self.path}, age unknown"
        if self.stale:
            return (
                f"external repo is {self.age_days} days old (stale after "
                f"{STALE_AFTER_DAYS}) -- run 'exa update'"
            )
        return f"external repo, {self.age_days} days old"


def reference_freshness() -> ReferenceFreshness:
    """Report the age of the AI/LLM reference data backing this run.

    Customers do not run scheduled tasks, so the data ages silently between
    engagements. Surfacing the age is the only thing standing between a TAM and
    reporting a confidently empty gap list built on last quarter's domain list.
    """
    newest: float | None = None
    for name in _REFERENCE_FILES:
        candidate = _EXTERNAL_DATA_DIR / name
        if candidate.exists():
            mtime = candidate.stat().st_mtime
            newest = mtime if newest is None else max(newest, mtime)

    if newest is None:
        return ReferenceFreshness(source="bundled", age_days=None)

    age = int((time.time() - newest) // 86400)
    return ReferenceFreshness(
        source="external", age_days=age, path=_EXTERNAL_DATA_DIR
    )

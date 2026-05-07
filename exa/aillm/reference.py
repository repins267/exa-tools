"""Load and filter AI/LLM reference data from bundled JSON files.

Applies exclusion filters:
- IPv4 addresses
- Named malicious/impersonator domains
- DLP entries that are IOCs rather than named alert strings
"""

from __future__ import annotations

import importlib.resources
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_MALICIOUS_DOMAINS = frozenset({"zeroclaw.org", "zeroclaw.net"})
_DLP_IOC_VENDOR_PATTERN = re.compile(r"IOC", re.IGNORECASE)

# External repo data takes precedence over the bundled snapshot when present.
# Populated by `exa update` → ~/.exa/aillm-domains/data/
_EXTERNAL_DATA_DIR = Path.home() / ".exa" / "aillm-domains" / "data"


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

    # Filter domains
    filtered_domains: list[dict[str, Any]] = []
    excluded_domains = 0
    for d in raw_domains:
        domain = d.get("domain", "")
        if _IPV4_RE.match(domain) or domain in _MALICIOUS_DOMAINS:
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

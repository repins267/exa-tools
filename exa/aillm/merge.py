"""Merge AI/LLM reference data with discovered data and customer overrides.

Risk precedence for PublicDomains:
  1. Customer risk override file (highest)
  2. Reference data default
  3. "medium" fallback for discovered-only domains
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from exa.aillm.reference import ReferenceData


@dataclass
class MergeStats:
    dlp_rulesets: int = 0
    proxy_categories: int = 0
    public_domains: int = 0
    web_domains: int = 0
    web_categories: int = 0
    applications: int = 0
    discovered_total: int = 0
    discovered_new: int = 0
    discovered_apps_total: int = 0
    discovered_apps_new: int = 0
    risk_overrides_applied: int = 0


@dataclass
class MergedData:
    dlp_rulesets: list[dict[str, str]] = field(default_factory=list)
    proxy_categories: list[dict[str, str]] = field(default_factory=list)
    public_domains: list[dict[str, str]] = field(default_factory=list)
    web_domains: list[dict[str, str]] = field(default_factory=list)
    web_categories: list[dict[str, str]] = field(default_factory=list)
    applications: list[dict[str, str]] = field(default_factory=list)
    merge_stats: MergeStats = field(default_factory=MergeStats)


def _dedup_by_key(records: list[dict[str, str]]) -> list[dict[str, str]]:
    """Deduplicate records by 'key' value (case-insensitive)."""
    seen: set[str] = set()
    result: list[dict[str, str]] = []
    for r in records:
        k = r.get("key", "").lower()
        if k and k not in seen:
            seen.add(k)
            result.append(r)
    return result


def merge_aillm_data(
    ref: ReferenceData,
    *,
    discovered_domains: list[str] | None = None,
    discovered_apps: list[str] | None = None,
    risk_override_path: str | Path | None = None,
) -> MergedData:
    """Merge reference data with optional discovered data and risk overrides."""
    # Load customer risk overrides
    risk_overrides: dict[str, str] = {}
    if risk_override_path:
        p = Path(risk_override_path)
        if p.exists():
            raw = json.loads(p.read_text(encoding="utf-8"))
            risk_overrides = {k.lower(): v for k, v in raw.items()}

    # Tables with no discovery: just dedup
    dlp_rulesets = _dedup_by_key(ref.dlp_rulesets)
    proxy_categories = _dedup_by_key(ref.proxy_categories)
    web_categories = _dedup_by_key(ref.web_categories)

    # Merge apps
    discovered_apps_new = 0
    if discovered_apps:
        seen: set[str] = set()
        merged_apps: list[dict[str, str]] = []
        for r in ref.applications:
            k = r["key"].lower()
            if k not in seen:
                seen.add(k)
                merged_apps.append(r)
        for a in discovered_apps:
            trimmed = a.strip()
            if trimmed and trimmed.lower() not in seen:
                seen.add(trimmed.lower())
                merged_apps.append({"key": trimmed})
                discovered_apps_new += 1
        applications = merged_apps
    else:
        applications = _dedup_by_key(ref.applications)

    # Merge domains
    discovered_new = 0
    if discovered_domains:
        seen_d: set[str] = set()
        public_domains: list[dict[str, str]] = []
        web_domains: list[dict[str, str]] = []

        for r in ref.public_domains:
            domain = r["key"]
            dl = domain.lower()
            if dl not in seen_d:
                seen_d.add(dl)
                risk = risk_overrides.get(dl, r.get("risk", "medium"))
                public_domains.append({"key": domain, "risk": risk})
                web_domains.append({"key": domain})

        for d in discovered_domains:
            trimmed = d.strip()
            if not trimmed:
                continue
            dl = trimmed.lower()
            if dl not in seen_d:
                seen_d.add(dl)
                discovered_new += 1
                risk = risk_overrides.get(dl, "medium")
                public_domains.append({"key": trimmed, "risk": risk})
                web_domains.append({"key": trimmed})
    else:
        if risk_overrides:
            public_domains = []
            for r in ref.public_domains:
                dl = r["key"].lower()
                risk = risk_overrides.get(dl, r.get("risk", "medium"))
                public_domains.append({"key": r["key"], "risk": risk})
        else:
            public_domains = _dedup_by_key(ref.public_domains)
        web_domains = _dedup_by_key(ref.web_domains)

    stats = MergeStats(
        dlp_rulesets=len(dlp_rulesets),
        proxy_categories=len(proxy_categories),
        public_domains=len(public_domains),
        web_domains=len(web_domains),
        web_categories=len(web_categories),
        applications=len(applications),
        discovered_total=len(discovered_domains) if discovered_domains else 0,
        discovered_new=discovered_new,
        discovered_apps_total=len(discovered_apps) if discovered_apps else 0,
        discovered_apps_new=discovered_apps_new,
        risk_overrides_applied=len(risk_overrides),
    )

    return MergedData(
        dlp_rulesets=dlp_rulesets,
        proxy_categories=proxy_categories,
        public_domains=public_domains,
        web_domains=web_domains,
        web_categories=web_categories,
        applications=applications,
        merge_stats=stats,
    )

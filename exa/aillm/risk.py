"""Join observed AI domains to curated risk levels.

`Public AI Domains and Risk` maps domain -> risk_level (High/Medium/Low) across
223 curated entries. At the time of writing **no analytics rule reads it**, so
that curation drives zero detections. This module makes it usable: it reports
which risk tiers a tenant is actually touching, and maintains a high-risk
watchlist that is empty by design and meaningful the moment it is not.

Risk rationales (from the ai-llm-domains repo) — a domain needs only one to
rate High:
  - data jurisdiction: provider subject to mandatory state data-access laws
  - autonomous execution: controls a terminal, browser or IDE
  - no enterprise controls: no SSO, audit, DLP integration or DPA
  - unofficial wrapper, impersonation fork, or abandoned service

Risk is capability-driven, not reputation-driven: a tool that executes code on a
user's behalf has a larger blast radius than one that returns text.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from importlib.resources import files
from typing import TYPE_CHECKING, Any

from exa.aillm.profile import TenantProfile, collect_tenant_profile

if TYPE_CHECKING:
    from exa.client import ExaClient

RISK_ORDER = ["critical", "high", "medium", "low", "unrated"]

# Heuristics for spotting an AI domain that our reference data does not list.
_AI_HINT = re.compile(
    r"openai|chatgpt|anthropic|claude|gemini|bard|copilot|perplexity|huggingface|"
    r"mistral|cohere|deepseek|qwen|midjourney|character\.ai|poe\.com|grok|cursor|"
    r"codeium|replit|otter\.ai|jasper|writesonic|n8n|dify|crewai|ollama|groq|"
    r"openrouter|quillbot|magnific|granola|kapa\.ai|devrev|lovable|together\.ai|"
    r"scite|elevenlabs|synthesia|runway|stability|leonardo|ideogram|duck\.ai|"
    r"wisprflow|tonic\.ai|moveworks|paradox\.ai|\.ai$",
    re.I,
)


@dataclass
class ObservedDomain:
    """An AI domain seen in tenant traffic, with any risk we can attribute."""

    domain: str
    risk: str = "unrated"
    matched_reference: str | None = None
    provider: str | None = None
    category: str | None = None


@dataclass
class RiskReport:
    """Risk posture across the AI domains a tenant actually reaches."""

    observed_total: int = 0
    by_risk: dict[str, list[ObservedDomain]] = field(default_factory=dict)
    unlisted: list[str] = field(default_factory=list)
    watchlist_total: int = 0
    watchlist_hits: list[ObservedDomain] = field(default_factory=list)
    sample_truncated: bool = False

    @property
    def watchlist_clear(self) -> bool:
        return not self.watchlist_hits


def load_domain_metadata() -> dict[str, dict[str, Any]]:
    """Full reference records keyed by lowercase domain.

    load_reference_data() intentionally returns upload-shaped records
    ({"key": ...}) and discards provider/risk/category. Risk lookups must read
    the raw file instead (EXA-REFDATA-STRIPS-RISK).
    """
    from exa.aillm.reference import _EXTERNAL_DATA_DIR  # noqa: PLC2701

    external = _EXTERNAL_DATA_DIR / "known_ai_domains.json"
    if external.exists():
        raw = json.loads(external.read_text(encoding="utf-8-sig"))
    else:
        text = (
            files("exa.aillm.data")
            .joinpath("known_ai_domains.json")
            .read_text(encoding="utf-8-sig")
        )
        raw = json.loads(text)
    return {
        str(d["domain"]).lower(): d
        for d in raw
        if isinstance(d, dict) and d.get("domain")
    }


def _match(host: str, reference: dict[str, dict[str, Any]]) -> str | None:
    """Exact match, else registered-domain suffix match."""
    h = host.lower()
    if h in reference:
        return h
    for known in reference:
        if h.endswith("." + known):
            return known
    return None


def build_risk_report(
    client: ExaClient,
    *,
    profile: TenantProfile | None = None,
    lookback_days: int = 30,
    refresh: bool = False,
) -> RiskReport:
    """Report which risk tiers of AI domains a tenant is reaching.

    Args:
        client: Authenticated ExaClient.
        profile: Reuse an existing TenantProfile. Collected if omitted.
        lookback_days: Lookback used when collecting a profile.
        refresh: Force profile re-collection.

    Returns:
        RiskReport. Costs zero API calls against a warm profile.
    """
    profile = profile or collect_tenant_profile(
        client, lookback_days=lookback_days, refresh=refresh
    )
    reference = load_domain_metadata()

    report = RiskReport(sample_truncated=profile.truncated("web_domain"))
    buckets: dict[str, list[ObservedDomain]] = defaultdict(list)

    for host in profile.values("web_domain"):
        matched = _match(host, reference)
        if matched is None:
            if _AI_HINT.search(host):
                report.unlisted.append(host)
            continue
        meta = reference[matched]
        od = ObservedDomain(
            domain=host,
            risk=str(meta.get("risk") or "unrated").lower(),
            matched_reference=matched,
            provider=meta.get("provider"),
            category=meta.get("category"),
        )
        buckets[od.risk].append(od)
        report.observed_total += 1

    report.by_risk = {
        tier: sorted(buckets.get(tier, []), key=lambda d: d.domain)
        for tier in RISK_ORDER
        if buckets.get(tier)
    }
    report.unlisted = sorted(set(report.unlisted))

    high_tiers = {"high", "critical"}
    report.watchlist_total = sum(
        1 for m in reference.values()
        if str(m.get("risk") or "").lower() in high_tiers
    )
    report.watchlist_hits = [
        d for tier in high_tiers for d in buckets.get(tier, [])
    ]
    return report

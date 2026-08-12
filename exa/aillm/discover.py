"""Discover AI/LLM signals a tenant actually emits.

Three discovery surfaces, all reading from the cached TenantProfile so a warm
profile makes discovery cost zero API calls:

  - ``discover_ai_domains``     -> web_domain
  - ``discover_categories``     -> category / categories  (what RULES match on)
  - ``discover_alert_names``    -> event.alert_name

Why this was rewritten
----------------------
The previous ``search_logs_for_ai_domains`` returned **every** distinct
``web_domain`` in the tenant with no AI filtering — 10,000+ on a mid-size
customer — and fed the result straight into ``merge_aillm_data`` and from there
into a context table. It also depended on an
``activity_type:"web-activity-allowed"`` EQL filter that is silently not applied
on some tenants, so the "web activity only" narrowing was not happening either.

Two further gaps it left:

  - **No category discovery at all**, despite ``category`` being the field three
    analytics rules match against via ``ContextListContains``.
  - **No ``event.alert_name`` discovery.** ``discover_alerts.discover_ai_activity``
    reads the *Threat Center* alert namespace, which does not intersect the
    ``event.alert_name`` CIM field (EXA-ALERTNAME-TWO-NAMESPACES). Populating the
    DLP Rulesets table from it produces zero matches.

Classification
--------------
Every candidate lands in exactly one bucket:

  ``known``     matched reference data (exact or registered-domain suffix)
  ``candidate`` looks like AI but is unlisted — the repo contribution queue
  ``excluded``  matched an exclusion rule (martech riding the ``.ai`` TLD)

Only ``known`` and reviewed ``candidate`` entries should ever reach a context
table. The ``.ai`` TLD is saturated with adtech — ``datagrail.io`` matches a
naive "contains ai" filter because of *datagr**ai**l*.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from importlib.resources import files
from typing import TYPE_CHECKING, Any

from exa.aillm.profile import TenantProfile, collect_tenant_profile

if TYPE_CHECKING:
    from exa.client import ExaClient

# Hostnames that look like AI but are advertising, analytics or unrelated SaaS.
# Ships as a fallback; ai-llm-domains/data/known_exclusions.json overrides it.
_DEFAULT_EXCLUSIONS: set[str] = {
    "datagrail.io", "trafficguard.ai", "mikmak.ai", "shortpixel.ai",
    "drift-pixel.ai", "clrt.ai", "kalio.ai", "rampmetrics.ai", "stape.ai",
    "symbiosys.ai", "programmaticx.ai", "adzen.ai", "sardine.ai",
    "shoplift.ai", "nrich.ai", "trinitymedia.ai", "aimerce.ai", "powerad.ai",
    "buzzfeed.ai", "resumegemini.com", "coherehealth.com", "gemini.com",
    "wemustactnow.ai", "vfmleonardo.com", "cbinsights.com",
}

# Provider/product tokens that indicate a genuine AI service.
_AI_TOKENS = re.compile(
    r"openai|chatgpt|anthropic|claude|gemini\.google|geminiweb|bard|copilot|"
    r"perplexity|huggingface|mistral|cohere\.|deepseek|qwen|midjourney|"
    r"character\.ai|poe\.com|grok|x\.ai|cursor|codeium|windsurf|replit|"
    r"otter\.ai|jasper|writesonic|quillbot|grammarly|n8n|dify|crewai|flowise|"
    r"ollama|groq|openrouter|magnific|beyondwords|granola|kapa\.ai|devrev|"
    r"toolbaz|yellow\.ai|asksquid|castify|nextslide|suno|lovable|together\.ai|"
    r"scite|elevenlabs|synthesia|runway|stability|leonardo|ideogram|duck\.ai|"
    r"wisprflow|tonic\.ai|moveworks|paradox\.ai|people\.ai|impel\.ai|"
    r"securiti\.ai|auditoria\.ai|espresso\.ai|openclaw|zeroclaw|agpt|"
    r"all-hands|openinterpreter|civitai|seaart|tensor\.art|chatglm|doubao|"
    r"ernie\.baidu|yiyan\.baidu|kimi\.moonshot|klingai",
    re.I,
)

# Weak signal — only meaningful with a supporting AI category or reference hit.
_WEAK_AI_HINT = re.compile(r"\.ai$|(^|\.)ai[-.]|chatbot|\bllm\b|genai", re.I)

# Category values that indicate AI, across vendor taxonomies.
_AI_CATEGORY = re.compile(
    r"^ai[-_ ]|artificial.intelligence|generative|genai|\bllm\b|chatbot|"
    r"ai (&|and) ml|machine.learning|copilot",
    re.I,
)

# `\bAI\b` alone is not enough: there is NO word boundary between "AI" and
# "Enterprise", so `AIEnterpriseInteractionsExported` -- a real Microsoft 365
# audit operation naming AI enterprise interactions -- was silently dropped on a
# live tenant, and with it one of only eight genuine AI alert names that tenant
# emits. The second alternative is scoped case-SENSITIVE `(?-i:...)` and demands
# CamelCase after the AI, so `AIEnterprise` matches while `AIRPORT` (all caps)
# and `airline` (lowercase) do not. Leaving it case-insensitive would match the
# "ai" inside every ordinary word.
_AI_ALERT = re.compile(
    r"\bAI\b|(?-i:\bAI(?=[A-Z][a-z]))|LLM|GenAI|generative|copilot|chatbot|"
    r"prompt|DSPM for AI",
    re.I,
)

KNOWN = "known"
CANDIDATE = "candidate"
EXCLUDED = "excluded"


# The four predicates below are the classifier itself, exposed so gap analysis
# runs the SAME test discovery runs. When `exa aillm gaps` carried its own copy
# of these patterns the two commands disagreed about the same tenant, which is
# the one failure mode neither operator can debug from the output.


def is_ai_alert_name(value: str) -> bool:
    """Whether an ``event.alert_name`` value carries an AI/LLM signal."""
    return bool(_AI_ALERT.search(value or ""))


def is_ai_category(value: str) -> bool:
    """Whether a proxy/URL category value names an AI class of traffic."""
    return bool(_AI_CATEGORY.search(value or ""))


def has_ai_provider_token(value: str) -> bool:
    """Whether a value names a known AI provider or product (strong signal)."""
    return bool(_AI_TOKENS.search(value or ""))


def has_weak_ai_hint(value: str) -> bool:
    """Whether a value only *looks* AI-ish (.ai TLD, ai- prefix) -- review first."""
    return bool(_WEAK_AI_HINT.search(value or ""))


@dataclass
class DiscoveredDomain:
    """One hostname observed in tenant traffic, classified."""

    domain: str
    classification: str = CANDIDATE
    matched_reference: str | None = None
    risk: str | None = None
    provider: str | None = None
    category: str | None = None
    reason: str = ""


@dataclass
class DiscoveredValue:
    """A category or alert-name value observed in tenant data."""

    value: str
    field_name: str
    sources: list[str] = field(default_factory=list)
    in_reference: bool = False


@dataclass
class DomainDiscovery:
    known: list[DiscoveredDomain] = field(default_factory=list)
    candidates: list[DiscoveredDomain] = field(default_factory=list)
    excluded: list[DiscoveredDomain] = field(default_factory=list)
    scanned: int = 0
    truncated: bool = False

    @property
    def safe_to_sync(self) -> list[str]:
        """Domains safe to push to a context table without human review."""
        return sorted(d.domain for d in self.known)


def load_exclusions() -> set[str]:
    """Exclusion list, preferring the external repo copy."""
    from exa.aillm.reference import _EXTERNAL_DATA_DIR  # noqa: PLC2701

    for path in (
        _EXTERNAL_DATA_DIR / "known_exclusions.json",
        files("exa.aillm.data").joinpath("known_exclusions.json"),
    ):
        try:
            if hasattr(path, "exists") and not path.exists():
                continue
            raw: Any = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError, FileNotFoundError):
            continue
        if isinstance(raw, list):
            out = set()
            for item in raw:
                if isinstance(item, str):
                    out.add(item.lower())
                elif isinstance(item, dict) and item.get("domain"):
                    out.add(str(item["domain"]).lower())
            if out:
                return out
    return set(_DEFAULT_EXCLUSIONS)


def _suffix_match(host: str, table: dict[str, Any] | set[str]) -> str | None:
    h = host.lower()
    if h in table:
        return h
    for known in table:
        if h.endswith("." + known):
            return known
    return None


def discover_ai_domains(
    client: ExaClient,
    *,
    profile: TenantProfile | None = None,
    lookback_days: int = 30,
    refresh: bool = False,
) -> DomainDiscovery:
    """Classify the AI domains a tenant reaches.

    Args:
        client: Authenticated ExaClient.
        profile: Reuse an existing TenantProfile. Collected if omitted.
        lookback_days: Lookback used when collecting a profile.
        refresh: Force profile re-collection.

    Returns:
        DomainDiscovery with known / candidate / excluded buckets. Note
        ``truncated`` — when the domain sample hit its cap the result is a lower
        bound, and "not found" does not mean "not present".
    """
    from exa.aillm.risk import load_domain_metadata

    profile = profile or collect_tenant_profile(
        client, lookback_days=lookback_days, refresh=refresh
    )
    reference = load_domain_metadata()
    exclusions = load_exclusions()

    result = DomainDiscovery(truncated=profile.truncated("web_domain"))
    hosts = profile.values("web_domain")
    result.scanned = len(hosts)

    for host in hosts:
        matched = _suffix_match(host, reference)
        if matched:
            meta = reference[matched]
            result.known.append(
                DiscoveredDomain(
                    domain=host,
                    classification=KNOWN,
                    matched_reference=matched,
                    risk=str(meta.get("risk") or "medium"),
                    provider=meta.get("provider"),
                    category=meta.get("category"),
                    reason="matched reference data",
                )
            )
            continue

        excluded_by = _suffix_match(host, exclusions)
        if excluded_by:
            result.excluded.append(
                DiscoveredDomain(
                    domain=host,
                    classification=EXCLUDED,
                    reason=f"exclusion list ({excluded_by})",
                )
            )
            continue

        if _AI_TOKENS.search(host):
            result.candidates.append(
                DiscoveredDomain(
                    domain=host, classification=CANDIDATE,
                    reason="matched a known AI provider token",
                )
            )
        elif _WEAK_AI_HINT.search(host):
            result.candidates.append(
                DiscoveredDomain(
                    domain=host, classification=CANDIDATE,
                    reason="weak signal (.ai TLD or ai- prefix) — review before use",
                )
            )

    for bucket in (result.known, result.candidates, result.excluded):
        bucket.sort(key=lambda d: d.domain)
    return result


def discover_categories(
    client: ExaClient,
    *,
    profile: TenantProfile | None = None,
    lookback_days: int = 30,
    refresh: bool = False,
) -> list[DiscoveredValue]:
    """Find AI-related proxy/URL category values, with vendor attribution.

    ``category`` is what three analytics rules match against; ``categories`` is a
    parallel multi-vendor field. Both are enumerated because vendors do not agree
    on a taxonomy — one tenant carried Palo Alto's ``AI-conversational-assistant``
    in ``categories`` and Zscaler's ``AI & ML Apps`` in ``category``, with almost
    no overlap between them.
    """
    from exa.aillm.reference import load_reference_data

    profile = profile or collect_tenant_profile(
        client, lookback_days=lookback_days, refresh=refresh
    )
    ref = load_reference_data()
    known = {str(r.get("key", "")).lower() for r in ref.web_categories}
    known |= {str(r.get("key", "")).lower() for r in ref.proxy_categories}

    found: list[DiscoveredValue] = []
    for field_name in ("category", "categories"):
        for value in profile.values(field_name):
            if not _AI_CATEGORY.search(value):
                continue
            found.append(
                DiscoveredValue(
                    value=value,
                    field_name=field_name,
                    sources=profile.sources_for(field_name, value),
                    in_reference=value.lower() in known,
                )
            )
    found.sort(key=lambda v: (v.field_name, v.value))
    return found


def discover_alert_names(
    client: ExaClient,
    *,
    profile: TenantProfile | None = None,
    lookback_days: int = 30,
    refresh: bool = False,
) -> list[DiscoveredValue]:
    """Find AI-related values in the ``event.alert_name`` CIM field.

    This is the namespace the AI/LLM Alerts dashboard and any
    ``ContextListContains('AI/LLM DLP Rulesets', toLower(alert_name))`` rule
    match against — NOT the Threat Center alert names returned by
    ``discover_alerts.discover_ai_activity``. The two do not intersect
    (EXA-ALERTNAME-TWO-NAMESPACES); populating the table from the wrong one
    yields a table full of records that match nothing.
    """
    from exa.aillm.reference import load_reference_data

    profile = profile or collect_tenant_profile(
        client, lookback_days=lookback_days, refresh=refresh
    )
    known = {
        str(r.get("key", "")).lower()
        for r in load_reference_data().dlp_rulesets
    }

    found = [
        DiscoveredValue(
            value=value,
            field_name="alert_name",
            sources=profile.sources_for("alert_name", value),
            in_reference=value.lower() in known,
        )
        for value in profile.values("alert_name")
        if _AI_ALERT.search(value)
    ]
    found.sort(key=lambda v: v.value)
    return found


def search_logs_for_ai_domains(
    client: ExaClient,
    *,
    lookback_days: int = 30,
    limit: int = 50_000,  # noqa: ARG001 - retained for signature compatibility
) -> list[str]:
    """AI domains seen in logs, as a plain list (backwards-compatible shim).

    Returns only domains that matched reference data. Callers feed this straight
    into ``merge_aillm_data(discovered_domains=...)`` and thence into a context
    table, so unreviewed candidates must not be included — the previous
    implementation returned every domain in the tenant.

    Use ``discover_ai_domains()`` for the classified result including candidates.
    """
    return discover_ai_domains(client, lookback_days=lookback_days).safe_to_sync

"""Discover AI/LLM domains from Exabeam proxy/web logs.

Queries the Exabeam Search API for distinct web_domain values from
web-activity events over a configurable lookback window. Results are
passed to merge_aillm_data() to augment bundled reference data.

CIM2 field: web_domain (NOT domain — per CLAUDE.md)
activity_type values: web-activity-allowed, web-activity-denied
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from exa.client import ExaClient

# Covers both allowed and denied proxy/web events
_WEB_ACTIVITY_FILTER = (
    'activity_type:"web-activity-allowed" OR activity_type:"web-activity-denied"'
)


def search_logs_for_ai_domains(
    client: ExaClient,
    *,
    lookback_days: int = 30,
    limit: int = 50_000,
) -> list[str]:
    """Query Exabeam proxy/web logs for distinct web_domain values.

    Uses the Search API with group_by to return one row per unique domain
    seen in proxy/web-activity events over the lookback window. The caller
    is responsible for merging results with reference data via
    merge_aillm_data(discovered_domains=...).

    Args:
        client: Authenticated ExaClient.
        lookback_days: Days to look back in proxy/web logs (default 30).
        limit: Max distinct domain values to return (default 50_000).

    Returns:
        Sorted list of distinct domain strings found in logs.
    """
    from exa.search.events import search_events

    rows = search_events(
        client,
        _WEB_ACTIVITY_FILTER,
        fields=["web_domain"],
        lookback_days=lookback_days,
        limit=limit,
        group_by=["web_domain"],
    )

    seen: set[str] = set()
    domains: list[str] = []
    for row in rows:
        domain = row.get("web_domain", "").strip()
        if domain and domain.lower() not in seen:
            seen.add(domain.lower())
            domains.append(domain)

    return sorted(domains)

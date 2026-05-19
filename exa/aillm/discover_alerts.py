"""Discover AI-related activity from Exabeam for context table enrichment.

Two discovery passes:

  1. Threat Center alert names (all tenants)
     Pulls recent alert names, filters for AI/LLM keywords, and identifies
     names not yet in the 'AI/LLM DLP Rulesets' context table.

  2. AI proxy/agent app names (requires SentinelOne Prompt Security or similar)
     Queries for events matching product:"Prompt Security" and extracts
     distinct `app` field values. Results depend on parser support for that
     data source — `app` is EXA-UNVERIFIED in CIM2.

For web domain discovery use: exa aillm sync --discover-from-logs
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

# Keywords for matching AI-related alert names (mirrors ruleset.py DEFAULT_KEYWORDS).
_AI_KEYWORDS: list[str] = [
    "ai",
    "llm",
    "gpt",
    "genai",
    "gen ai",
    "copilot",
    "claude",
    "openai",
    "gemini",
    "chatgpt",
    "bard",
    "perplexity",
    "midjourney",
    "stable diffusion",
    "artificial intelligence",
    "machine learning",
    "public ai",
    "ai domain",
    "ai application",
    "ai agent",
    "prompt security",
    "prompt injection",
    "data exfiltration",
]
_WORD_BOUNDARY_KW: frozenset[str] = frozenset({"ai", "llm", "gpt"})

# AI proxy product names to search for in event logs.
# product is a verified CIM2 Generic field.
_AI_PROXY_PRODUCTS: list[str] = [
    "Prompt Security",  # SentinelOne Prompt Security / Prompt Security standalone
]

_APPS_TABLE = "AI/LLM Applications"
_RULESETS_TABLE = "AI/LLM DLP Rulesets"


@dataclass
class DiscoverResult:
    """Results from a discover_ai_activity() run."""

    # Threat Center alert name discovery
    alerts_searched: int = 0
    alert_names_found: int = 0
    alert_names_matched: list[str] = field(default_factory=list)
    alert_names_new: list[str] = field(default_factory=list)

    # AI proxy/agent app name discovery
    proxy_events_searched: int = 0
    app_names_found: list[str] = field(default_factory=list)
    app_names_new: list[str] = field(default_factory=list)

    # Write outcomes (populated only when add_rulesets / add_apps is True)
    rulesets_written: int = 0
    apps_written: int = 0

    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _match_ai_keywords(name: str) -> bool:
    """Return True if name matches any AI keyword."""
    name_lower = name.lower()
    for kw in _AI_KEYWORDS:
        kw_lower = kw.lower()
        if kw_lower in _WORD_BOUNDARY_KW:
            if re.search(rf"\b{re.escape(kw_lower)}\b", name_lower):
                return True
        else:
            if kw_lower in name_lower:
                return True
    return False


def _known_app_names(ref_apps: list[dict[str, str]]) -> set[str]:
    return {a.get("key", "").lower() for a in ref_apps if a.get("key")}


def _known_dlp_names(ref_dlp: list[dict[str, str]]) -> set[str]:
    return {d.get("key", "").lower() for d in ref_dlp if d.get("key")}


def _find_table(
    tables: list[dict[str, Any]], display_name: str
) -> dict[str, Any] | None:
    dn = display_name.lower()
    for t in tables:
        td = (t.get("displayName") or t.get("name", "")).lower()
        if td == dn:
            return t
    return None


# ---------------------------------------------------------------------------
# Phase 1: Threat Center alert names
# ---------------------------------------------------------------------------


def _discover_alert_names(
    client: ExaClient,
    result: DiscoverResult,
    lookback_days: int,
    alert_limit: int,
    known_dlp: set[str],
) -> None:
    from exa.case.alerts import search_alerts

    try:
        alerts = search_alerts(
            client,
            fields=["alertName"],
            lookback_days=lookback_days,
            limit=alert_limit,
        )
    except Exception as e:
        result.errors.append(f"Alert search failed: {e}")
        return

    result.alerts_searched = len(alerts)

    unique_names: set[str] = set()
    for a in alerts:
        name = a.get("alertName", "").strip()
        if name:
            unique_names.add(name)
    result.alert_names_found = len(unique_names)

    matched = sorted(n for n in unique_names if _match_ai_keywords(n))
    result.alert_names_matched = matched
    result.alert_names_new = [n for n in matched if n.lower() not in known_dlp]


# ---------------------------------------------------------------------------
# Phase 2: AI proxy/agent app names
# ---------------------------------------------------------------------------


def _discover_app_names(
    client: ExaClient,
    result: DiscoverResult,
    lookback_days: int,
    event_limit: int,
    known_apps: set[str],
) -> None:
    from exa.search.events import search_events

    for product in _AI_PROXY_PRODUCTS:
        filter_str = f'product:"{product}"'
        try:
            rows = search_events(
                client,
                filter_str,
                fields=["app", "alert_name", "action", "category"],  # app: EXA-UNVERIFIED
                lookback_days=lookback_days,
                limit=event_limit,
            )
        except Exception as e:
            result.errors.append(f"Event search for product={product!r} failed: {e}")
            continue

        result.proxy_events_searched += len(rows)

        seen: set[str] = set()
        for row in rows:
            # app is EXA-UNVERIFIED — may be absent depending on parser
            name = (row.get("app") or "").strip()
            if name and name.lower() not in seen:
                seen.add(name.lower())
                if name not in result.app_names_found:
                    result.app_names_found.append(name)

    result.app_names_found = sorted(result.app_names_found)
    result.app_names_new = [
        n for n in result.app_names_found if n.lower() not in known_apps
    ]


# ---------------------------------------------------------------------------
# Phase 3: Optional writes
# ---------------------------------------------------------------------------


def _write_rulesets(
    client: ExaClient, result: DiscoverResult, new_names: list[str]
) -> None:
    from exa.context.tables import add_records, get_all_records, get_tables

    tables = get_tables(client)
    target = _find_table(tables, _RULESETS_TABLE)
    if not target:
        result.errors.append(
            f"Table '{_RULESETS_TABLE}' not found — run 'exa aillm sync' first."
        )
        return

    table_id = target["id"]
    try:
        existing = get_all_records(client, table_id)
        existing_keys = {r.get("key", "").lower() for r in existing if r.get("key")}
    except Exception:
        existing_keys = set()

    to_write = [n for n in new_names if n.lower() not in existing_keys]
    if not to_write:
        return

    records = [{"key": n} for n in to_write]
    add_records(client, table_id, records, operation="append")
    result.rulesets_written = len(to_write)


def _write_apps(
    client: ExaClient, result: DiscoverResult, new_apps: list[str]
) -> None:
    from exa.context.tables import add_records, get_all_records, get_tables

    tables = get_tables(client)
    target = _find_table(tables, _APPS_TABLE)
    if not target:
        result.errors.append(
            f"Table '{_APPS_TABLE}' not found — run 'exa aillm sync' first."
        )
        return

    table_id = target["id"]
    try:
        existing = get_all_records(client, table_id)
        existing_keys = {r.get("key", "").lower() for r in existing if r.get("key")}
    except Exception:
        existing_keys = set()

    to_write = [n for n in new_apps if n.lower() not in existing_keys]
    if not to_write:
        return

    records = [{"key": n} for n in to_write]
    add_records(client, table_id, records, operation="append")
    result.apps_written = len(to_write)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def discover_ai_activity(
    client: ExaClient,
    *,
    lookback_days: int = 30,
    alert_limit: int = 3000,
    event_limit: int = 10000,
    add_rulesets: bool = False,
    add_apps: bool = False,
) -> DiscoverResult:
    """Discover AI-related activity across Threat Center and proxy/agent event logs.

    Phase 1 — Threat Center alert names:
      Pulls recent alert names, filters for AI/LLM keywords, and identifies
      names not yet in the bundled DLP reference data.

    Phase 2 — AI proxy/agent app names:
      Queries for events from products in _AI_PROXY_PRODUCTS (e.g. SentinelOne
      Prompt Security) and extracts distinct `app` field values. CIM2 field `app`
      is EXA-UNVERIFIED — results depend on parser support.

    Args:
        client: Authenticated ExaClient.
        lookback_days: Days to look back for alerts and events (default 30).
        alert_limit: Max alerts to pull from Threat Center (default 3000).
        event_limit: Max events to pull per proxy product query (default 10000).
        add_rulesets: Write matched alert names to AI/LLM DLP Rulesets table.
        add_apps: Write discovered app names to AI/LLM Applications table.

    Returns:
        DiscoverResult with all findings and optional write outcomes.
    """
    from exa.aillm.reference import load_reference_data

    ref = load_reference_data()
    known_apps = _known_app_names(ref.applications)
    known_dlp = _known_dlp_names(ref.dlp_rulesets)

    result = DiscoverResult()

    _discover_alert_names(client, result, lookback_days, alert_limit, known_dlp)
    _discover_app_names(client, result, lookback_days, event_limit, known_apps)

    if add_rulesets and result.alert_names_new:
        try:
            _write_rulesets(client, result, result.alert_names_new)
        except Exception as e:
            result.errors.append(f"Write rulesets failed: {e}")

    if add_apps and result.app_names_new:
        try:
            _write_apps(client, result, result.app_names_new)
        except Exception as e:
            result.errors.append(f"Write apps failed: {e}")

    return result

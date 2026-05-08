"""Sync the AI/LLM DLP Rulesets context table from live alert history.

Pulls actual Exabeam alert names from the Threat Center for the past N days,
filters them against AI/LLM keywords, and writes matching names to the
'AI/LLM DLP Rulesets' context table.

This complements the static reference data approach: instead of generic vendor
DLP pattern names, we use the real correlation rule names already firing in
the tenant — these are the strings that appear in BigQuery alert_name and make
the Looker dashboard tiles show data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from rich.console import Console

from exa.case.alerts import search_alerts
from exa.context.tables import add_records, get_all_records, get_tables

if TYPE_CHECKING:
    from exa.client import ExaClient

console = Console()

# Default keyword set — case-insensitive substring match against alert name.
# Covers Exabeam OOTB rules and common custom rule naming conventions.
DEFAULT_KEYWORDS: list[str] = [
    "ai",
    "llm",
    "genai",
    "gen ai",
    "gpt",
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
    "dlp",
]

_TABLE_DISPLAY_NAME = "AI/LLM DLP Rulesets"


@dataclass
class SyncRulesetResult:
    """Result of a sync-ruleset run."""

    alerts_searched: int = 0
    alert_names_found: int = 0
    keyword_matched: int = 0
    already_present: int = 0
    upserted: int = 0
    error: str = ""

    @property
    def success(self) -> bool:
        return not self.error


def _match_keywords(name: str, keywords: list[str]) -> bool:
    """Return True if any keyword appears in the alert name (case-insensitive)."""
    name_lower = name.lower()
    return any(kw.lower() in name_lower for kw in keywords)


def sync_dlp_ruleset(
    client: ExaClient,
    *,
    lookback_days: int = 90,
    keywords: list[str] | None = None,
    limit: int = 3000,
    dry_run: bool = False,
    force: bool = False,
) -> SyncRulesetResult:
    """Pull AI/LLM-related alert names from this tenant and sync to the
    'AI/LLM DLP Rulesets' context table.

    Args:
        client: Authenticated ExaClient.
        lookback_days: How far back to search for alerts (default 90).
        keywords: Alert name substrings to match (default: DEFAULT_KEYWORDS).
        limit: Max alerts to pull per search call (max 3000).
        dry_run: Preview matched names without writing.
        force: Replace all existing records instead of appending new ones.

    Returns:
        SyncRulesetResult with counts and any error detail.
    """
    kw = keywords if keywords is not None else DEFAULT_KEYWORDS
    result = SyncRulesetResult()

    # Step 1: Pull recent alert names from Threat Center
    console.print(
        f"  Searching alerts (last {lookback_days} days, limit {limit})...",
        style="dim",
    )
    try:
        alerts = search_alerts(
            client,
            fields=["alertName"],
            lookback_days=lookback_days,
            limit=limit,
        )
    except Exception as e:
        result.error = f"Alert search failed: {e}"
        return result

    result.alerts_searched = len(alerts)
    console.print(f"  {result.alerts_searched} alerts returned", style="dim")

    # Step 2: Deduplicate alert names
    raw_names: set[str] = set()
    for a in alerts:
        name = a.get("alertName", "").strip()
        if name:
            raw_names.add(name)
    result.alert_names_found = len(raw_names)

    # Step 3: Filter by keywords
    matched: list[str] = sorted(
        name for name in raw_names if _match_keywords(name, kw)
    )
    result.keyword_matched = len(matched)

    if not matched:
        console.print(
            "  No AI/LLM-related alert names found in recent history.",
            style="yellow",
        )
        console.print(
            "  Tip: expand --lookback or check that AI/LLM rules are enabled.",
            style="dim",
        )
        return result

    console.print(f"  Matched {result.keyword_matched} AI/LLM alert names:")
    for name in matched:
        console.print(f"    • {name}")

    if dry_run:
        console.print("\n  Dry run — no changes written.", style="dim")
        return result

    # Step 4: Find the target context table
    tables = get_tables(client)
    target = next(
        (
            t for t in tables
            if (t.get("displayName") or t.get("name", "")) == _TABLE_DISPLAY_NAME
        ),
        None,
    )
    if target is None:
        result.error = (
            f"Context table '{_TABLE_DISPLAY_NAME}' not found. "
            "Run 'exa aillm sync' first to create it."
        )
        return result

    table_id = target["id"]
    operation = "replace" if force else "append"

    # Step 5: Dedup against existing records (append mode only)
    records = [{"key": name} for name in matched]
    if operation == "append":
        try:
            existing = get_all_records(client, table_id)
            existing_keys = {r.get("key", "").lower() for r in existing if r.get("key")}
            new_records = [r for r in records if r["key"].lower() not in existing_keys]
            result.already_present = len(records) - len(new_records)
            records = new_records
        except Exception:
            pass  # Proceed without dedup on error

    result.already_present = result.keyword_matched - len(records)

    if not records:
        console.print(
            "  All matched names already present in the context table.",
            style="dim",
        )
        return result

    # Step 6: Write to context table
    console.print(
        f"  Writing {len(records)} new alert names to '{_TABLE_DISPLAY_NAME}' "
        f"({operation})...",
        end="",
    )
    try:
        add_records(client, table_id, records, operation=operation)
        console.print(" OK", style="green")
        result.upserted = len(records)
    except Exception as e:
        console.print(f" FAILED: {e}", style="red")
        result.error = str(e)

    return result

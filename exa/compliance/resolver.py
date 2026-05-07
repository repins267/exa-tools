"""Field Oracle-backed concept resolver for compliance queries.

Translates semantic concept names (GROUP_MANAGEMENT, AUTH_SUCCESS, etc.)
to CIM2 activity_type values, optionally filtered to types confirmed active
in the target tenant.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from exa.compliance.concepts import CONCEPT_ACTIVITY_MAP, PHYSICAL_ACCESS

if TYPE_CHECKING:
    from exa.client import ExaClient


class ConceptResolver:
    """Resolves compliance concepts to CIM2 activity_type lists.

    Lazy-loads the Field Oracle cache from ~/.exa/cache/field_oracle.json.
    Degrades gracefully when the cache is absent — returns the full static
    mapping from CONCEPT_ACTIVITY_MAP in that case.
    """

    def __init__(self) -> None:
        self._oracle: dict[str, Any] | None = None
        self._loaded: bool = False

    def _get_oracle(self) -> dict[str, Any] | None:
        if not self._loaded:
            try:
                path = Path.home() / ".exa" / "cache" / "field_oracle.json"
                text = path.read_text(encoding="utf-8") if path.exists() else None
                self._oracle = json.loads(text) if text is not None else None
            except Exception:
                self._oracle = None
            self._loaded = True
        return self._oracle

    def oracle_version(self) -> str:
        """Return oracle built_at timestamp, or 'no-cache' if unavailable."""
        oracle = self._get_oracle()
        if oracle:
            return oracle.get("built_at", "unknown")
        return "no-cache"

    def active_activity_types(
        self,
        client: ExaClient,
        lookback_days: int = 30,
    ) -> set[str]:
        """Query the tenant for distinct activity_type values seen recently.

        Returns an empty set on any failure — never raises. The empty set
        signals the caller to fall back to static (unfiltered) resolution.
        """
        try:
            from exa.search.events import search_events

            rows = search_events(
                client,
                "*",
                fields=["activity_type"],
                group_by=["activity_type"],
                lookback_days=lookback_days,
                limit=200,
            )
            if isinstance(rows, list):
                return {r["activity_type"] for r in rows if r.get("activity_type")}
            return set()
        except Exception:
            return set()

    def resolve(
        self,
        concepts: list[str],
        active_types: set[str] | None = None,
    ) -> list[str]:
        """Return deduplicated activity_types for the given concept list.

        Args:
            concepts: List of concept name strings (e.g. ["GROUP_MANAGEMENT"]).
            active_types: Set of activity_types confirmed present in the tenant.
                If None, returns the full static list (static/fallback mode).

        Returns:
            Deduplicated list of activity_type strings, stable-sorted.
            PHYSICAL_ACCESS types are always included regardless of active_types
            (0 results means missing log source, not wrong query).
        """
        result: list[str] = []
        seen: set[str] = set()

        for concept in concepts:
            is_physical = (concept == PHYSICAL_ACCESS)
            for at in CONCEPT_ACTIVITY_MAP.get(concept, []):
                if at in seen:
                    continue
                seen.add(at)
                if active_types is None or at in active_types or is_physical:
                    result.append(at)

        return sorted(result)

"""Dynamic EQL query builder for compliance controls.

Translates a list of concept names into an EQL filter string, with
graceful fallback to a static filter when concept resolution yields
no results.
"""

from __future__ import annotations

from exa.compliance.resolver import ConceptResolver


class ComplianceQueryBuilder:
    """Builds EQL filter strings from semantic concept lists.

    Uses ConceptResolver to map concepts → activity_types, then formats
    them as: activity_type:"X" OR activity_type:"Y" ...

    Falls back to the static `fallback_filter` when:
      - No concepts provided
      - Active-type filtering removes all resolved types
      - Resolver returns empty for the given concepts
    """

    def __init__(self, resolver: ConceptResolver) -> None:
        self._resolver = resolver

    def build(
        self,
        concepts: list[str],
        *,
        fallback_filter: str | None = None,
        active_types: set[str] | None = None,
    ) -> str:
        """Build an EQL filter string from concept names.

        Args:
            concepts: Concept names to resolve (e.g. ["GROUP_MANAGEMENT"]).
            fallback_filter: Static EQL filter to use when resolution yields
                nothing. Typically the hardcoded filter from ControlQueries JSON.
            active_types: Tenant-active activity_types from ConceptResolver.
                Pass None for static (unfiltered) mode.

        Returns:
            EQL filter string, or fallback_filter, or "" if both are empty.
        """
        if not concepts:
            return fallback_filter or ""

        types = self._resolver.resolve(concepts, active_types)
        if not types:
            return fallback_filter or ""

        return " OR ".join(f'activity_type:"{t}"' for t in types)

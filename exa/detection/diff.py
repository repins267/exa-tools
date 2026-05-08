"""Pure diff utility for comparing detection rule lists."""

from __future__ import annotations

from typing import Any


def diff_rules(
    rules_a: list[dict[str, Any]],
    rules_b: list[dict[str, Any]],
    *,
    key: str = "id",
) -> dict[str, Any]:
    """Compare two rule lists and return added/removed/changed sets.

    Args:
        rules_a: Baseline rule list (e.g. exported snapshot).
        rules_b: Current rule list (e.g. live tenant).
        key: Field name used as the unique rule identifier (default "id").

    Returns:
        Dict with keys:
          added     list[dict]  Rules in b but not in a.
          removed   list[dict]  Rules in a but not in b.
          changed   list[dict]  Rules present in both but with differing fields
                                (each entry has "id", "before", "after").
          unchanged int         Count of identical rules.
    """
    index_a: dict[str, dict[str, Any]] = {r[key]: r for r in rules_a if key in r}
    index_b: dict[str, dict[str, Any]] = {r[key]: r for r in rules_b if key in r}

    added = [index_b[k] for k in index_b if k not in index_a]
    removed = [index_a[k] for k in index_a if k not in index_b]

    changed: list[dict[str, Any]] = []
    unchanged = 0
    for k in index_a:
        if k not in index_b:
            continue
        ra, rb = index_a[k], index_b[k]
        field_diffs = {
            field: {"before": ra.get(field), "after": rb.get(field)}
            for field in set(ra) | set(rb)
            if ra.get(field) != rb.get(field)
        }
        if field_diffs:
            changed.append({key: k, "changes": field_diffs})
        else:
            unchanged += 1

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged": unchanged,
    }

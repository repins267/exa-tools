"""EQL overflow compression for SPL-converted correlation rules.

When generated EQL exceeds Exabeam's 1024-char API limit, compresses large
wildcard value lists into compact RGXi() alternations.

Strategy:
  - Groups sigma detection selection entries by base field name
  - For fields with >= MIN_VALUES total values across all modifiers:
    collapses N WLDi()/exact terms into one RGXi("alt1|alt2|...") term
  - Exact-value fields (no wildcards) are recorded as TableCandidate
    and written to .tables.json for reference — NOTE: Exabeam EQL has no
    supported LOOKUP/membership syntax for correlation rules (confirmed live
    2026-05-12, see EXA-LOOKUP-UNSUPPORTED in CLAUDE.md). The only fix for
    oversized exact-value lists is splitting into multiple rules.
  - Never touches the filter/negation block
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from typing import Any


_MIN_VALUES = 5  # fields with >= this many values are candidates for compression


@dataclass
class TableCandidate:
    """A large exact-value list that could live in a context table."""
    field: str
    table_name: str
    values: list[str]


@dataclass
class CompressResult:
    sigma_dict: dict[str, Any]          # modified sigma dict (or original if unchanged)
    compressed_fields: list[str]        # base field names that were collapsed to RGXi
    table_candidates: list[TableCandidate]  # exact-value fields suitable for a table


def _parse_modifier(key: str) -> tuple[str, str | None]:
    """Return (base_field_name, modifier) from a sigma detection key."""
    if "|" in key:
        base, mod = key.split("|", 1)
        return base, mod
    return key, None


def _val_to_regex_part(modifier: str | None, val: str) -> str:
    """Convert a sigma field value + modifier to a regex fragment.

    modifier: "startswith" | "endswith" | "contains" | "re" | None
    val: stripped sigma value (leading/trailing * already removed by _wildcard_key)
    """
    if modifier == "re":
        return val  # already a regex pattern

    def _glob_to_inner(s: str) -> str:
        """Convert a string (possibly with embedded *) to a regex fragment."""
        parts = s.split("*")
        return ".*".join(re.escape(p) for p in parts)

    if modifier == "startswith":
        return "^" + _glob_to_inner(val)

    if modifier == "endswith":
        return _glob_to_inner(val) + "$"

    if modifier == "contains":
        return _glob_to_inner(val)

    # No modifier (exact match from sigma) — val may have * in middle if
    # _wildcard_key could not classify it (star not at start or end of value)
    if "*" in val:
        inner = _glob_to_inner(val)
        return f"^{inner}$"

    return f"^{re.escape(val)}$"


def compress_sigma_selection(
    selection: dict[str, Any],
    min_values: int = _MIN_VALUES,
) -> tuple[dict[str, Any], list[str], list[TableCandidate]]:
    """Compress large value lists in a sigma selection block.

    Groups sigma keys by base field name (stripping modifiers).  Fields with
    >= min_values total values are compressed:
      - wildcard/mixed lists → single ``field|re`` key with regex alternation
      - all-exact lists      → left unchanged but recorded as TableCandidate

    Returns:
        (compressed_selection, compressed_field_names, table_candidates)
    """
    from collections import defaultdict

    groups: dict[str, list[tuple[str | None, list[str]]]] = defaultdict(list)
    for key, values in selection.items():
        base, mod = _parse_modifier(key)
        if not isinstance(values, list):
            values = [values]
        groups[base].append((mod, list(values)))

    compressed: dict[str, Any] = {}
    compressed_fields: list[str] = []
    table_candidates: list[TableCandidate] = []

    for base_field, mod_val_pairs in groups.items():
        total_values = sum(len(vals) for _, vals in mod_val_pairs)

        if total_values < min_values:
            for mod, vals in mod_val_pairs:
                key = f"{base_field}|{mod}" if mod else base_field
                compressed[key] = vals
            continue

        # Determine if all values are exact (no wildcards, no modifiers)
        all_exact = all(
            mod is None and "*" not in v
            for mod, vals in mod_val_pairs
            for v in vals
        )

        if all_exact:
            # Exact-value list — keep as-is; record as table candidate
            exact_vals: list[str] = [v for _, vals in mod_val_pairs for v in vals]
            for mod, vals in mod_val_pairs:
                key = f"{base_field}|{mod}" if mod else base_field
                compressed[key] = vals
            table_candidates.append(TableCandidate(
                field=base_field,
                table_name=f"{base_field} Values",  # caller fills in rule_name prefix
                values=exact_vals,
            ))
            continue

        # Wildcard / mixed list → collapse to a single RGXi alternation
        regex_parts: list[str] = []
        for mod, vals in mod_val_pairs:
            for v in vals:
                part = _val_to_regex_part(mod, v)
                if part:
                    regex_parts.append(part)

        combined = "|".join(regex_parts)
        compressed[f"{base_field}|re"] = [combined]
        compressed_fields.append(base_field)

    return compressed, compressed_fields, table_candidates


def compress_overflow(
    sigma_dict: dict[str, Any],
    rule_name: str,
    min_values: int = _MIN_VALUES,
) -> CompressResult:
    """Compress a sigma dict's selection block to reduce generated EQL length.

    Only modifies the ``detection.selection`` block (never the filter/negation
    block).  Returns a new sigma dict with the selection replaced, plus lists
    of which fields were compressed and which are context table candidates.

    Returns the original sigma_dict unchanged if there is nothing to compress.
    """
    det = sigma_dict.get("detection", {})
    selection = det.get("selection", {})

    if not selection or set(selection.keys()) == {"_empty"}:
        return CompressResult(
            sigma_dict=sigma_dict,
            compressed_fields=[],
            table_candidates=[],
        )

    comp_sel, comp_fields, table_cands = compress_sigma_selection(
        selection, min_values=min_values
    )

    # Attach rule name to table candidate names
    for tc in table_cands:
        tc.table_name = f"{rule_name} - {tc.field} Values"

    if not comp_fields and not table_cands:
        return CompressResult(
            sigma_dict=sigma_dict,
            compressed_fields=[],
            table_candidates=[],
        )

    new_detection = {**det, "selection": comp_sel}
    new_sigma = {**sigma_dict, "detection": new_detection}

    return CompressResult(
        sigma_dict=new_sigma,
        compressed_fields=comp_fields,
        table_candidates=table_cands,
    )

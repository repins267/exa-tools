"""EQL overflow compression for SPL-converted correlation rules.

When generated EQL exceeds Exabeam's 1024-char API limit, compresses large
value lists using two strategies:

  Wildcard lists  → RGXi alternation (field|re with combined regex)
  Exact-value lists → context table substitution (field IN "TableName")

The IN "TableName" syntax is confirmed live against sademodev22 (2026-05-12)
and matches the Exabeam Search Guide § "Query by Context Table".
Max 2 context table references per rule (Exabeam limit).

Filter/negation blocks are also scanned: large exact-value lists there become
NOT field IN "TableName" candidates.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from typing import Any


_MIN_VALUES = 5  # fields with >= this many values are candidates for compression
_MAX_TABLE_REFS = 2  # Exabeam hard limit: max 2 context tables per EQL query


@dataclass
class TableCandidate:
    """A large exact-value list that belongs in a context table."""
    field: str          # sigma detection key (e.g. "SourceIp", "User")
    field_eql: str      # CIM2 field name as it appears in EQL (e.g. "src_ip")
    table_name: str     # display name for the context table
    values: list[str]   # exact values (no wildcards)
    negated: bool = False   # True when this comes from the filter/negation block


@dataclass
class CompressResult:
    sigma_dict: dict[str, Any]          # modified sigma dict (or original if unchanged)
    compressed_fields: list[str]        # base field names collapsed to RGXi
    table_candidates: list[TableCandidate]  # exact-value fields for context table substitution


def _get_eql_field(sigma_field: str) -> str:
    """Return the CIM2/EQL field name for a sigma detection key."""
    from exa.sigma.converter import CIM2_FIELD_MAP
    return CIM2_FIELD_MAP.get(sigma_field, sigma_field)


def _parse_modifier(key: str) -> tuple[str, str | None]:
    """Return (base_field_name, modifier) from a sigma detection key."""
    if "|" in key:
        base, mod = key.split("|", 1)
        return base, mod
    return key, None


def _val_to_regex_part(modifier: str | None, val: str) -> str:
    """Convert a sigma field value + modifier to a regex fragment."""
    if modifier == "re":
        return val

    def _glob_to_inner(s: str) -> str:
        parts = s.split("*")
        return ".*".join(re.escape(p) for p in parts)

    if modifier == "startswith":
        return "^" + _glob_to_inner(val)
    if modifier == "endswith":
        return _glob_to_inner(val) + "$"
    if modifier == "contains":
        return _glob_to_inner(val)

    if "*" in val:
        return f"^{_glob_to_inner(val)}$"
    return f"^{re.escape(val)}$"


def compress_sigma_selection(
    selection: dict[str, Any],
    min_values: int = _MIN_VALUES,
) -> tuple[dict[str, Any], list[str], list[TableCandidate]]:
    """Compress large value lists in a sigma selection block.

    Returns:
        (compressed_selection, rGXi_compressed_field_names, table_candidates)
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

        all_exact = all(
            mod is None and "*" not in v
            for mod, vals in mod_val_pairs
            for v in vals
        )

        if all_exact:
            exact_vals: list[str] = [v for _, vals in mod_val_pairs for v in vals]
            for mod, vals in mod_val_pairs:
                key = f"{base_field}|{mod}" if mod else base_field
                compressed[key] = vals
            table_candidates.append(TableCandidate(
                field=base_field,
                field_eql=_get_eql_field(base_field),
                table_name=f"{base_field} Values",
                values=exact_vals,
                negated=False,
            ))
            continue

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


def _extract_filter_candidates(
    filter_dict: dict[str, Any],
    min_values: int = _MIN_VALUES,
) -> list[TableCandidate]:
    """Extract table candidates from a sigma filter (negation) block.

    The filter block contains fields that are negated in the EQL (NOT ...).
    Large exact-value lists here can be replaced with NOT field IN "TableName".
    """
    candidates: list[TableCandidate] = []
    for sigma_field, values in filter_dict.items():
        if not isinstance(values, list):
            values = [values]
        if len(values) < min_values:
            continue
        if all("*" not in str(v) for v in values):
            candidates.append(TableCandidate(
                field=sigma_field,
                field_eql=_get_eql_field(sigma_field),
                table_name=f"{sigma_field} Values",
                values=[str(v) for v in values],
                negated=True,
            ))
    return candidates


def apply_table_substitutions(eql: str, candidates: list[TableCandidate]) -> str:
    """Replace OR-lists with field IN "TableName" for each table candidate.

    For negated candidates, replaces (field:"v1" OR field:"v2" OR ...) with
    field IN "TableName" — the preceding NOT in the EQL stays intact, giving
    NOT field IN "TableName".

    Returns the patched EQL. If an OR-list is not found verbatim (e.g. due to
    field mapping mismatch), that candidate is skipped silently.
    """
    for tc in candidates:
        field = tc.field_eql
        # Build the exact OR-list string as the sigma converter emits it
        if len(tc.values) == 1:
            or_list = f'{field}:"{tc.values[0]}"'
        else:
            terms = " OR ".join(f'{field}:"{v}"' for v in tc.values)
            or_list = f"({terms})"
        replacement = f'{field} IN "{tc.table_name}"'
        eql = eql.replace(or_list, replacement)
    return eql


def compress_overflow(
    sigma_dict: dict[str, Any],
    rule_name: str,
    min_values: int = _MIN_VALUES,
) -> CompressResult:
    """Compress a sigma dict's selection and filter blocks to reduce EQL length.

    Selection block:
      - wildcard/mixed fields → single RGXi alternation (modifies sigma dict)
      - all-exact fields      → recorded as TableCandidate (sigma dict unchanged;
                                  caller patches EQL via apply_table_substitutions)

    Filter/negation block:
      - all-exact fields      → recorded as negated TableCandidate
                                  (EQL patched via apply_table_substitutions)

    Returns the original sigma_dict unchanged if there is nothing to compress.
    Enforces the 2-table-reference limit: candidates beyond the first 2 are dropped.
    """
    det = sigma_dict.get("detection", {})
    selection = det.get("selection", {})
    filter_block = det.get("filter", {})

    sel_empty = not selection or set(selection.keys()) == {"_empty"}

    # Selection compression
    if not sel_empty:
        comp_sel, comp_fields, sel_table_cands = compress_sigma_selection(
            selection, min_values=min_values
        )
    else:
        comp_sel = selection
        comp_fields = []
        sel_table_cands = []

    # Filter block table candidates (exact-value negation lists)
    filter_table_cands = _extract_filter_candidates(filter_block, min_values=min_values)

    all_table_cands = sel_table_cands + filter_table_cands

    # Apply rule name prefix and enforce max-2-tables limit
    for tc in all_table_cands:
        tc.table_name = f"{rule_name} - {tc.field} Values"
    if len(all_table_cands) > _MAX_TABLE_REFS:
        all_table_cands = all_table_cands[:_MAX_TABLE_REFS]

    if not comp_fields and not all_table_cands:
        return CompressResult(
            sigma_dict=sigma_dict,
            compressed_fields=[],
            table_candidates=[],
        )

    if comp_fields or sel_table_cands:
        new_detection = {**det, "selection": comp_sel}
        new_sigma = {**sigma_dict, "detection": new_detection}
    else:
        new_sigma = sigma_dict

    return CompressResult(
        sigma_dict=new_sigma,
        compressed_fields=comp_fields,
        table_candidates=all_table_cands,
    )

"""Convert parsed Splunk SPL searches to Exabeam EQL correlation rules.
Modelled after exa/sigma/converter.py.  Key differences:
  - Rule prefix is "[Splunk] " instead of "[Sigma] "
  - All Splunk conversions are deploy_ready="Needs review" by design —
    SPL→EQL is lossy (stats/lookups/eval dropped) and require human sign-off
  - Description includes dropped SPL features and data source info
  - Context table hints are generated for lookup references
Pipeline stages that cannot be represented in EQL are noted in warnings:
  stats, eventstats, eval, rex (field extraction), spath, lookup,
  makemv, join, ldapsearch.
Field conditions from the search head ARE converted to EQL where possible.
"""
from __future__ import annotations
import re
from typing import Any
from exa.splunk.field_map import SPL_TO_CIM2, UNVERIFIED_FIELDS, KNOWN_CIM2_FIELDS
from exa.splunk.parser import ParsedSPL, parse_spl
from exa.splunk.source_map import (
    BUILTIN_LOOKUPS,
    LOOKUP_TO_CONTEXT_TABLE,
    INDEX_DISPLAY,
    resolve_activity_type,
)
_MAX_DESC_LEN = 900
_TRUNCATED_SUFFIX = " | (truncated)"
# SPL pipeline stages that are silently dropped with a warning
_DROPPED_STAGE_LABELS: dict[str, str] = {
    "stats": "per-user aggregation (stats)",
    "eventstats": "population-level stats (eventstats)",
    "eval": "computed fields (eval)",
    "rex": "in-query field extraction (rex)",
    "spath": "JSON field extraction (spath)",
    "lookup": "enrichment join (lookup)",
    "inputlookup": "enrichment join (inputlookup)",
    "convert": "time formatting (convert)",
    "fillnull": "null filling (fillnull)",
    "dedup": "deduplication (dedup)",
    "makemv": "multival expansion (makemv)",
    "mvexpand": "multival expansion (mvexpand)",
    "ldapsearch": "LDAP query (ldapsearch)",
    "where": "post-pipeline filter (where)",
    "join": "subsearch join (join)",
    "rename": "field rename (rename)",
    "sort": "result sorting (sort)",
    "strcat": "string concatenation (strcat)",
    "table": "column selection (table)",
}
def _map_spl_field(spl_field: str) -> tuple[str, bool]:
    """Map SPL field to CIM2.
    Returns (cim2_field, is_unverified).
    """
    clean = spl_field.strip("\"'")
    # Normalise array notation: destination.tabs{}.url → destination.tabs.url
    clean_norm = re.sub(r"\{\}", "", clean)
    cim2 = SPL_TO_CIM2.get(clean) or SPL_TO_CIM2.get(clean_norm) or clean
    is_unverified = (
        cim2 in UNVERIFIED_FIELDS
        or (cim2 == clean and cim2 not in KNOWN_CIM2_FIELDS)
    )
    return cim2, is_unverified
def _escape_eql_value(val: str) -> str:
    return val.replace('"', '\\"')
def _condition_to_eql(
    field_name: str,
    op: str,
    value: str,
    warnings: list[str],
) -> str | None:
    """Convert a single SPL field condition to an EQL clause.
    Returns None if the condition cannot be converted.
    """
    cim2, unverified = _map_spl_field(field_name)
    negated = op == "!="
    val = _escape_eql_value(value)
    if unverified:
        warnings.append(f"# EXA-UNVERIFIED field: {field_name} → {cim2}")
    # Wildcard value?
    if "*" in val:
        eql = f'{cim2}:WLDi("{val}")'
    else:
        eql = f'{cim2}:"{val}"'
    return f"NOT {eql}" if negated else eql
def _build_eql_query(
    parsed: ParsedSPL,
    activity_type: str | None,
    warnings: list[str],
) -> str:
    """Build the best-effort EQL query from the parsed SPL.
    Strategy:
      1. activity_type filter (from index/sourcetype mapping)
      2. Field conditions extracted from the search head
      3. | regex conditions from the pipeline
    """
    parts: list[str] = []
    field_mappings: list[dict[str, str]] = []
    # 1. Activity type
    if activity_type:
        parts.append(f'activity_type:"{activity_type}"')
    # 2. Field conditions from head
    for field_name, op, value in parsed.field_conditions:
        clause = _condition_to_eql(field_name, op, value, warnings)
        if clause:
            cim2, _ = _map_spl_field(field_name)
            parts.append(clause)
            field_mappings.append({"spl": field_name, "cim2": cim2, "op": op})
    # 3. | regex conditions
    for reg_field, pattern in parsed.regex_conditions:
        cim2, unverified = _map_spl_field(reg_field)
        if unverified:
            warnings.append(f"# EXA-UNVERIFIED field in regex: {reg_field} → {cim2}")
        parts.append(f'{cim2}:RGXi("{_escape_eql_value(pattern)}")')
        field_mappings.append({"spl": reg_field, "cim2": cim2, "op": "regex"})
    if not parts:
        warnings.append("No convertible filter conditions found — manual EQL required")
        return "/* TODO: manual EQL query required */"
    return " AND ".join(parts)
def _build_description(
    title: str,
    parsed: ParsedSPL,
    activity_type: str | None,
    context_tables: list[str],
) -> str:
    """Build a structured description capped at 900 chars."""
    parts: list[str] = [f"Converted from Splunk search: {title}"]
    # Data source
    src_display = INDEX_DISPLAY.get(parsed.index, f"index={parsed.index}")
    if parsed.sourcetype:
        src_display += f" ({parsed.sourcetype})"
    parts.append(f"Source: {src_display}")
    # Activity type hint
    if activity_type:
        parts.append(f"activity_type hint: {activity_type}")
    # Context table dependencies
    if context_tables:
        parts.append(f"Context tables needed: {', '.join(context_tables)}")
    # Dropped SPL features
    dropped_labels = [
        _DROPPED_STAGE_LABELS.get(s, s) for s in sorted(set(parsed.dropped_stages))
    ]
    if dropped_labels:
        parts.append(f"Dropped (EQL limitation): {'; '.join(dropped_labels)}")
    # Incremental assembly, 900-char cap
    description = ""
    truncated = False
    for p in parts:
        candidate = p if not description else f"{description} | {p}"
        if len(candidate) <= _MAX_DESC_LEN:
            description = candidate
        else:
            truncated = True
            break
    if not description:
        description = " | ".join(parts)
        if len(description) > _MAX_DESC_LEN:
            description = description[: _MAX_DESC_LEN - len(_TRUNCATED_SUFFIX)]
            truncated = True
    if truncated:
        tail = _TRUNCATED_SUFFIX
        if len(description) + len(tail) <= _MAX_DESC_LEN:
            description += tail
        else:
            description = description[: _MAX_DESC_LEN - len(tail)] + tail
    return description
def convert_spl_to_exa_rule(title: str, spl: str) -> dict[str, Any]:
    """Convert a single Splunk SPL search to an Exabeam correlation rule dict.
    Modelled after exa.sigma.converter.convert_to_exa_rule().
    Returns a dict with:
      name            "[Splunk] <title>"
      description     Structured description ≤900 chars
      severity        "medium" (all Splunk conversions default to medium)
      index           Splunk index
      sourcetype      Splunk sourcetype (or None)
      activity_type_hint  CIM2 activity_type for this data source
      eql_query       Best-effort EQL query
      context_tables  Exabeam context tables needed (from lookup references)
      field_mappings  List of {spl, cim2, op} dicts
      dropped_stages  SPL pipeline stages dropped in conversion
      warnings        Conversion warnings (including # EXA-UNVERIFIED notices)
      deploy_ready    Always "Needs review" — Splunk conversions require sign-off
    """
    warnings: list[str] = []
    parsed = parse_spl(spl, title=title)
    # Resolve activity_type
    activity_type = resolve_activity_type(parsed.index, parsed.sourcetype)
    if not activity_type:
        warnings.append(
            f"Unknown index '{parsed.index}' — no activity_type mapping; "
            "add to exa/splunk/source_map.py"
        )
    # Resolve context tables from lookup references
    context_tables: list[str] = []
    for lookup_name in parsed.lookup_names:
        if lookup_name.lower() in BUILTIN_LOOKUPS:
            continue  # Splunk built-in — no context table needed
        ct = LOOKUP_TO_CONTEXT_TABLE.get(lookup_name)
        if ct and ct not in context_tables:
            context_tables.append(ct)
        elif not ct:
            warnings.append(f"Unknown lookup '{lookup_name}' — create context table")
    # Warn about dropped pipeline features
    for stage in sorted(set(parsed.dropped_stages)):
        label = _DROPPED_STAGE_LABELS.get(stage, stage)
        warnings.append(f"Dropped: {label}")
    if parsed.has_ldapsearch:
        warnings.append(
            "LDAP query (ldapsearch) cannot be converted — "
            "use Exabeam user context or AD integration instead"
        )
    if parsed.has_subsearch and not parsed.lookup_names:
        warnings.append(
            "Subsearch detected but no lookup table identified — "
            "manual review required"
        )
    if parsed.has_spath:
        warnings.append(
            "JSON path extraction (spath) not supported in EQL — "
            "fields must be pre-parsed by the Exabeam parser"
        )
    # Build EQL
    eql_query = _build_eql_query(parsed, activity_type, warnings)
    # Deduplicate all warnings, preserving order (EXA-UNVERIFIED fires once per field)
    seen: set[str] = set()
    deduped: list[str] = []
    for w in warnings:
        # For EXA-UNVERIFIED, deduplicate on the field-name portion only
        key = w.split(" -> ")[0] if " -> " in w else w.split(" → ")[0] if " → " in w else w
        if key not in seen:
            seen.add(key)
            deduped.append(w)
    warnings = deduped
    # Build description
    description = _build_description(title, parsed, activity_type, context_tables)
    # All Splunk conversions require human review — too much is lost
    deploy_ready = "Needs review"
    return {
        "name": f"[Splunk] {title}",
        "description": description,
        "severity": "medium",
        "index": parsed.index,
        "sourcetype": parsed.sourcetype,
        "activity_type_hint": activity_type or "",
        "eql_query": eql_query,
        "context_tables": context_tables,
        "dropped_stages": sorted(set(parsed.dropped_stages)),
        "warnings": warnings,
        "deploy_ready": deploy_ready,
    }
def to_api_payload(exa_rule: dict[str, Any], *, enabled: bool = False) -> dict[str, Any]:
    """Convert exa_rule dict to Exabeam correlation rules API payload.
    Matches POST /correlation-rules/v2/rules body schema.
    Disabled by default — all Splunk rules need review before activation.
    """
    return {
        "name": exa_rule["name"],
        "description": exa_rule["description"],
        "severity": exa_rule["severity"],
        "enabled": enabled,
        "sequencesConfig": {
            "sequences": [
                {
                    "name": "Sequence 1",
                    "query": exa_rule["eql_query"],
                    "condition": {
                        "triggerOnAnyMatch": True,
                    },
                }
            ],
            "sequencesExecution": "CREATION_ORDER",
        },
    }

"""Convert parsed Splunk SPL searches to Exabeam EQL correlation rules.

Routes through a Sigma intermediate representation so the battle-tested
exa.sigma.converter handles field mapping, modifier expansion, and EQL
construction.  Pipeline:

    SPL string
        → ParsedSPL          (exa.splunk.parser)
        → Sigma rule dict    (exa.splunk.to_sigma)
        → EQL + metadata     (exa.sigma.converter)
        → Splunk-augmented   (this module)

Splunk conversions require human sign-off (deploy_ready="Needs review") but
escalate to "No" when the Field Oracle is present and a converted field has
passthrough confidence — meaning Exabeam's parser definitions don't recognise
it and the UI would reject the rule with "Field 'x' is unknown".
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from exa.sigma.converter import convert_to_exa_rule as _sigma_convert
from exa.splunk.parser import ParsedSPL, parse_spl
from exa.splunk.source_map import (
    BUILTIN_LOOKUPS,
    INDEX_DISPLAY,
    LOOKUP_TO_CONTEXT_TABLE,
    resolve_activity_type,
)
from exa.splunk.to_sigma import spl_to_sigma_dict, spl_to_sigma_yaml

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


def _build_description(
    title: str,
    parsed: ParsedSPL,
    activity_type: str | None,
    context_tables: list[str],
) -> str:
    """Build a structured description capped at 900 chars."""
    parts: list[str] = [f"Converted from Splunk search: {title}"]
    src_display = INDEX_DISPLAY.get(parsed.index, f"index={parsed.index}")
    if parsed.sourcetype:
        src_display += f" ({parsed.sourcetype})"
    parts.append(f"Source: {src_display}")
    if activity_type:
        parts.append(f"activity_type hint: {activity_type}")
    if context_tables:
        parts.append(f"Context tables needed: {', '.join(context_tables)}")
    dropped_labels = [
        _DROPPED_STAGE_LABELS.get(s, s) for s in sorted(set(parsed.dropped_stages))
    ]
    if dropped_labels:
        parts.append(f"Dropped (EQL limitation): {'; '.join(dropped_labels)}")

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


def _dedup_warnings(warnings: list[str]) -> list[str]:
    """Deduplicate warnings preserving order. EXA-UNVERIFIED deduped on field name."""
    seen: set[str] = set()
    result: list[str] = []
    for w in warnings:
        key = w.split(" → ")[0] if " → " in w else w.split(" -> ")[0] if " -> " in w else w
        if key not in seen:
            seen.add(key)
            result.append(w)
    return result


def convert_spl_to_exa_rule(title: str, spl: str, *, compress: bool = True) -> dict[str, Any]:
    """Convert a single Splunk SPL search to an Exabeam correlation rule dict.

    Returns a dict with:
      name            "[Splunk] <title>"
      description     Structured description ≤900 chars
      severity        "medium" (all Splunk conversions default to medium)
      index           Splunk index
      sourcetype      Splunk sourcetype (or None)
      activity_type_hint  CIM2 activity_type for this data source
      eql_query       Best-effort EQL query
      context_tables  Exabeam context tables needed (from lookup references)
      field_mappings  List of {sigma, cim2, modifier} dicts
      dropped_stages  SPL pipeline stages dropped in conversion
      warnings        Conversion warnings (including EXA-UNVERIFIED notices)
      deploy_ready    Always "Needs review" — Splunk conversions require sign-off
      sigma_yaml      Intermediate Sigma rule in YAML format (for audit/review)
    """
    warnings: list[str] = []
    parsed = parse_spl(spl, title=title)

    blocked: list[tuple[str, str]] = []
    sigma_dict = spl_to_sigma_dict(parsed, title, blocked_out=blocked)

    # has_conditions: True if any non-blocked conditions remain (selection or negation filter)
    det = sigma_dict.get("detection", {})
    det_selection = det.get("selection", {})
    det_filter = det.get("filter", {})
    has_conditions = (
        (bool(det_selection) and set(det_selection.keys()) != {"_empty"})
        or bool(det_filter)
    )

    if has_conditions:
        sigma_result = _sigma_convert(sigma_dict)
        eql_query = sigma_result["eql_query"]
        field_mappings: list[dict[str, str]] = sigma_result["field_mappings"]
        sigma_warnings: list[str] = sigma_result["warnings"]
        sigma_activity: str | None = sigma_result["activity_type_hint"] or None
    else:
        eql_query = ""  # resolved below after activity_type is known
        field_mappings = []
        sigma_warnings = []
        sigma_activity = None

    # Activity type: Sigma converter resolves category-based logsources
    # (e.g. process_creation → process-create). Fall back to source_map for
    # product/service-only logsources (code42, dg, o365, etc.).
    activity_type = sigma_activity
    if not activity_type:
        activity_type = resolve_activity_type(parsed.index, parsed.sourcetype)
        if activity_type and has_conditions:
            # Sigma converter didn't prepend the activity_type filter; add it now
            eql_query = f'activity_type:"{activity_type}" AND {eql_query}'

    # For the no-conditions case: build the simplest valid EQL or fall back to TODO
    if not has_conditions:
        if activity_type:
            eql_query = f'activity_type:"{activity_type}"'
        else:
            eql_query = "/* TODO: manual EQL query required */"
            warnings.append("No convertible filter conditions found — manual EQL required")

    if not activity_type:
        warnings.append(
            f"Unknown index '{parsed.index}' — no activity_type mapping; "
            "add to exa/splunk/source_map.py"
        )

    # Context tables from lookup references
    context_tables: list[str] = []
    for lookup_name in parsed.lookup_names:
        if lookup_name.lower() in BUILTIN_LOOKUPS:
            continue
        ct = LOOKUP_TO_CONTEXT_TABLE.get(lookup_name)
        if ct and ct not in context_tables:
            context_tables.append(ct)
        elif not ct:
            warnings.append(f"Unknown lookup '{lookup_name}' — create context table")

    # Warn about dropped pipeline stages
    for stage in sorted(set(parsed.dropped_stages)):
        warnings.append(f"Dropped: {_DROPPED_STAGE_LABELS.get(stage, stage)}")

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

    # Warnings for stripped invalid fields
    for field_name, reason in blocked:
        warnings.append(f"Stripped field '{field_name}': {reason}")

    # Attempt RGXi compression when EQL is too long and conditions exist
    eql_api_limit = 1024
    overflowed_tables: list[dict[str, Any]] = []
    _compress_warnings: list[str] = []
    if compress and has_conditions and len(eql_query) > eql_api_limit:
        from exa.splunk.compress import compress_overflow as _compress_overflow
        _cr = _compress_overflow(sigma_dict, title)
        if _cr.compressed_fields:
            _comp = _sigma_convert(_cr.sigma_dict)
            _comp_eql: str = _comp["eql_query"]
            if activity_type and not sigma_activity:
                _comp_eql = f'activity_type:"{activity_type}" AND {_comp_eql}'
            if len(_comp_eql) <= eql_api_limit:
                eql_query = _comp_eql
                field_mappings = _comp["field_mappings"]
                sigma_warnings = _comp["warnings"]
                for _f in _cr.compressed_fields:
                    _compress_warnings.append(
                        f"Compressed field '{_f}' wildcard list → RGXi to fit API limit"
                    )
        if _cr.table_candidates:
            overflowed_tables = [
                {"field": tc.field, "table_name": tc.table_name, "values": tc.values}
                for tc in _cr.table_candidates
            ]

    # Sigma warnings first (field-level), then Splunk-level; deduplicate both
    all_warnings = _dedup_warnings(sigma_warnings + warnings + _compress_warnings)

    description = _build_description(title, parsed, activity_type, context_tables)

    # Oracle passthrough: if the oracle cache is present and any converted field
    # has passthrough confidence, Exabeam's parser schema doesn't recognise it —
    # the UI would reject the rule with "Field 'x' is unknown".
    _oracle_available = (Path.home() / ".exa" / "cache" / "field_oracle.json").exists()
    has_oracle_passthrough = _oracle_available and any(
        m.get("confidence") == "passthrough" for m in field_mappings
    )

    if len(eql_query) > eql_api_limit:
        deploy_ready = "EQL too long"
        all_warnings.append(
            f"EQL query is {len(eql_query)} chars (API limit: {eql_api_limit}) — "
            "too large even after RGXi compression; split into multiple rules"
        )
    elif blocked:
        deploy_ready = "No"
    elif has_oracle_passthrough:
        deploy_ready = "No"
    else:
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
        "field_mappings": field_mappings,
        "dropped_stages": sorted(set(parsed.dropped_stages)),
        "warnings": all_warnings,
        "deploy_ready": deploy_ready,
        "sigma_yaml": spl_to_sigma_yaml(parsed, title),
        "overflowed_tables": overflowed_tables,
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

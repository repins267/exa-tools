"""Convert parsed Sigma rules to Exabeam EQL correlation rules.

Maps Sigma detection logic and field names to Exabeam's CIM2 schema
and EQL query syntax.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# Sigma field → Exabeam CIM2 field mapping
CIM2_FIELD_MAP: dict[str, str] = {
    # Process creation — all verified against ExabeamLabs/CIMLibrary Fields_Descriptions.md
    "Image": "process_name",
    "OriginalFileName": "process_name",
    "CommandLine": "command",                        # CIM2: command ✓
    "ParentImage": "parent_process_name",            # CIM2: parent_process_name ✓
    "ParentCommandLine": "parent_process_command_line",  # CIM2: parent_process_command_line ✓
    "User": "user",
    "IntegrityLevel": "process_integrity",           # CIM2: process_integrity ✓ (not integrity_level)
    "ProcessId": "process_id",                       # CIM2: process_id ✓ (not pid)
    "ParentProcessId": "parent_process_id",          # CIM2: parent_process_id ✓ (not ppid)
    "CurrentDirectory": "process_dir",               # CIM2: process_dir ✓ (not directory)
    "Hashes": "file_hash",                           # CIM2: file_hash ✓ (not hash)
    # Network — all verified
    "DestinationPort": "dest_port",
    "dst_port": "dest_port",
    "SourcePort": "src_port",
    "src_port": "src_port",
    "DestinationIp": "dest_ip",                      # CIM2: dest_ip ✓ (ipv4/ipv6 type)
    "dst_ip": "dest_ip",
    "SourceIp": "src_ip",                            # CIM2: src_ip ✓ (ipv4/ipv6 type)
    "src_ip": "src_ip",
    "DestinationHostname": "dest_host",              # CIM2: dest_host ✓
    "action": "action",
    "blocked": "blocked",
    # File — all verified against CIMLibrary
    "TargetFilename": "file_name",
    "SourceFilename": "file_name",
    "filePath": "file_path",
    "file_category": "file_category",
    "file_ext": "file_ext",
    "file_path": "file_path",
    "file_hash": "file_hash",
    "md5": "hash_md5",               # CIM2: hash_md5 ✓
    "sha1": "hash_sha1",             # CIM2: hash_sha1 ✓
    "sha256": "hash_sha256",         # CIM2: hash_sha256 ✓
    "Imphash": "file_hash",          # Sigma imphash → closest CIM2 is file_hash
    # Registry — verified
    "TargetObject": "registry_path",
    "Details": "registry_value",
    # Web proxy
    "c-uri": "url",                                  # CIM2: url ✓
    "cs-uri-stem": "uri_path",                       # CIM2: uri_path ✓ (verified in new-scale-content-hub rules)
    "cs-uri-query": "uri_query",                     # CIM2: uri_query ✓ (verified in new-scale-content-hub rules)
    "r-dns": "web_domain",                           # CIM2: web_domain ✓
    # DNS
    "QueryName": "query",                            # CIM2: query ✓
    # Cloud / AWS — verified from Content-Library-CIM2/DS/Amazon/aws_cloudtrail
    "eventSource": "service_name",
    "eventName": "operation",
    "sourceIPAddress": "src_ip",
    "userIdentity.type": "user_type",
    "userIdentity.arn": "user_arn",
    "requestParameters.bucketName": "bucket_name",
    "responseElements.ConsoleLogin": "alert_name",   # closest CIM2 field; console_login not in CIMLibrary
    # Hostname — verified
    "ComputerName": "dest_host",                     # CIM2: dest_host ✓
    "SourceHostname": "src_host",                    # CIM2: src_host ✓
    # Auth — verified
    "LogonType": "logon_type",
    "TargetUserName": "dest_user",
    "SubjectUserName": "src_user",
    "IpAddress": "src_ip",
    # Generic
    "EventID": "event_id",
    "Channel": "channel",
    "Provider_Name": "channel",                      # CIM2: channel ✓ (provider not in CIMLibrary)
    "Product": "product",
}

# Sigma logsource → Exabeam activity_type hint
LOGSOURCE_ACTIVITY_MAP: dict[str, str] = {
    "process_creation": "process-create",
    "network_connection": "network-connection",
    "firewall": "network-connection",
    "dns_query": "dns-query",
    "file_event": "file-write",
    "registry_event": "registry-write",
    "image_load": "dll-loaded",
    "driver_load": "driver-loaded",
    "authentication": "authentication",
    "cloudtrail": "app-activity",  # CIM2 verified: CloudTrail → app-activity:success
}

# Modifiers that cannot be faithfully converted to EQL
_UNSUPPORTED_MODIFIERS: frozenset[str] = frozenset({
    "base64", "base64offset", "cidr", "wide", "utf16le", "utf16be",
    "utf16", "windash", "expand",
})

# Supported modifier for "all values must match" (AND instead of OR)
_ALL_MODIFIER = "all"


# Known valid CIM2 activity_type values (bundled snapshot from CLAUDE.md)
# Used for validation; cache augments this when available
_BUNDLED_ACTIVITY_TYPES: frozenset[str] = frozenset({
    "web-activity-allowed", "web-activity-denied", "dns-query",
    "dns-response", "network-session", "http-session", "http-traffic",
    "authentication", "process-create", "file-write", "file-delete",
    "rule-trigger", "audit_policy-modify", "physical_location-access",
    "app-activity", "network-connection", "registry-write",
    "dll-loaded", "driver-loaded",
})


_ORACLE_NOT_LOADED = object()  # sentinel for lazy cache
_field_oracle_cache: object = _ORACLE_NOT_LOADED


def _load_field_oracle() -> dict[str, Any] | None:
    """Return the field oracle dict, loading it lazily from cache.

    Returns None if ~/.exa/cache/field_oracle.json does not exist or
    is unreadable. Never raises — always returns None on failure.
    """
    global _field_oracle_cache
    if _field_oracle_cache is not _ORACLE_NOT_LOADED:
        return _field_oracle_cache  # type: ignore[return-value]
    try:
        oracle_path = Path.home() / ".exa" / "cache" / "field_oracle.json"
        if oracle_path.exists():
            _field_oracle_cache = json.loads(oracle_path.read_text(encoding="utf-8"))
        else:
            _field_oracle_cache = None
    except Exception:
        _field_oracle_cache = None
    return _field_oracle_cache  # type: ignore[return-value]


def _check_oracle_confidence(
    oracle: dict[str, Any],
    cim2_field: str,
    activity_type: str | None,
    vendor: str | None,
) -> str:
    """Return 'oracle' if cim2_field is confirmed in the DS/ oracle, else 'schema'."""
    by_at: dict[str, dict[str, list[str]]] = oracle.get("by_activity_type", {})

    # Priority 1: exact activity_type match
    if activity_type and cim2_field in by_at.get(activity_type, {}):
        return "oracle"

    # Priority 2: any activity_type match (field confirmed somewhere in DS/)
    if any(cim2_field in fields for fields in by_at.values()):
        return "oracle"

    return "schema"


def resolve_cim2_field(
    sigma_field: str,
    activity_type: str | None = None,
    vendor: str | None = None,
    *,
    _oracle: dict[str, Any] | None | object = _ORACLE_NOT_LOADED,
) -> tuple[str, str]:
    """Resolve a Sigma field name to a CIM2 field name with confidence rating.

    Returns (cim2_field, confidence) where confidence is one of:
      "oracle"      — field confirmed in DS/ for this activity_type/vendor
      "schema"      — in CIM2_FIELD_MAP but not confirmed in DS/
      "passthrough" — no mapping found anywhere

    Resolution order:
      1. Check oracle raw_to_cim2 for direct raw field translation
      2. Apply CIM2_FIELD_MAP (Sigma → CIM2 name)
      3. Confirm translated name in oracle by_activity_type / by_vendor
      4. If oracle absent, fall back to CIM2_FIELD_MAP silently
    """
    oracle = _load_field_oracle() if _oracle is _ORACLE_NOT_LOADED else _oracle  # type: ignore[assignment]
    base_field = sigma_field.split("|")[0]

    # Step 1: oracle raw_to_cim2 for direct raw → CIM2 match.
    # A hit here is inherently oracle-confidence (extracted from a parser file).
    if oracle is not None:
        raw_cim2: dict[str, str] = oracle.get("raw_to_cim2", {})
        if base_field in raw_cim2:
            return raw_cim2[base_field], "oracle"

    # Step 2: CIM2_FIELD_MAP lookup
    cim2_field = CIM2_FIELD_MAP.get(base_field, base_field)
    in_schema = base_field in CIM2_FIELD_MAP

    # Step 3: oracle confirmation
    if oracle is not None and in_schema:
        confidence = _check_oracle_confidence(oracle, cim2_field, activity_type, vendor)
        return cim2_field, confidence

    if in_schema:
        return cim2_field, "schema"  # oracle absent — schema-only confidence

    return base_field, "passthrough"


def _load_known_activity_types() -> set[str]:
    """Load known activity_type values.

    Tries CIM2 cache first, falls back to bundled snapshot.
    Never fails — always returns at least the bundled set.
    """
    known = set(_BUNDLED_ACTIVITY_TYPES)
    try:
        from exa.update import load_cim2_cache

        cached = load_cim2_cache("activity_types")
        if isinstance(cached, list):
            known.update(str(v) for v in cached)
    except Exception:
        pass  # Cache missing — use bundled snapshot
    return known


def _map_field(sigma_field: str) -> tuple[str, str | None]:
    """Map a Sigma field (with optional modifier) to CIM2.

    Returns (cim2_field, modifier) where modifier is endswith/contains/startswith/None.
    """
    modifier = None
    base_field = sigma_field
    if "|" in sigma_field:
        parts = sigma_field.split("|")
        base_field = parts[0]
        modifier = parts[1] if len(parts) > 1 else None

    cim2 = CIM2_FIELD_MAP.get(base_field, base_field)
    return cim2, modifier


def _escape_eql_value(val: Any) -> str:
    """Escape a value for EQL query string."""
    s = str(val)
    s = s.replace('"', '\\"')
    return s


def _build_field_condition(
    field: str,
    modifier: str | None,
    values: list[Any],
    *,
    sigma_field: str = "",
    warnings: list[str] | None = None,
) -> str:
    """Build an EQL condition for a single field with values."""
    conditions: list[str] = []

    # Detect unsupported modifiers — warn but still attempt conversion
    effective_modifier = modifier
    if modifier and modifier in _UNSUPPORTED_MODIFIERS:
        msg = (
            f"Unsupported modifier '{modifier}' on field "
            f"'{sigma_field or field}' \u2014 EQL may be incomplete"
        )
        if warnings is not None:
            warnings.append(msg)
        effective_modifier = None  # fall back to exact match

    # "all" modifier: AND instead of OR
    use_and = False
    if effective_modifier == _ALL_MODIFIER:
        use_and = True
        effective_modifier = None

    for val in values:
        val_str = str(val)

        if effective_modifier == "endswith":
            conditions.append(f'{field}:WLDi("*{_escape_eql_value(val_str)}")')
        elif effective_modifier == "startswith":
            conditions.append(f'{field}:WLDi("{_escape_eql_value(val_str)}*")')
        elif effective_modifier == "contains":
            conditions.append(f'{field}:WLDi("*{_escape_eql_value(val_str)}*")')
        elif effective_modifier == "re":
            conditions.append(f'{field}:RGXi("{_escape_eql_value(val_str)}")')
        else:
            conditions.append(f'{field}:"{_escape_eql_value(val_str)}"')

    if len(conditions) == 1:
        return conditions[0]
    joiner = " AND " if use_and else " OR "
    return "(" + joiner.join(conditions) + ")"


def _build_selection_eql(
    selection: dict[str, Any],
    warnings: list[str] | None = None,
) -> tuple[str, list[dict[str, str]]]:
    """Build EQL for a single selection block.

    Returns (eql_string, field_mappings) where field_mappings tracks
    what was mapped.
    """
    parts: list[str] = []
    mappings: list[dict[str, str]] = []

    if isinstance(selection, list):
        # List of dicts — OR them together
        sub_parts: list[str] = []
        for item in selection:
            if isinstance(item, dict):
                sub_eql, sub_maps = _build_selection_eql(item, warnings)
                sub_parts.append(sub_eql)
                mappings.extend(sub_maps)
        if len(sub_parts) == 1:
            return sub_parts[0], mappings
        return "(" + " OR ".join(sub_parts) + ")", mappings

    for field_key, values in selection.items():
        if values is None:
            continue
        if not isinstance(values, list):
            values = [values]

        cim2_field, modifier = _map_field(field_key)
        mappings.append(
            {"sigma": field_key, "cim2": cim2_field, "modifier": modifier or "exact"}
        )

        part = _build_field_condition(
            cim2_field, modifier, values,
            sigma_field=field_key, warnings=warnings,
        )
        parts.append(part)

    if len(parts) == 1:
        return parts[0], mappings
    return "(" + " AND ".join(parts) + ")", mappings


def _parse_condition(
    condition: str,
    selections: dict[str, Any],
    *,
    rule_title: str = "",
) -> tuple[str, list[dict[str, str]], list[str]]:
    """Parse a Sigma condition string and build the EQL query.

    Returns (eql_query, field_mappings, warnings).
    Raises SigmaConversionError if a selection name in the condition
    does not match any defined selection.
    """
    from exa.exceptions import SigmaConversionError

    warnings: list[str] = []
    all_mappings: list[dict[str, str]] = []

    # Build EQL for each named selection
    selection_eql: dict[str, str] = {}
    for sel_name, sel_data in selections.items():
        if sel_name == "condition":
            continue
        eql, maps = _build_selection_eql(sel_data, warnings)
        selection_eql[sel_name] = eql
        all_mappings.extend(maps)

    # Parse the condition expression
    expr = condition.strip()

    # Handle "X of Y" patterns
    # "1 of selection_*" → OR of all matching selections
    # "all of selection_*" → AND of all matching selections
    def expand_of_pattern(m: re.Match) -> str:
        quantifier = m.group(1)  # "1", "all"
        pattern = m.group(2)    # "selection_*", "filter_*"

        if pattern.endswith("*"):
            prefix = pattern[:-1]
            matching = [k for k in selection_eql if k.startswith(prefix)]
        else:
            matching = [pattern] if pattern in selection_eql else []

        if not matching:
            warnings.append(f"No selections match pattern: {pattern}")
            return "false"

        parts = [selection_eql[k] for k in matching]
        if quantifier == "all":
            return "(" + " AND ".join(parts) + ")"
        else:
            return "(" + " OR ".join(parts) + ")"

    expr = re.sub(r"(\ball\b|\b\d+)\s+of\s+([\w*]+)", expand_of_pattern, expr)

    # Replace selection names with their EQL
    # Sort by length descending to avoid partial matches
    for sel_name in sorted(selection_eql.keys(), key=len, reverse=True):
        expr = expr.replace(sel_name, f"({selection_eql[sel_name]})")

    # Convert Sigma boolean operators to EQL
    expr = re.sub(r"\band\b", "AND", expr, flags=re.IGNORECASE)
    expr = re.sub(r"\bor\b", "OR", expr, flags=re.IGNORECASE)
    expr = re.sub(r"\bnot\b", "NOT", expr, flags=re.IGNORECASE)

    # Detect unmatched selection names left as literal text
    # After substitution, any bare word that looks like a selection name
    # (not a boolean keyword or parenthesized EQL) indicates a missing selection
    unmatched = re.findall(r"\b(selection\w*|filter\w*)\b", expr)
    if unmatched:
        ctx = f" in rule '{rule_title}'" if rule_title else ""
        raise SigmaConversionError(
            f"Unmatched selection(s) {unmatched}{ctx} "
            f"— not defined in detection block"
        )

    return expr, all_mappings, warnings


_MAX_DESC_LEN = 900
_TRUNCATED_SUFFIX = " | (truncated)"


def _build_description(sigma: dict[str, Any], mitre_tags: list[str]) -> str:
    """Build a structured description with metadata, capped at 900 chars.

    Ported from Convert-SigmaToExaRule.ps1 production logic.
    MITRE/Tags/Use Cases are NOT settable via the correlation rules API,
    so they are packed into the description as structured text.

    Format: "<desc> | Sigma ID: <id> | Author: <author> | MITRE: ... | Tags: ..."
    """
    parts: list[str] = []
    desc = sigma.get("description", "")
    if desc:
        parts.append(str(desc).replace("\n", " ").strip())
    sigma_id = sigma.get("id", "")
    if sigma_id:
        parts.append(f"Sigma ID: {sigma_id}")
    author = sigma.get("author", "")
    if author:
        parts.append(f"Author: {author}")
    refs = sigma.get("references", [])
    if isinstance(refs, list):
        for ref in refs:
            if ref:
                parts.append(f"Reference: {ref}")
    if mitre_tags:
        parts.append(f"MITRE: {','.join(mitre_tags)}")
    tags = sigma.get("tags", [])
    if isinstance(tags, list) and tags:
        parts.append(f"Tags: {','.join(str(t) for t in tags)}")

    # Incremental assembly: add parts until we'd exceed 900 chars
    description = ""
    truncated = False
    for p in parts:
        candidate = p if not description else f"{description} | {p}"
        if len(candidate) <= _MAX_DESC_LEN:
            description = candidate
        else:
            truncated = True
            break

    # Fallback: if nothing fit incrementally, hard-join and truncate
    if not description:
        description = " | ".join(parts)
        if len(description) > _MAX_DESC_LEN:
            description = description[:_MAX_DESC_LEN]
            truncated = True

    if truncated:
        if len(description) + len(_TRUNCATED_SUFFIX) <= _MAX_DESC_LEN:
            description += _TRUNCATED_SUFFIX
        else:
            description = description[:_MAX_DESC_LEN - len(_TRUNCATED_SUFFIX)] + _TRUNCATED_SUFFIX

    return description


def convert_to_exa_rule(sigma: dict[str, Any]) -> dict[str, Any]:
    """Convert a parsed Sigma rule dict to an Exabeam correlation rule.

    Matches Convert-SigmaToExaRule.ps1 production behavior:
    - Rule name always prefixed with "[Sigma] "
    - MITRE/Tags packed into description (API does not support tags)
    - Description capped at 900 chars with truncation indicator

    Returns a dict with:
      - name, description, severity, tags
      - eql_query: the converted EQL filter string
      - field_mappings: list of {sigma, cim2, modifier} dicts
      - warnings: any conversion issues
      - deploy_ready: Yes / Needs review / No
    """
    detection = sigma.get("detection", {})
    condition = ""
    selections: dict[str, Any] = {}

    if isinstance(detection, dict):
        condition = detection.get("condition", "")
        if isinstance(condition, dict):
            condition = str(list(condition.values())[0]) if condition else ""
        selections = {k: v for k, v in detection.items() if k != "condition"}

    # Determine activity type hint from logsource
    logsource = sigma.get("logsource", {})
    if isinstance(logsource, dict):
        category = logsource.get("category", "")
        service = logsource.get("service", "")
        product = logsource.get("product", "")
    else:
        category = service = product = ""

    activity_hint = LOGSOURCE_ACTIVITY_MAP.get(
        category if isinstance(category, str) else "",
        LOGSOURCE_ACTIVITY_MAP.get(service if isinstance(service, str) else "", ""),
    )

    # Build EQL query
    title = sigma.get("title", "Unnamed Sigma Rule")
    eql_query, field_mappings, warnings = _parse_condition(
        condition, selections, rule_title=title,
    )

    # Validate activity_type against known CIM2 values
    if activity_hint:
        known = _load_known_activity_types()
        if activity_hint not in known:
            warnings.append(
                f"activity_type '{activity_hint}' not found in CIM2 "
                f"Data Sources \u2014 rule may not match"
            )
        eql_query = f'activity_type:"{activity_hint}" AND {eql_query}'

    # Map severity
    level = sigma.get("level", "medium")
    severity_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "informational": "Informational"}
    severity = severity_map.get(level, "Medium") if isinstance(level, str) else "Medium"

    # Extract MITRE tags
    tags = sigma.get("tags", [])
    if not isinstance(tags, list):
        tags = [tags] if tags else []
    mitre_tags = [t for t in tags if isinstance(t, str) and t.startswith("attack.")]

    # Rule name: always "[Sigma] " prefix for bulk management
    title = sigma.get("title", "Unnamed Sigma Rule")
    name = f"[Sigma] {title}"

    # Build structured description (MITRE/tags packed in, 900 char cap)
    description = _build_description(sigma, mitre_tags)

    # Oracle-aware confidence check and warnings
    oracle = _load_field_oracle()
    for mapping in field_mappings:
        sigma_f = mapping["sigma"].split("|")[0]
        cim2_f = mapping["cim2"]
        _, confidence = resolve_cim2_field(
            sigma_f, activity_hint or None, product or None,
            _oracle=oracle,
        )
        mapping["confidence"] = confidence
        if confidence == "passthrough":
            warnings.append(f"Unmapped field: {sigma_f} (not in CIM2 DS/)")
        elif confidence == "schema" and oracle is not None:
            ctx = f"{product or 'unknown'}/{activity_hint or 'unknown'}"
            warnings.append(
                f"Field '{cim2_f}' mapped by schema but not confirmed in DS/ "
                f"for {ctx}"
            )

    # Assess deploy readiness
    has_passthrough = any(m.get("confidence") == "passthrough" for m in field_mappings)
    if not eql_query or eql_query.strip() == "":
        deploy_ready = "No"
        warnings.append("Empty EQL query")
    elif len(warnings) > 2:
        deploy_ready = "No"
    elif has_passthrough:
        deploy_ready = "Needs review"
    else:
        deploy_ready = "Yes"

    return {
        "name": name,
        "description": description,
        "severity": severity,
        "sigma_id": sigma.get("id", ""),
        "sigma_status": sigma.get("status", ""),
        "mitre_tags": mitre_tags,
        "logsource": {
            "category": category,
            "product": product,
            "service": service,
        },
        "activity_type_hint": activity_hint,
        "eql_query": eql_query,
        "field_mappings": field_mappings,
        "warnings": warnings,
        "deploy_ready": deploy_ready,
    }


def to_api_payload(exa_rule: dict[str, Any], *, enabled: bool = False) -> dict[str, Any]:
    """Convert exa_rule dict to the Exabeam correlation rules API payload.

    Matches the POST /correlation-rules/v2/rules body schema from
    New-ExaCorrelationRule.ps1.
    """
    return {
        "name": exa_rule["name"],
        "description": exa_rule["description"],
        "severity": exa_rule["severity"].lower(),
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

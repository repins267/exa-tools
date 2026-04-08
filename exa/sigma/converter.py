"""Convert parsed Sigma rules to Exabeam EQL correlation rules.

Maps Sigma detection logic and field names to Exabeam's CIM2 schema
and EQL query syntax.
"""

from __future__ import annotations

import re
from typing import Any

# Sigma field → Exabeam CIM2 field mapping
CIM2_FIELD_MAP: dict[str, str] = {
    # Process creation
    "Image": "process_name",
    "OriginalFileName": "process_name",
    "CommandLine": "command",
    "ParentImage": "parent_process_name",
    "ParentCommandLine": "parent_command",
    "User": "user",
    "IntegrityLevel": "integrity_level",
    "ProcessId": "pid",
    "ParentProcessId": "ppid",
    "CurrentDirectory": "directory",
    "Hashes": "hash",
    # Network
    "DestinationPort": "dest_port",
    "dst_port": "dest_port",
    "SourcePort": "src_port",
    "src_port": "src_port",
    "DestinationIp": "dest_ip",
    "dst_ip": "dest_ip",
    "SourceIp": "src_ip",
    "src_ip": "src_ip",
    "DestinationHostname": "dest_host",
    "action": "action",
    "blocked": "blocked",
    # File
    "TargetFilename": "file_name",
    "SourceFilename": "file_name",
    # Registry
    "TargetObject": "registry_path",
    "Details": "registry_value",
    # DNS
    "QueryName": "query",
    # Cloud / AWS — CIM2 verified from Content-Library-CIM2/DS/Amazon/aws_cloudtrail
    "eventSource": "service_name",  # CIM2: eventSource → service_name (some parsers → src_host)
    "eventName": "operation",  # CIM2: eventName → operation (verified across multiple parsers)
    "sourceIPAddress": "src_ip",
    "userIdentity.type": "user_type",
    "userIdentity.arn": "user_arn",
    "requestParameters.bucketName": "bucket_name",
    "responseElements.ConsoleLogin": "console_login",
    # Auth
    "LogonType": "logon_type",
    "TargetUserName": "dest_user",
    "SubjectUserName": "src_user",
    "IpAddress": "src_ip",
    # Generic
    "EventID": "event_id",
    "Channel": "channel",
    "Provider_Name": "provider",
    "Product": "product",
}

# Sigma logsource → Exabeam activity_type hint
LOGSOURCE_ACTIVITY_MAP: dict[str, str] = {
    "process_creation": "process-created",
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


def _build_field_condition(field: str, modifier: str | None, values: list[Any]) -> str:
    """Build an EQL condition for a single field with values."""
    conditions: list[str] = []

    for val in values:
        val_str = str(val)

        if modifier == "endswith":
            conditions.append(f'{field}:WLDi("*{_escape_eql_value(val_str)}")')
        elif modifier == "startswith":
            conditions.append(f'{field}:WLDi("{_escape_eql_value(val_str)}*")')
        elif modifier == "contains":
            conditions.append(f'{field}:WLDi("*{_escape_eql_value(val_str)}*")')
        elif modifier == "re":
            conditions.append(f'{field}:RGXi("{_escape_eql_value(val_str)}")')
        else:
            conditions.append(f'{field}:"{_escape_eql_value(val_str)}"')

    if len(conditions) == 1:
        return conditions[0]
    return "(" + " OR ".join(conditions) + ")"


def _build_selection_eql(selection: dict[str, Any]) -> tuple[str, list[dict[str, str]]]:
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
                sub_eql, sub_maps = _build_selection_eql(item)
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
        mappings.append({"sigma": field_key, "cim2": cim2_field, "modifier": modifier or "exact"})

        part = _build_field_condition(cim2_field, modifier, values)
        parts.append(part)

    if len(parts) == 1:
        return parts[0], mappings
    return "(" + " AND ".join(parts) + ")"  , mappings


def _parse_condition(
    condition: str,
    selections: dict[str, Any],
) -> tuple[str, list[dict[str, str]], list[str]]:
    """Parse a Sigma condition string and build the EQL query.

    Returns (eql_query, field_mappings, warnings).
    """
    warnings: list[str] = []
    all_mappings: list[dict[str, str]] = []

    # Build EQL for each named selection
    selection_eql: dict[str, str] = {}
    for sel_name, sel_data in selections.items():
        if sel_name == "condition":
            continue
        eql, maps = _build_selection_eql(sel_data)
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
    eql_query, field_mappings, warnings = _parse_condition(condition, selections)

    # Prepend activity type hint if available
    if activity_hint:
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

    # Check for unmapped fields
    unmapped = [m for m in field_mappings if m["sigma"].split("|")[0] == m["cim2"]]
    for um in unmapped:
        if um["sigma"] not in CIM2_FIELD_MAP and "|" not in um["sigma"]:
            warnings.append(f"Unmapped field: {um['sigma']} (passed through as-is)")

    # Assess deploy readiness
    if not eql_query or eql_query.strip() == "":
        deploy_ready = "No"
        warnings.append("Empty EQL query")
    elif len(warnings) > 2:
        deploy_ready = "No"
    elif unmapped:
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

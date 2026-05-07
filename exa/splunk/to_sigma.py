"""Convert ParsedSPL to a Sigma rule dict/YAML for exa.sigma.converter.

Generates a valid Sigma intermediate representation from a parsed SPL search.
Field conditions and regex patterns extracted by parser.py are translated into
Sigma detection blocks; the (index, sourcetype) pair is mapped to a Sigma
logsource so the downstream Sigma converter can resolve activity_type and
apply its battle-tested CIM2 field map.

SPL fields not present in SPL_TO_SIGMA_FIELD pass through unchanged — the
Sigma converter will emit an EXA-UNVERIFIED warning for any field not in its
own CIM2_FIELD_MAP.
"""
from __future__ import annotations

from typing import Any

from exa.splunk.parser import ParsedSPL

# ---------------------------------------------------------------------------
# SPL field name → Sigma-canonical field name
# Keys: names as they appear in SPL search-head conditions
# Values: keys that exa/sigma/converter.py's CIM2_FIELD_MAP recognises
# Fields NOT listed here pass through unchanged → EXA-UNVERIFIED downstream
# ---------------------------------------------------------------------------
SPL_TO_SIGMA_FIELD: dict[str, str] = {
    # Pass-throughs — already Sigma-canonical
    "User": "User",
    "CommandLine": "CommandLine",
    "Image": "Image",
    "ParentImage": "ParentImage",
    "OriginalFileName": "OriginalFileName",
    "IntegrityLevel": "IntegrityLevel",
    "ProcessId": "ProcessId",
    "ParentProcessId": "ParentProcessId",
    "ParentCommandLine": "ParentCommandLine",
    "CurrentDirectory": "CurrentDirectory",
    "Hashes": "Hashes",
    "DestinationIp": "DestinationIp",
    "DestinationPort": "DestinationPort",
    "DestinationHostname": "DestinationHostname",
    "SourceIp": "SourceIp",
    "SourcePort": "SourcePort",
    "SourceHostname": "SourceHostname",
    "TargetFilename": "TargetFilename",
    "TargetObject": "TargetObject",
    "Details": "Details",
    "EventID": "EventID",
    "LogonType": "LogonType",
    "Channel": "Channel",
    "Provider_Name": "Provider_Name",
    "QueryName": "QueryName",
    "eventSource": "eventSource",
    "eventName": "eventName",
    "sourceIPAddress": "sourceIPAddress",
    # SPL variants → Sigma canonical names
    "username": "User",
    "user": "User",
    "user.email": "User",
    "actor": "User",
    "User_Name": "User",
    "UserId": "User",
    "uid": "User",
    "src_ip": "SourceIp",
    "computer.external_ip": "SourceIp",
    "dst_ip": "DestinationIp",
    "dest_ip": "DestinationIp",
    "ComputerName": "ComputerName",
    "computer.hostname": "ComputerName",
    "osHostName": "ComputerName",
    "dest_port": "DestinationPort",
    "src_port": "SourcePort",
    "Command_Line": "CommandLine",
    "processName": "Image",
    # File fields
    "file_name": "TargetFilename",   # Fireamp / DocExchange → CIM2: file_name
    "fileName": "TargetFilename",    # DG / PLM variant → CIM2: file_name
    "filePath": "filePath",          # DG / PLM → pass-through; CIM2 verified below
    "file_path": "filePath",         # generic variant
    "destPath": "filePath",          # DG destination path
    # Process (DG)
    "srcProcess": "Image",           # DG source process → CIM2: process_name
    # User variants
    "destUser": "TargetUserName",    # DG destination user → CIM2: dest_user
    "src_user": "SubjectUserName",   # → CIM2: src_user
    "dest_user": "TargetUserName",   # → CIM2: dest_user
    # Web / URL
    "tabUrl": "c-uri",
    "tab-url": "c-uri",
    "destination.tabs{}.url": "c-uri",
    "URL": "c-uri",
    # Cloud / O365
    "Operation": "eventName",
    "ClientIP": "SourceIp",          # O365 / generic → CIM2: src_ip
    "Application": "Product",
    "Workload": "eventSource",       # O365 workload (Exchange, SharePoint…) → CIM2: service_name
}

# ---------------------------------------------------------------------------
# (index, sourcetype) → Sigma logsource dict
# sourcetype=None = index-only match (mirrors source_map.py convention)
# ---------------------------------------------------------------------------
SPL_TO_SIGMA_LOGSOURCE: dict[tuple[str, str | None], dict[str, str]] = {
    ("ad", None): {"product": "windows", "category": "process_creation"},
    ("ad", "wineventlog"): {"product": "windows", "service": "security"},
    ("o365", None): {"product": "m365", "service": "threat_management"},
    ("ips", None): {"product": "cisco", "service": "firepower"},
    ("c42", None): {"product": "code42", "service": "incydr"},
    ("c42", "c42-file-exposure"): {"product": "code42", "service": "incydr"},
    ("c42", "c42-alerts"): {"product": "code42", "service": "incydr"},
    ("fireamp_stream", None): {"product": "cisco", "service": "amp"},
    ("dg", None): {"product": "digital_guardian", "service": "arc"},
    ("dg", "syslog_csirtexportprocess"): {"product": "digital_guardian", "service": "arc"},
    ("docexchange", None): {"product": "custom", "service": "docexchange"},
    ("plminfoexchangelogs", None): {"product": "oracle", "service": "agile_plm"},
}


def _resolve_logsource(index: str, sourcetype: str | None) -> dict[str, str]:
    """Return Sigma logsource dict for given (index, sourcetype)."""
    idx = index.lower() if index else ""
    stype = sourcetype.lower() if sourcetype else None
    if stype:
        ls = SPL_TO_SIGMA_LOGSOURCE.get((idx, stype))
        if ls:
            return ls
    return SPL_TO_SIGMA_LOGSOURCE.get((idx, None), {"product": "unknown"})


def _map_field(spl_field: str) -> str:
    """Map an SPL field name to its Sigma-canonical equivalent."""
    return SPL_TO_SIGMA_FIELD.get(spl_field, spl_field)


def _wildcard_key(sigma_field: str, value: str) -> tuple[str, str]:
    """Return (field_key_with_modifier, stripped_value) for wildcard SPL values."""
    if value.startswith("*") and value.endswith("*") and len(value) > 2:
        return f"{sigma_field}|contains", value[1:-1]
    if value.startswith("*"):
        return f"{sigma_field}|endswith", value[1:]
    if value.endswith("*"):
        return f"{sigma_field}|startswith", value[:-1]
    return sigma_field, value


def spl_to_sigma_dict(parsed: ParsedSPL, title: str) -> dict[str, Any]:
    """Build a Sigma rule dict from a ParsedSPL.

    The returned dict is shaped so exa.sigma.converter.convert_to_exa_rule()
    can consume it directly without a YAML round-trip.

    All detection values are lists (required by _build_selection_eql).
    Unknown SPL fields pass through as-is; the Sigma converter will emit
    EXA-UNVERIFIED warnings for any field not in its CIM2_FIELD_MAP.
    """
    logsource = _resolve_logsource(parsed.index, parsed.sourcetype)

    selection: dict[str, list[str]] = {}
    negation: dict[str, list[str]] = {}

    for field_name, op, value in parsed.field_conditions:
        sigma_field = _map_field(field_name)
        if "*" in value:
            key, stripped = _wildcard_key(sigma_field, value)
        else:
            key, stripped = sigma_field, value

        target = negation if op == "!=" else selection
        target.setdefault(key, []).append(stripped)

    for reg_field, pattern in parsed.regex_conditions:
        sigma_field = _map_field(reg_field)
        selection.setdefault(f"{sigma_field}|re", []).append(pattern)

    detection: dict[str, Any] = {}
    has_selection = bool(selection)
    has_negation = bool(negation)

    if has_selection:
        detection["selection"] = selection
    else:
        # Placeholder so the Sigma dict is structurally valid; the empty-
        # conditions path in convert_spl_to_exa_rule() short-circuits before
        # calling _sigma_convert(), so this is only used for YAML export.
        detection["selection"] = {"_empty": ["TODO"]}

    if has_negation:
        detection["filter"] = negation

    if has_selection and has_negation:
        detection["condition"] = "selection and not filter"
    elif has_negation:
        detection["condition"] = "not filter"
    else:
        detection["condition"] = "selection"

    return {
        "title": title,
        "status": "experimental",
        "description": f"Converted from Splunk search: {title}",
        "logsource": logsource,
        "detection": detection,
        "level": "medium",
        "tags": [],
    }


# ---------------------------------------------------------------------------
# Minimal YAML serialiser — avoids a PyYAML dependency for the simple
# structure that spl_to_sigma_dict() always produces.
# ---------------------------------------------------------------------------

def _yaml_scalar(value: str) -> str:
    """Return a YAML-safe representation of a string scalar."""
    needs_quote = (
        not value
        or value.lower() in ("true", "false", "null", "yes", "no", "on", "off")
        or any(c in value for c in ":#{}[]|>&*!?,")
        or value[0] in ('"', "'", "-", " ", "@", "`")
    )
    if needs_quote:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return value


def spl_to_sigma_yaml(parsed: ParsedSPL, title: str) -> str:
    """Serialise a ParsedSPL as a Sigma YAML rule string.

    Produces human-readable YAML for audit/review purposes.
    Stored under the 'sigma_yaml' key in the rule dict returned by
    exa.splunk.converter.convert_spl_to_exa_rule().
    """
    sigma = spl_to_sigma_dict(parsed, title)
    lines: list[str] = []

    lines.append(f"title: {_yaml_scalar(sigma['title'])}")
    lines.append(f"status: {sigma['status']}")
    lines.append(f"description: {_yaml_scalar(sigma['description'])}")

    lines.append("logsource:")
    for k, v in sigma["logsource"].items():
        lines.append(f"    {k}: {v}")

    detection = sigma["detection"]
    lines.append("detection:")
    for block_name, block_data in detection.items():
        if block_name == "condition":
            continue
        lines.append(f"    {block_name}:")
        if isinstance(block_data, dict):
            for field_key, field_values in block_data.items():
                lines.append(f"        {field_key}:")
                vals = field_values if isinstance(field_values, list) else [field_values]
                for v in vals:
                    lines.append(f"            - {_yaml_scalar(str(v))}")
    lines.append(f"    condition: {detection['condition']}")

    lines.append(f"level: {sigma['level']}")
    tags = sigma.get("tags", [])
    if tags:
        lines.append("tags:")
        for t in tags:
            lines.append(f"    - {t}")
    else:
        lines.append("tags: []")

    return "\n".join(lines) + "\n"

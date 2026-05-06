"""SPL field name → Exabeam CIM2 field name mapping.

Verified against:
  - exa/sigma/converter.py CIM2_FIELD_MAP (battle-tested)
  - ExabeamLabs/CIMLibrary Fields_Descriptions.md
  - CLAUDE.md Known correct CIM2 field names

Fields marked EXA-UNVERIFIED are not confirmed in CIM2 but are
the best available mapping.  All uses should be reviewed before
deploying rules that depend on them.
"""

from __future__ import annotations

# SPL field → CIM2 field
# Covers all field names observed in the 22 Supply Chain Splunk searches
SPL_TO_CIM2: dict[str, str] = {
    # ── Identity / User ────────────────────────────────────────────────────
    "User": "user",
    "user": "user",
    "username": "user",
    "user.email": "user",
    "actor": "user",
    "User_Name": "user",
    "UserId": "user",
    "computer.user": "user",
    # ── Host / Endpoint ────────────────────────────────────────────────────
    "ComputerName": "dest_host",
    "computer.hostname": "dest_host",
    "Computer_Name": "dest_host",
    "SourceHostname": "src_host",
    "DestinationHostname": "dest_host",
    "osHostName": "dest_host",
    # ── Network ────────────────────────────────────────────────────────────
    "src_ip": "src_ip",
    "SourceIp": "src_ip",
    "computer.external_ip": "src_ip",
    "dst_ip": "dest_ip",
    "DestinationIp": "dest_ip",
    "dest_ip": "dest_ip",
    "DestinationPort": "dest_port",
    "dest_port": "dest_port",
    "SourcePort": "src_port",
    "src_port": "src_port",
    "Protocol": "protocol",
    "web_domain": "web_domain",
    # ── Process ────────────────────────────────────────────────────────────
    "Image": "process_name",
    "processName": "process_name",
    "CommandLine": "command",
    "Command_Line": "command",
    # ── Web / URL ──────────────────────────────────────────────────────────
    "tabUrl": "url",
    "tab-url": "url",
    "destination.tabs{}.url": "url",
    "URL": "url",
    # ── Alert / Rule ───────────────────────────────────────────────────────
    "msg": "alert_name",
    "message": "alert_name",
    "alert_name": "alert_name",
    # ── Service / App ──────────────────────────────────────────────────────
    "Application": "service_name",
    "web_app": "service_name",
    # ── Cloud / O365 ───────────────────────────────────────────────────────
    "Operation": "operation",        # CIM2 verified: O365 operation → operation
    "eventName": "operation",        # CIM2 verified: CloudTrail eventName → operation
    "eventSource": "service_name",   # CIM2 verified: CloudTrail eventSource → service_name
    # ── Severity ───────────────────────────────────────────────────────────
    "severity": "severity",
    # ── File — EXA-UNVERIFIED ──────────────────────────────────────────────
    # Not confirmed in CIM2; flag all uses with # EXA-UNVERIFIED
    "file-name": "file_name",         # EXA-UNVERIFIED
    "file.name": "file_name",         # EXA-UNVERIFIED
    "fileName": "file_name",          # EXA-UNVERIFIED
    "file_name": "file_name",         # EXA-UNVERIFIED
    "event.file.file_name": "file_name",  # EXA-UNVERIFIED (Secure Endpoint)
    "file-path": "file_path",         # EXA-UNVERIFIED
    "file.path": "file_path",         # EXA-UNVERIFIED
    "filePath": "file_path",          # EXA-UNVERIFIED
    "file_path": "file_path",         # EXA-UNVERIFIED
    "event.file.file_path": "file_path",  # EXA-UNVERIFIED
    # ── Code42-specific — EXA-UNVERIFIED ───────────────────────────────────
    "event-type": "activity_type",    # EXA-UNVERIFIED: Code42 event-type → activity_type
    "eventType": "activity_type",     # EXA-UNVERIFIED
    "risk.indicators{}.name": "alert_name",   # EXA-UNVERIFIED
    "riskIndicators{}.name": "alert_name",    # EXA-UNVERIFIED
    "risk.severity": "severity",      # EXA-UNVERIFIED
    # ── Digital Guardian — EXA-UNVERIFIED ──────────────────────────────────
    "DNS Hostname": "dest_host",      # EXA-UNVERIFIED
    "Was Detail Blocked": "blocked",  # EXA-UNVERIFIED
    # ── Sysmon ─────────────────────────────────────────────────────────────
    "TaskCategory": "event_category",  # EXA-UNVERIFIED
}

# Fields whose CIM2 mapping is unverified against the canonical CIM2 schema.
# Any rule that maps to one of these should be flagged deploy_ready="Needs review".
UNVERIFIED_FIELDS: frozenset[str] = frozenset({
    "file_name",
    "file_path",
    "activity_type",   # when mapped from C42 event-type
    "event_category",
    "blocked",
})

# Canonical CIM2 fields (from CLAUDE.md + sigma/converter.py).
# Used to detect pass-through (unmapped) fields.
KNOWN_CIM2_FIELDS: frozenset[str] = frozenset({
    "web_domain", "dest_host", "dest_ip", "src_ip", "dest_port", "src_port",
    "user", "alert_name", "activity_type", "bytes_out", "bytes_in",
    "process_name", "parent_process_name", "command", "url", "category",
    "service_name", "operation", "severity", "protocol", "event_id",
    "file_name", "file_path", "hash", "registry_path", "registry_value",
    "blocked", "src_host", "dest_user", "src_user", "logon_type",
})

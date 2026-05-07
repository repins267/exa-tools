"""Canonical security concept taxonomy for compliance query resolution.

Maps 18 semantic concepts to CIM2 activity_type values. Controls in
ControlQueries/*.json reference these concepts; ConceptResolver translates
them to tenant-specific activity_types at audit time.
"""

from __future__ import annotations

# ── Concept name constants ────────────────────────────────────────────────────
# Used as keys in CONCEPT_ACTIVITY_MAP and in ControlQueries JSON files.

GROUP_MANAGEMENT    = "GROUP_MANAGEMENT"
PERMISSION_CHANGE   = "PERMISSION_CHANGE"
AUTH_SUCCESS        = "AUTH_SUCCESS"
AUTH_FAILURE        = "AUTH_FAILURE"
ACCOUNT_MANAGEMENT  = "ACCOUNT_MANAGEMENT"
NETWORK_TRAFFIC     = "NETWORK_TRAFFIC"
FILE_ACTIVITY       = "FILE_ACTIVITY"
PROCESS_EXECUTION   = "PROCESS_EXECUTION"
PRIVILEGED_ACCESS   = "PRIVILEGED_ACCESS"
AUDIT_LOG           = "AUDIT_LOG"
PHYSICAL_ACCESS     = "PHYSICAL_ACCESS"
EMAIL_ACTIVITY      = "EMAIL_ACTIVITY"
CLOUD_ACTIVITY      = "CLOUD_ACTIVITY"
ENDPOINT_ACTIVITY   = "ENDPOINT_ACTIVITY"
VULNERABILITY_EVENT = "VULNERABILITY_EVENT"
INCIDENT_RESPONSE   = "INCIDENT_RESPONSE"
DATA_EXFILTRATION   = "DATA_EXFILTRATION"
CONFIG_CHANGE       = "CONFIG_CHANGE"

ALL_CONCEPTS: frozenset[str] = frozenset({
    GROUP_MANAGEMENT, PERMISSION_CHANGE, AUTH_SUCCESS, AUTH_FAILURE,
    ACCOUNT_MANAGEMENT, NETWORK_TRAFFIC, FILE_ACTIVITY, PROCESS_EXECUTION,
    PRIVILEGED_ACCESS, AUDIT_LOG, PHYSICAL_ACCESS, EMAIL_ACTIVITY,
    CLOUD_ACTIVITY, ENDPOINT_ACTIVITY, VULNERABILITY_EVENT, INCIDENT_RESPONSE,
    DATA_EXFILTRATION, CONFIG_CHANGE,
})

# ── Concept → CIM2 activity_type mapping ─────────────────────────────────────
# Sourced from CIM2 parser analysis (Field Oracle, 7,382 parsers).
# Activity_types prefixed with # are in the broader CIM2 schema but may not
# appear in every tenant's Field Oracle (still valid to query).

CONCEPT_ACTIVITY_MAP: dict[str, list[str]] = {
    GROUP_MANAGEMENT: [
        "group-modify",
    ],
    PERMISSION_CHANGE: [
        "file-permission-modify",
        "ds_object-modify",
        "audit_policy-modify",
    ],
    AUTH_SUCCESS: [
        "authentication",
        "endpoint-authentication",
    ],
    AUTH_FAILURE: [
        "authentication",
        "endpoint-authentication",
    ],
    ACCOUNT_MANAGEMENT: [
        "account-creation",
        "account-modification",
        "user-modify",
    ],
    NETWORK_TRAFFIC: [
        "network-session",
        "http-session",
        "http-traffic",
        "dns-query",
        "dns-response",
    ],
    FILE_ACTIVITY: [
        "file-read",
        "file-write",
        "file-delete",
        "file-create",
    ],
    PROCESS_EXECUTION: [
        "process-create",
    ],
    # PRIVILEGED_ACCESS maps to authentication — filtered at query time by
    # context table (Compliance - Privileged Users) rather than activity_type
    PRIVILEGED_ACCESS: [
        "authentication",
        "endpoint-authentication",
    ],
    AUDIT_LOG: [
        "audit_policy-modify",
    ],
    # PHYSICAL_ACCESS is never filtered by active_types — 0 results means
    # the log source (e.g. DNA Fusion) is not connected, not a query error.
    PHYSICAL_ACCESS: [
        "physical_location-access",
    ],
    EMAIL_ACTIVITY: [
        "email-send",
    ],
    CLOUD_ACTIVITY: [
        "app-activity",
        "cloud-activity",
    ],
    ENDPOINT_ACTIVITY: [
        "process-create",
        "dll-load",
        "driver-load",
    ],
    VULNERABILITY_EVENT: [
        "alert-trigger",
    ],
    INCIDENT_RESPONSE: [
        "rule-trigger",
        "alert-trigger",
    ],
    DATA_EXFILTRATION: [
        "file-write",
        "network-session",
        "alert-trigger",
    ],
    CONFIG_CHANGE: [
        "registry-modify",
        "registry-create",
        "ds_object-modify",
        "audit_policy-modify",
    ],
}

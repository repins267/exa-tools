"""Splunk index/sourcetype → Exabeam activity_type mapping.

Maps the (index, sourcetype) pairs seen in the Supply Chain searches
to the closest Exabeam CIM2 activity_type.

Where no exact match exists, the index-only fallback is used.
All mappings marked EXA-UNVERIFIED should be reviewed against
Content-Library-CIM2/DS/ before deploying rules.
"""

from __future__ import annotations

# (index, sourcetype) → activity_type
# sourcetype=None means match on index alone (fallback)
SOURCE_TO_ACTIVITY: dict[tuple[str, str | None], str] = {
    # ── Code42 / Incydr ────────────────────────────────────────────────────
    # EXA-UNVERIFIED: Code42 events in Exabeam depend on parser config
    ("c42", None): "file-write",
    ("c42", "c42-file-exposure"): "file-write",
    ("c42", "c42-alerts"): "rule-trigger",
    # ── Active Directory / Sysmon ──────────────────────────────────────────
    ("ad", None): "process-create",              # Default: Sysmon process events
    ("ad", "wineventlog"): "authentication",
    # ── Cisco Firepower IPS ────────────────────────────────────────────────
    ("ips", None): "rule-trigger",
    # ── Microsoft O365 ────────────────────────────────────────────────────
    ("o365", None): "app-activity",
    # ── Cisco Secure Endpoint (AMP / FireAMP) ─────────────────────────────
    ("fireamp_stream", None): "rule-trigger",
    # ── Digital Guardian ──────────────────────────────────────────────────
    # EXA-UNVERIFIED: DG events; file-write is the closest CIM2 activity
    ("dg", None): "file-write",
    ("dg", "syslog_csirtexportprocess"): "process-create",
    # ── Document Exchange (PCB/hardware design files) ─────────────────────
    # EXA-UNVERIFIED: proprietary system, no CIM2 mapping confirmed
    ("docexchange", None): "file-write",
    # ── Agile PLM Info Exchange ────────────────────────────────────────────
    # EXA-UNVERIFIED: PLM document access
    ("plminfoexchangelogs", None): "app-activity",
}

# Human-readable data source descriptions for rule descriptions
INDEX_DISPLAY: dict[str, str] = {
    "c42": "Code42 (Incydr) DLP",
    "ad": "Active Directory / Sysmon",
    "ips": "Cisco Firepower IPS",
    "o365": "Microsoft O365",
    "fireamp_stream": "Cisco Secure Endpoint (AMP)",
    "dg": "Digital Guardian DLP",
    "docexchange": "Document Exchange (PCB/hardware files)",
    "plminfoexchangelogs": "Agile PLM Info Exchange",
}

# Lookup CSV files referenced in the searches and their suggested
# Exabeam context table equivalents.
# Key = Splunk lookup CSV name, Value = suggested Exabeam context table name
LOOKUP_TO_CONTEXT_TABLE: dict[str, str] = {
    "sco_all_users_lookup.csv": "Supply Chain Vendor Users",
    "sco_all_users_lookup": "Supply Chain Vendor Users",
    "High_IP_Table.csv": "Supply Chain High IP Files",
    "High_IP_Table": "Supply Chain High IP Files",
    "ai_hostnames.csv": "AI Platform Hostnames",
    "ai_hostnames": "AI Platform Hostnames",
}

# Splunk built-in lookups that should be silently ignored (not user-created CSVs)
BUILTIN_LOOKUPS: frozenset[str] = frozenset({
    "dnslookup", "geo_attr_ips", "geo_attr_countries",
    "asset_lookup_by_str", "asset_lookup_by_cidr",
    "identity_lookup_expanded",
})


def resolve_activity_type(index: str, sourcetype: str | None) -> str | None:
    """Return activity_type for given index + sourcetype, or None if unknown."""
    idx = index.lower() if index else ""
    stype = sourcetype.lower() if sourcetype else None

    # Try exact (index, sourcetype) match first
    if stype:
        result = SOURCE_TO_ACTIVITY.get((idx, stype))
        if result:
            return result

    # Fall back to index-only
    return SOURCE_TO_ACTIVITY.get((idx, None))

"""Network Zones hot key risk analysis.

Reads the Network Zones context table and classifies each entry by
Dataflow hot key risk based on IP range cardinality.

API base path: /context-management/v1/
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

from exa.context.tables import get_all_records, get_table, get_tables

NETWORK_ZONES_TABLE = "Network Zones"
_COARSE_PREFIX_MAX = 16  # prefix_len ≤ 16 → COARSE (≥65k addresses)
_MEDIUM_PREFIX_MAX = 24  # 17 ≤ prefix_len ≤ 24 → MEDIUM; note /17–/23 are
# conservative (still 32k–8k IPs). scan can still flag them as HOT_KEY_RISK.


@dataclass
class ZoneEntry:
    key: str                # raw record key value (e.g. "10.0.0.0/8")
    zone_name: str          # zone label value (e.g. "Net_10_0_0_0")
    ip_field: str           # column id holding the IP/subnet
    name_field: str         # column id holding the zone label
    table_id: str           # id of the Network Zones table (for write ops)
    table_display_name: str # displayName of the table (for manifests)
    raw: dict[str, Any]     # full original record (for rollback)


@dataclass
class ZoneRisk:
    entry: ZoneEntry
    risk: str                # "COARSE" | "MEDIUM" | "FINE" | "UNKNOWN"
    prefix_len: int | None   # e.g. 8, 16, 24, 32; None for non-CIDR keys
    cardinality: int | None  # net.num_addresses; None for non-CIDR keys


def analyze_zones(
    client: ExaClient,
    *,
    ip_field: str | None = None,
    name_field: str | None = None,
) -> list[ZoneRisk]:
    """Find Network Zones table, read all records, classify each by hot key risk.

    Raises ValueError if the table is not found or schema cannot be detected.
    Pass ip_field / name_field to override auto-detection (--ip-field / --name-field).
    """
    table_meta = _find_network_zones_table(client)
    table_id = table_meta["id"]
    table_display_name = table_meta.get("displayName", NETWORK_ZONES_TABLE)
    table_detail = get_table(client, table_id)
    ip_col, name_col = _detect_schema(table_detail, ip_field=ip_field, name_field=name_field)
    records = get_all_records(client, table_id)
    results: list[ZoneRisk] = []
    for rec in records:
        key = str(rec.get(ip_col, ""))
        zone = str(rec.get(name_col, ""))
        entry = ZoneEntry(
            key=key,
            zone_name=zone,
            ip_field=ip_col,
            name_field=name_col,
            table_id=table_id,
            table_display_name=table_display_name,
            raw=rec,
        )
        risk, prefix_len, cardinality = _classify_zone(key)
        results.append(
            ZoneRisk(entry=entry, risk=risk, prefix_len=prefix_len, cardinality=cardinality)
        )
    return results


def _find_network_zones_table(client: ExaClient) -> dict[str, Any]:
    """Return the Network Zones table matched on displayName or name (case-insensitive substring).

    Prefers displayName per CLAUDE.md OOTB table rule, falls back to name field
    because some tenants have displayName=None (observed on sademodev22).
    """
    tables = get_tables(client)
    needle = NETWORK_ZONES_TABLE.lower()
    for t in tables:
        display = (t.get("displayName") or "").lower()
        internal = (t.get("name") or "").lower()
        if needle in display or needle in internal:
            return t
    sample = [t.get("displayName") or t.get("name", "?") for t in tables[:10]]
    raise ValueError(
        f"Network Zones table not found (searched displayName/name for '{NETWORK_ZONES_TABLE}').\n"
        f"First 10 table names: {sample}\n"
        f"Check the exact name with: exa context list"
    )


def _detect_schema(
    table: dict[str, Any],
    *,
    ip_field: str | None = None,
    name_field: str | None = None,
) -> tuple[str, str]:
    """Return (ip_field_id, name_field_id) from table column metadata.

    Detection strategy:
    1. Use caller overrides if both provided — skip detection entirely.
    2. Column with isKey=True → ip_field (or override if provided).
    3. Remaining columns: match display-name patterns for zone label.
       Fallback: if only one non-key column exists, use it as name_field.
    4. Failure: raise ValueError listing columns + --ip-field/--name-field hint.
    """
    if ip_field and name_field:
        return ip_field, name_field

    # Unwrap {"table": {...}} wrapper that some API versions return
    inner = table.get("table", table)
    columns: list[dict[str, Any]] = inner.get("columns", inner.get("attributes", []))

    key_col: str | None = ip_field
    label_col: str | None = name_field

    if not key_col:
        for col in columns:
            if col.get("isKey") or col.get("id") == "key":
                key_col = col.get("id") or col.get("name")
                break

    name_hints = {"name", "zone", "label", "description", "zonename", "zone_name"}
    non_key_cols = [
        col for col in columns
        if (col.get("id") or col.get("name")) != key_col
    ]

    if not label_col:
        for col in non_key_cols:
            col_id = (col.get("id") or col.get("name") or "").lower().replace("-", "_")
            display = (col.get("displayName") or "").lower()
            if col_id in name_hints or any(h in display for h in name_hints):
                label_col = col.get("id") or col.get("name")
                break
        # Single non-key column — use it regardless of name
        if not label_col and len(non_key_cols) == 1:
            label_col = non_key_cols[0].get("id") or non_key_cols[0].get("name")

    if key_col and label_col:
        return key_col, label_col

    col_summary = [
        (c.get("id"), c.get("displayName"), c.get("isKey")) for c in columns
    ]
    raise ValueError(
        f"Cannot auto-detect Network Zones schema from columns: {col_summary}\n"
        f"Use --ip-field and --name-field to specify column ids explicitly.\n"
        f"  --ip-field:   column id that holds the IP/subnet value\n"
        f"  --name-field: column id that holds the zone name"
    )


def _classify_zone(key: str) -> tuple[str, int | None, int | None]:
    """Return (risk, prefix_len, cardinality) for a zone key string.

    Parses key as a CIDR network. Returns UNKNOWN for non-CIDR strings.
    """
    try:
        net = ipaddress.ip_network(key, strict=False)
        prefix_len = net.prefixlen
        cardinality = net.num_addresses
        if prefix_len <= _COARSE_PREFIX_MAX:
            return "COARSE", prefix_len, cardinality
        elif prefix_len <= _MEDIUM_PREFIX_MAX:
            return "MEDIUM", prefix_len, cardinality
        else:
            return "FINE", prefix_len, cardinality
    except ValueError:
        return "UNKNOWN", None, None

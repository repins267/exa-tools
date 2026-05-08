"""Network Zones hot key expansion — coarse zones to /24 granularity.

OOTB table constraint (EXA-COLLECTOR-API-9):
  The Network Zones table is Exabeam-managed ("source": "Exabeam"), so
  deleteRecords returns HTTP 404. The only write path is addRecords with
  operation="replace", which replaces the entire table in one call.

  Strategy:
  1. Snapshot all current records.
  2. Remove coarse entries for target zone(s) from the snapshot.
  3. Append /24 replacement entries.
  4. Call add_records(operation="replace") with the merged set.

  Rollback restores the snapshot via the same add_records(operation="replace").
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

from exa.context.tables import add_records, get_all_records
from exa.hotkey.analyze import ZoneRisk
from exa.hotkey.rollback import write_manifest
from exa.hotkey.scan import _ip_in_zone

_BATCH_WRITE_SLEEP = 1.0  # mirrors exa.client._BATCH_WRITE_SLEEP


def expand_zones(
    client: ExaClient,
    zones: list[ZoneRisk],
    *,
    zone_name: str | None = None,
    observed_ips: list[str] | None = None,
    enumerate_all: bool = False,
    dry_run: bool = False,
    tenant: str = "default",
) -> list[dict[str, Any]]:
    """Expand coarse zone(s) to /24 granularity via full-table replace.

    For OOTB tables (source=Exabeam), deleteRecords is blocked — the only
    write path is addRecords with operation="replace". This function:
    1. Snapshots all current records.
    2. Removes coarse entries for the target zone(s) from the snapshot.
    3. Appends /24 replacement entries for each coarse subnet.
    4. Writes a rollback manifest (stores the full original snapshot).
    5. Calls add_records(operation="replace") with the merged set.

    dry_run=True: prints the plan, makes no API writes, no manifest.
    Returns list of {zone_name, old_key, new_key_count, status} per target.
    """
    targets = [z for z in zones if z.risk == "COARSE"]
    if zone_name:
        targets = [z for z in targets if z.entry.zone_name == zone_name]

    if not targets:
        return []

    table_id = targets[0].entry.table_id
    table_display_name = targets[0].entry.table_display_name
    ip_field = targets[0].entry.ip_field

    # Generate /24 records and summary for each target
    new_slash24: list[dict[str, Any]] = []
    summary: list[dict[str, Any]] = []
    for zone in targets:
        new_records = _gen_slash24_records(zone, observed_ips, enumerate_all)
        new_slash24.extend(new_records)
        summary.append({
            "zone_name": zone.entry.zone_name,
            "old_key": zone.entry.key,
            "new_key_count": len(new_records),
            "status": "dry-run" if dry_run else "expanded",
        })

    if dry_run:
        return summary

    # Snapshot all records before any modification
    all_records = get_all_records(client, table_id)

    # Remove coarse entries targeted for expansion, keep everything else
    coarse_keys = {z.entry.key for z in targets}
    kept = [r for r in all_records if r.get(ip_field) not in coarse_keys]

    merged = kept + new_slash24

    # Write rollback manifest before any write (stores full original snapshot)
    write_manifest(
        tenant=tenant,
        table_id=table_id,
        table_display_name=table_display_name,
        zone_name=zone_name or "(all COARSE)",
        original_records=all_records,
        added_keys=[],  # not used for replace-based rollback; snapshot is sufficient
    )

    add_records(client, table_id, merged, operation="replace")

    return summary


def _gen_slash24_records(
    zone: ZoneRisk,
    observed_ips: list[str] | None,
    enumerate_all: bool,
) -> list[dict[str, Any]]:
    """Generate /24-granularity table records for a zone.

    If observed_ips and not enumerate_all: only /24s containing an observed IP.
    Otherwise: all /24 subnets within the zone's CIDR range mathematically.
    """
    nets: set[ipaddress.IPv4Network] = set()

    if observed_ips and not enumerate_all:
        for ip in observed_ips:
            if _ip_in_zone(ip, zone):
                try:
                    nets.add(_to_slash24(ip))
                except ValueError:
                    pass

    # Fall back to full enumeration if no observed IPs matched or --enumerate
    if not nets or enumerate_all:
        try:
            parent = ipaddress.ip_network(zone.entry.key, strict=False)
            nets = set(parent.subnets(new_prefix=24))
        except ValueError:
            return []

    return [
        {
            zone.entry.ip_field: str(net),
            zone.entry.name_field: _zone_name_from_network(net),
        }
        for net in sorted(nets)
    ]


def _to_slash24(ip: str) -> ipaddress.IPv4Network:
    """Map an IP string to its /24 network. Raises ValueError for invalid input."""
    return ipaddress.ip_network(f"{ip}/24", strict=False)


def _zone_name_from_network(net: ipaddress.IPv4Network) -> str:
    """Format /24 network as zone name: Net_{a}_{b}_{c}_0"""
    a, b, c, _ = str(net.network_address).split(".")
    return f"Net_{a}_{b}_{c}_0"

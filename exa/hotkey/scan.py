"""Network Zones hot key risk scan — active IP discovery.

Verified 2026-05-08 against sademodev22:
  POST /search/v2/events with groupBy=["src_ip"] returns rows as
  {"src_ip": "x.x.x.x"} with NO count field. The API de-duplicates
  by the grouped field but does not aggregate event counts per group.
  event_count is therefore always 0 in ZoneScan — ip_count is the
  sole hot key signal.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

from exa.hotkey.analyze import ZoneRisk
from exa.search.events import search_events

_DEFAULT_THRESHOLD = 500  # distinct IPs per zone above which zone is HOT_KEY_RISK


@dataclass
class ZoneScan:
    zone_name: str
    ip_count: int    # distinct source IPs observed in this zone
    event_count: int # always 0 — API returns no per-IP count for group_by queries
    risk: str        # "HOT_KEY_RISK" | "OK"


def scan_zones(
    client: ExaClient,
    zones: list[ZoneRisk],
    *,
    lookback_days: int = 7,
    threshold: int = _DEFAULT_THRESHOLD,
    limit: int = 50_000,
) -> list[ZoneScan]:
    """Query recent events for distinct src_ips, map to zones, aggregate.

    Returns list sorted by ip_count descending.
    """
    rows = search_events(
        client,
        "src_ip:*",
        fields=["src_ip"],
        group_by=["src_ip"],
        lookback_days=lookback_days,
        limit=limit,
    )
    ip_list = _parse_grouped_rows(rows)
    return _group_by_zone(ip_list, zones, threshold)


def _parse_grouped_rows(rows: list[dict[str, Any]]) -> list[str]:
    """Extract distinct IP strings from group_by response rows.

    Verified 2026-05-08: rows are {"src_ip": "x.x.x.x"} with no count field.
    Skips rows with missing or blank src_ip.
    """
    return [row["src_ip"] for row in rows if row.get("src_ip")]


def _ip_in_zone(ip: str, zone: ZoneRisk) -> bool:
    """Return True if ip falls within zone's CIDR key.

    Returns False (does not raise) if either value fails to parse.
    """
    try:
        addr = ipaddress.ip_address(ip)
        net = ipaddress.ip_network(zone.entry.key, strict=False)
        return addr in net
    except ValueError:
        return False


def _group_by_zone(
    ip_list: list[str],
    zones: list[ZoneRisk],
    threshold: int,
) -> list[ZoneScan]:
    """Map each IP to the first matching zone, aggregate ip_count per unique zone_name.

    Multiple zone entries with the same zone_name (e.g. six /16 subnets all named
    "Atlanta Office") are merged into one ZoneScan row — the ip_count is the total
    across all matching subnets for that name, which is what Dataflow sees as one key.
    """
    counts: dict[str, int] = {}
    for ip in ip_list:
        for zone in zones:
            if _ip_in_zone(ip, zone):
                counts[zone.entry.zone_name] = counts.get(zone.entry.zone_name, 0) + 1
                break

    seen: set[str] = set()
    result: list[ZoneScan] = []
    for zone in zones:
        name = zone.entry.zone_name
        if name in seen:
            continue
        seen.add(name)
        ip_count = counts.get(name, 0)
        result.append(ZoneScan(
            zone_name=name,
            ip_count=ip_count,
            event_count=0,
            risk="HOT_KEY_RISK" if ip_count >= threshold else "OK",
        ))
    return sorted(result, key=lambda z: z.ip_count, reverse=True)

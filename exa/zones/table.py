"""Network Zones table snapshot — shared state for zones CLI commands."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient


@dataclass
class ZonesSnapshot:
    table_id: str
    table_display_name: str
    ip_field: str    # column id for CIDR/IP key
    name_field: str  # column id for zone label
    records: list[dict[str, Any]]


def get_zones_snapshot(client: ExaClient) -> ZonesSnapshot:
    """Find Network Zones table, detect schema, and read all records.

    Raises ValueError if the table is not found or schema cannot be detected.
    """
    from exa.context.tables import get_all_records, get_table
    from exa.hotkey.analyze import _detect_schema, _find_network_zones_table

    table_meta = _find_network_zones_table(client)
    table_id = table_meta["id"]
    table_display_name = (
        table_meta.get("displayName") or table_meta.get("name", "Network Zones")
    )
    table_detail = get_table(client, table_id)
    ip_field, name_field = _detect_schema(table_detail)
    records = get_all_records(client, table_id)
    return ZonesSnapshot(
        table_id=table_id,
        table_display_name=table_display_name,
        ip_field=ip_field,
        name_field=name_field,
        records=records,
    )

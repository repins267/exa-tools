"""Read live record counts for the 6 AI/LLM context tables.

Uses GET /context-management/v1/tables and matches on displayName.
Record count is read from totalItems (NOT numRecords — per CLAUDE.md).
lastUpdated is a Unix timestamp (milliseconds).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from exa.aillm.sync import TABLE_MAP
from exa.context.tables import get_tables

if TYPE_CHECKING:
    from exa.client import ExaClient


@dataclass
class TableStatus:
    """Live status for a single AI/LLM context table."""

    table_name: str
    table_id: str | None
    record_count: int
    last_updated: str  # Human-readable string or "Never" / "Unknown"
    found: bool


def get_aillm_table_status(client: ExaClient) -> list[TableStatus]:
    """Query live record counts for all 6 AI/LLM context tables.

    Matches tables by displayName (canonical per CLAUDE.md).
    Uses totalItems for record count.
    Returns results in TABLE_MAP order.

    Args:
        client: Authenticated ExaClient.

    Returns:
        List of TableStatus, one per AI/LLM table.
    """
    all_tables = get_tables(client)

    # Build lookup by displayName — CLAUDE.md: "Match on displayName (NOT name)"
    by_display: dict[str, dict] = {}
    for t in all_tables:
        display = t.get("displayName") or t.get("name", "")
        if display:
            by_display[display] = t

    results: list[TableStatus] = []
    for _bucket, exa_name in TABLE_MAP.items():
        t = by_display.get(exa_name)

        if t is None:
            results.append(TableStatus(
                table_name=exa_name,
                table_id=None,
                record_count=0,
                last_updated="Never",
                found=False,
            ))
            continue

        # CLAUDE.md: "totalItems is the ONLY correct record count field"
        record_count = int(t.get("totalItems") or 0)

        # lastUpdated is a Unix timestamp — handle both ms and seconds
        last_updated_raw = t.get("lastUpdated")
        last_updated: str
        if last_updated_raw:
            try:
                ts = int(last_updated_raw)
                if ts > 1_000_000_000_000:  # milliseconds
                    ts = ts // 1000
                dt = datetime.fromtimestamp(ts, tz=UTC)
                last_updated = dt.strftime("%Y-%m-%d %H:%M UTC")
            except (ValueError, OSError):
                last_updated = "Unknown"
        else:
            last_updated = "Never" if record_count == 0 else "Unknown"

        results.append(TableStatus(
            table_name=exa_name,
            table_id=t.get("id"),
            record_count=record_count,
            last_updated=last_updated,
            found=True,
        ))

    return results

"""Sync OOTB compliance control tables to Exabeam context tables.

Creates or updates a context table containing the framework's controls
as records, enabling correlation rules to reference compliance metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from exa.compliance.frameworks import load_framework
from exa.context.tables import (
    add_records,
    create_table,
    get_tables,
)

if TYPE_CHECKING:
    from exa.client import ExaClient


@dataclass
class OOTBSyncResult:
    """Result of syncing a framework's controls to a context table."""

    table_name: str
    framework: str
    records_written: int = 0
    records_skipped: int = 0
    created: bool = False
    errors: list[str] = field(default_factory=list)


# EXA-CONTEXT-SCHEMA-35 workaround: "Framework" as a column name
# causes 409 conflicts because the displayName is globally scoped.
# Use "Compliance Framework" instead.

_ATTRIBUTES: list[dict[str, Any]] = [
    {"displayName": "key", "isKey": True},
    {"displayName": "Title", "isKey": False},
    {"displayName": "Family", "isKey": False},
    {"displayName": "Description", "isKey": False},
    {"displayName": "MITRE", "isKey": False},
    {"displayName": "Testable", "isKey": False},
    {"displayName": "Compliance Framework", "isKey": False},
]


def _build_records(
    fw_name: str,
    controls: list[Any],
) -> list[dict[str, str]]:
    """Build context table records from framework controls."""
    records: list[dict[str, str]] = []
    for c in controls:
        desc = c.description[:500] if len(c.description) > 500 else c.description
        records.append({
            "key": c.control_id,
            "Title": c.description.split(".")[0] if "." in c.description else c.description[:80],
            "Family": c.family,
            "Description": desc,
            "MITRE": "",
            "Testable": "Yes" if c.siem_validatable else "No",
            "Compliance Framework": fw_name,
        })
    return records


def sync_ootb_tables(
    client: ExaClient,
    framework: str = "NIST_CSF",
    *,
    dry_run: bool = False,
) -> OOTBSyncResult:
    """Sync a framework's controls to a compliance context table.

    Creates the table if it doesn't exist. Uses operation="replace"
    for idempotency — safe to run multiple times.

    Args:
        client: Authenticated ExaClient.
        framework: Framework ID (e.g. "NIST_CSF").
        dry_run: If True, report what would be written without API calls.
    """
    fw = load_framework(framework)
    table_name = f"Compliance - {fw.name} Controls"

    result = OOTBSyncResult(
        table_name=table_name,
        framework=fw.name,
    )

    # Build records from leaf controls
    leaf = fw.leaf_controls
    records = _build_records(fw.name, leaf)

    if dry_run:
        result.records_written = len(records)
        return result

    # Find or create the table
    existing = get_tables(client, name=table_name, exact=True)

    if existing:
        table_id = existing[0]["id"]
    else:
        try:
            resp = create_table(
                client, table_name, attributes=_ATTRIBUTES,
            )
            table_id = resp.get("id") or resp.get("table", {}).get("id", "")
            if not table_id:
                result.errors.append(
                    f"Table creation returned no ID: {resp}"
                )
                return result
            result.created = True
            client.batch_write_sleep()
        except Exception as e:
            result.errors.append(f"Failed to create table: {e}")
            return result

    # Write records (replace for idempotency)
    try:
        add_records(client, table_id, records, operation="replace")
        result.records_written = len(records)
    except Exception as e:
        result.errors.append(f"Failed to write records: {e}")

    return result

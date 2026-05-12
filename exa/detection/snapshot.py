"""Snapshot analytics rules into a Context Management table.

Writes all current detection rules as a point-in-time snapshot so the table
can be used as a dashboard source and diffed month-over-month.

Column contract
---------------
The target table must have these display-name columns (created via
create_snapshot_table or via the UI). The API assigns opaque IDs to custom
columns at creation time; snapshot_rules_to_table resolves them at runtime
via the table schema so record field keys are always correct.

  Detection Rule Name
  Detection Rule Enabled
  Detection Rule Severity
  Detection Rule Type
  Detection Rule Families
  Detection Snapshot Date
  Detection Rule Author
"""

from __future__ import annotations

from datetime import date
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

from exa.context.tables import add_records, create_table, get_table

# Display names used when creating the snapshot table schema.
# Keys here must stay in sync with _rule_to_record().
_COL_RULE_NAME = "Detection Rule Name"
_COL_ENABLED = "Detection Rule Enabled"
_COL_SEVERITY = "Detection Rule Severity"
_COL_TYPE = "Detection Rule Type"
_COL_FAMILIES = "Detection Rule Families"
_COL_SNAPSHOT_DATE = "Detection Snapshot Date"
_COL_AUTHOR = "Detection Rule Author"

SNAPSHOT_COLUMNS: list[str] = [
    _COL_RULE_NAME,
    _COL_ENABLED,
    _COL_SEVERITY,
    _COL_TYPE,
    _COL_FAMILIES,
    _COL_SNAPSHOT_DATE,
    _COL_AUTHOR,
]


def create_snapshot_table(client: ExaClient, table_name: str) -> str:
    """Create a context table with the detection snapshot schema. Returns table_id."""
    attrs: list[dict[str, Any]] = [{"id": "key", "isKey": True}]
    for col in SNAPSHOT_COLUMNS:
        attrs.append({"displayName": col, "isKey": False})
    resp = create_table(client, table_name, attributes=attrs)
    table_id: str = resp.get("id") or resp.get("table", {}).get("id", "")
    if not table_id:
        raise RuntimeError(f"create_table did not return an ID: {resp}")
    return table_id


def snapshot_rules_to_table(
    client: ExaClient,
    table_id: str,
) -> dict[str, Any]:
    """Fetch all analytics rules and write them to a context table as a snapshot.

    Resolves the table's attribute IDs from its schema so records use the
    correct opaque field keys. Performs a full-table replace — stale rules
    (deleted upstream) are removed automatically.

    Returns {"written": N, "table_id": table_id, "snapshotDate": "YYYY-MM-DD"}.
    """
    from exa.detection.rules import get_detection_rules

    attr_map = _resolve_attr_ids(client, table_id)
    rules = get_detection_rules(client)
    snapshot_date = date.today().isoformat()

    records = [_rule_to_record(rule, attr_map, snapshot_date) for rule in rules]
    add_records(client, table_id, records, operation="replace")

    return {
        "written": len(records),
        "table_id": table_id,
        "snapshotDate": snapshot_date,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_attr_ids(client: ExaClient, table_id: str) -> dict[str, str]:
    """Return {displayName: attribute_id} map from a table's schema."""
    detail = get_table(client, table_id)
    inner = detail.get("table", detail) if isinstance(detail, dict) else {}
    attrs: list[dict[str, Any]] = inner.get("attributes", [])
    return {
        a["displayName"]: a["id"]
        for a in attrs
        if a.get("displayName") and a.get("id")
    }


def _rule_to_record(
    rule: dict[str, Any],
    attr_map: dict[str, str],
    snapshot_date: str,
) -> dict[str, Any]:
    """Map a detection rule dict to a context table record using resolved IDs."""
    families = rule.get("families") or []
    families_str = (
        "; ".join(str(f) for f in families) if isinstance(families, list) else str(families)
    )

    record: dict[str, Any] = {"key": rule.get("id", "")}

    def _set(col: str, value: Any) -> None:
        field_id = attr_map.get(col)
        if field_id:
            record[field_id] = value

    _set(_COL_RULE_NAME, rule.get("name", ""))
    _set(_COL_ENABLED, str(rule.get("isEnabled", "")).lower())
    _set(_COL_SEVERITY, rule.get("severity", ""))
    _set(_COL_TYPE, rule.get("type", ""))
    _set(_COL_FAMILIES, families_str)
    _set(_COL_SNAPSHOT_DATE, snapshot_date)
    _set(_COL_AUTHOR, rule.get("author", ""))

    return record

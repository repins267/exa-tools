"""Push context tables from exa splunk convert output to Exabeam.

Reads the .tables.json file produced by convert and creates each context table
on the tenant, uploading all values as records.  Tables use a single key column
so the EQL  field IN "TableName"  syntax resolves against the key column by
default (Exabeam Search Guide § "Query by Context Table").

Idempotent: tables that already exist (matched by display name) are updated
with a replace operation rather than duplicated.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from exa.client import ExaClient
from exa.context.tables import add_records, create_table, get_tables


_KEY_COL = "value"          # attribute id for the key column in all splunk tables
_SLEEP_BETWEEN = 1.0        # seconds between table writes (rate-limit headroom)

# CIM2 field → context_type mapping for sensible table categorisation
_FIELD_CONTEXT_TYPE: dict[str, str] = {
    "src_ip": "TI_ips",
    "dest_ip": "TI_ips",
    "src_host": "Device",
    "dest_host": "Device",
    "user": "User",
    "src_user": "User",
    "dest_user": "User",
}


def _context_type_for_field(field_eql: str) -> str:
    return _FIELD_CONTEXT_TYPE.get(field_eql, "Other")


def _find_existing_table(client: ExaClient, display_name: str) -> str | None:
    """Return the table ID if a table with this display name already exists."""
    tables = get_tables(client)
    needle = display_name.lower()
    for t in tables:
        dn = (t.get("displayName") or "").lower()
        nm = (t.get("name") or "").lower()
        if needle in (dn, nm):
            return t.get("id")
    return None


def _ensure_table(client: ExaClient, table_entry: dict[str, Any]) -> tuple[str, bool]:
    """Create or locate the context table. Returns (table_id, created: bool)."""
    table_name: str = table_entry["table_name"]
    field_eql: str = table_entry.get("field_eql", table_entry["field"])
    ctx_type = _context_type_for_field(field_eql)

    existing = _find_existing_table(client, table_name)
    if existing:
        return existing, False

    attrs = [{"id": _KEY_COL, "isKey": True}]
    resp = create_table(client, table_name, context_type=ctx_type, attributes=attrs)
    table_obj = resp.get("table", resp) if isinstance(resp, dict) else resp
    table_id: str = table_obj.get("id", "")
    if not table_id:
        raise RuntimeError(f"create_table did not return an id: {resp}")
    return table_id, True


def _upload_values(
    client: ExaClient,
    table_id: str,
    values: list[str],
    *,
    operation: str = "replace",
) -> int:
    """Upload values as records to a context table. Returns record count."""
    records = [{_KEY_COL: v} for v in values]
    add_records(client, table_id, records, operation=operation)
    return len(records)


def push_splunk_tables(
    client: ExaClient,
    tables_json_path: str | Path,
    *,
    operation: str = "replace",
) -> list[dict[str, Any]]:
    """Create context tables from a .tables.json file and upload all values.

    Args:
        client: Authenticated ExaClient.
        tables_json_path: Path to the .tables.json produced by exa splunk convert.
        operation: "replace" (default) or "append" for add_records.

    Returns:
        List of result dicts per table:
            rule, table_name, table_id, records, created (bool), error (str|None)
    """
    path = Path(tables_json_path)
    bundles: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))

    results: list[dict[str, Any]] = []

    for bundle in bundles:
        rule_name: str = bundle.get("rule", "unknown")
        for tbl in bundle.get("tables", []):
            table_name = tbl["table_name"]
            values: list[str] = tbl.get("values", [])
            result: dict[str, Any] = {
                "rule": rule_name,
                "table_name": table_name,
                "table_id": None,
                "records": 0,
                "created": False,
                "error": None,
            }
            try:
                table_id, created = _ensure_table(client, tbl)
                result["table_id"] = table_id
                result["created"] = created
                result["records"] = _upload_values(
                    client, table_id, values, operation=operation
                )
            except Exception as exc:
                result["error"] = str(exc)
            results.append(result)
            time.sleep(_SLEEP_BETWEEN)

    return results

"""Context table CRUD operations for Exabeam New-Scale.

All functions take an ExaClient as their first argument.

API base path: /context-management/v1/
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

_BATCH_SIZE = 20_000


# -- Tables -------------------------------------------------------------------


def get_tables(
    client: ExaClient,
    *,
    name: str | None = None,
    exact: bool = False,
) -> list[dict[str, Any]]:
    """List all context tables, optionally filtered by name."""
    tables: list[dict[str, Any]] = client.get("/context-management/v1/tables")
    if name is not None:
        if exact:
            tables = [t for t in tables if t.get("name") == name]
        else:
            name_lower = name.lower()
            tables = [t for t in tables if name_lower in t.get("name", "").lower()]
    return tables


def get_table(client: ExaClient, table_id: str) -> dict[str, Any]:
    """Get a single context table by ID."""
    return client.get(f"/context-management/v1/tables/{table_id}")


def create_table(
    client: ExaClient,
    name: str,
    *,
    context_type: str = "Other",
    source: str = "Custom",
    attributes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Create a new context table.

    Args:
        name: Table display name.
        context_type: One of Other, User, TI_ips, TI_domains, Device, Domain, IP.
        source: "Custom" for user-created, "Exabeam" for managed.
        attributes: Column definitions, e.g. [{"id": "key", "isKey": True}].
    """
    body: dict[str, Any] = {
        "name": name,
        "contextType": context_type,
        "source": source,
    }
    if attributes:
        body["attributes"] = attributes
    return client.post("/context-management/v1/tables", json=body)


def delete_table(
    client: ExaClient,
    table_id: str,
    *,
    delete_unused_attributes: bool = False,
) -> None:
    """Delete a context table."""
    flag = "true" if delete_unused_attributes else "false"
    client.delete(
        f"/context-management/v1/tables/{table_id}?deleteUnusedCustomAttributes={flag}"
    )


# -- Attributes ---------------------------------------------------------------


def get_attributes(client: ExaClient, context_type: str) -> list[dict[str, Any]]:
    """Get available attributes for a context type (Other, User, TI_ips, TI_domains)."""
    resp = client.get(f"/context-management/v1/attributes/{context_type}")
    return resp.get("attributes", resp) if isinstance(resp, dict) else resp


def get_table_attributes(client: ExaClient, table_id: str) -> dict[str, Any]:
    """Get attribute schema for a specific table."""
    return client.get(f"/context-management/v1/tables/{table_id}")


# -- Records ------------------------------------------------------------------


def get_records(
    client: ExaClient,
    table_id: str,
    *,
    limit: int = 1000,
    offset: int = 0,
) -> Any:
    """Read records from a context table with pagination."""
    return client.get(
        f"/context-management/v1/tables/{table_id}/records",
        params={"limit": limit, "offset": offset},
    )


def get_all_records(
    client: ExaClient,
    table_id: str,
    *,
    page_size: int = 100_000,
) -> list[dict[str, Any]]:
    """Read all records from a context table, auto-paginating."""
    all_records: list[dict[str, Any]] = []
    offset = 0
    while True:
        resp = get_records(client, table_id, limit=page_size, offset=offset)
        records = resp.get("records", resp) if isinstance(resp, dict) else resp
        if not records:
            break
        all_records.extend(records)
        if len(records) < page_size:
            break
        offset += len(records)
    return all_records


def resolve_table_schema(
    client: ExaClient,
    table: str | dict[str, Any],
) -> tuple[str, dict[str, str]]:
    """Resolve a table's real key attribute and its other attribute IDs.

    NEVER assume the key attribute is named "key" (EXA-TABLE-KEY-ATTR). Each
    table defines its own. Reading records with r.get("key") against a table
    that uses a different attribute returns an EMPTY list while totalItems
    reports a healthy count — it looks like an empty table but is fully
    populated. Confirmed on "Public AI Domains and Risk", which uses
    `aillm_domain` + `risk_level`.

    Args:
        client: Authenticated ExaClient.
        table: Table ID, or a table object from get_tables() (which already
            includes `attributes` — pass it to avoid a second round trip).

    Returns:
        (key_attr_id, {display_name_lower: attr_id}) for non-key attributes.
        Falls back to ("key", {}) if the schema cannot be read.
    """
    if isinstance(table, dict):
        attributes = table.get("attributes") or []
        if not attributes and table.get("id"):
            attributes = (get_table_attributes(client, table["id"]) or {}).get(
                "attributes", []
            )
    else:
        attributes = (get_table_attributes(client, table) or {}).get("attributes", [])

    key_attr = "key"
    others: dict[str, str] = {}
    for attr in attributes:
        attr_id = attr.get("id", "")
        if not attr_id:
            continue
        if attr.get("isKey"):
            key_attr = attr_id
        else:
            display = (attr.get("displayName") or attr_id).lower()
            others[display] = attr_id
    return key_attr, others


def get_all_records_keyed(
    client: ExaClient,
    table: str | dict[str, Any],
) -> tuple[str, list[dict[str, Any]], set[str]]:
    """Read every record from a table using its real key attribute.

    Prefer this over get_all_records() whenever you intend to read key values —
    it removes the "key" assumption that silently yields an empty result set.

    Returns:
        (key_attr_id, records, lowercased set of key values)
    """
    table_id = table["id"] if isinstance(table, dict) else table
    key_attr, _ = resolve_table_schema(client, table)
    records = get_all_records(client, table_id)
    keys = {
        str(r[key_attr]).strip().lower()
        for r in records
        if r.get(key_attr) not in (None, "")
    }
    return key_attr, records, keys


def add_records(
    client: ExaClient,
    table_id: str,
    data: list[dict[str, Any]],
    *,
    operation: str = "append",
) -> Any:
    """Add records to a context table with automatic batching (20k per request).

    Note: addRecords is additive — re-runs create duplicates. Use operation="replace"
    or check existing records first for idempotency.
    """
    total_batches = math.ceil(len(data) / _BATCH_SIZE)
    response = None
    for i in range(total_batches):
        start = i * _BATCH_SIZE
        batch = data[start : start + _BATCH_SIZE]
        response = client.post(
            f"/context-management/v1/tables/{table_id}/addRecords",
            json={"operation": operation, "data": batch},
        )
    return response


def delete_records(
    client: ExaClient,
    table_id: str,
    record_ids: list[str],
) -> Any:
    """Delete records from a context table by key values."""
    return client.request(
        "DELETE",
        f"/context-management/v1/tables/{table_id}/deleteRecords",
        json={"ids": record_ids},
    ).json()

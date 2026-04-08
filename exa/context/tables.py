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

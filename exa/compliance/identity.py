"""Sync compliance identity context tables to Exabeam.

Populates 6 pre-built compliance context tables that feed Exabeam's
compliance analyst dashboards (CMMC, HIPAA, ISO 27001, NIST 800-171,
NIST 800-53, NIST CSF, PCI DSS).

Supports DirectMap mode (map named source tables) and FilterMode
(classify from a single AD/Entra table).

Note: "hippa" is Exabeam's typo in their OOTB schema — not "hipaa".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from rich.console import Console

from exa.compliance.mapping import (
    ClassificationResult,
    classify_records,
    extract_keys,
)
from exa.context.tables import (
    add_records,
    create_table,
    get_all_records,
    get_attributes,
    get_tables,
)

if TYPE_CHECKING:
    from exa.client import ExaClient

console = Console()

# Target table names in Exabeam
TARGET_TABLE_MAP: dict[str, str] = {
    "privileged_users": "Compliance - Privileged Users",
    "shared_accounts": "Compliance - Shared Accounts",
    "third_party_users": "Compliance - Third-Party Users",
    "service_accounts": "Compliance - System & Service Accounts",
    "in_scope_systems": "Compliance - In-Scope Data Systems",
    "network_systems": "Compliance - Network Security Systems",
}

# Framework columns — "hippa" is Exabeam's OOTB typo
FRAMEWORK_COLUMNS = ["nist_800_53", "nist_800_171", "nist_csf", "iso_27001", "pci_dss", "hippa"]


@dataclass
class IdentitySyncResult:
    table_name: str
    records_found: int = 0
    records_upserted: int = 0
    errors: int = 0
    error_detail: str = ""


def _build_compliance_records(keys: list[str]) -> list[dict[str, str]]:
    """Build records with key + all framework columns set to 'Yes'."""
    return [
        {"key": k, **{col: "Yes" for col in FRAMEWORK_COLUMNS}}
        for k in keys
    ]


def sync_compliance_identity_tables(
    client: ExaClient,
    *,
    # DirectMap sources
    privileged_users_source: str | None = None,
    service_accounts_source: str | None = None,
    shared_accounts_source: str | None = None,
    third_party_users_source: str | None = None,
    in_scope_systems_source: str | None = None,
    network_systems_source: str | None = None,
    # Manual lists
    in_scope_system_list: list[str] | None = None,
    network_system_list: list[str] | None = None,
    # FilterMode
    filter_mode: bool = False,
    source_context_table: str | None = None,
    privileged_patterns: list[str] | None = None,
    service_patterns: list[str] | None = None,
    internal_domains: list[str] | None = None,
    # Options
    force: bool = False,
) -> list[IdentitySyncResult]:
    """Sync compliance identity tables.

    Args:
        client: Authenticated ExaClient.
        *_source: Source context table names for DirectMap mode.
        *_list: Manual lists of system names.
        filter_mode: Classify from a single source table.
        source_context_table: Source table name for FilterMode.
        force: Replace instead of append.
    """
    operation = "replace" if force else "append"
    results: list[IdentitySyncResult] = []

    console.rule("Compliance Identity Table Sync")

    # Get all tables
    console.print("\n[1/3] Retrieving context tables...", style="yellow")
    all_tables = get_tables(client)
    existing = {t["name"]: t for t in all_tables}
    console.print(f"  Found {len(all_tables)} context tables in tenant")

    # Resolve source data
    console.print("\n[2/3] Resolving source data...", style="yellow")
    source_data: dict[str, list[str]] = {}

    if filter_mode:
        if not source_context_table:
            raise ValueError("FilterMode requires source_context_table")
        console.print(f"  Reading source table: {source_context_table}")
        table = next((t for t in all_tables if t["name"] == source_context_table), None)
        if not table:
            raise ValueError(f"Source table not found: {source_context_table}")
        records = get_all_records(client, table["id"])
        classified = classify_records(
            records,
            privileged_patterns=privileged_patterns,
            service_patterns=service_patterns,
            internal_domains=internal_domains,
        )
        source_data["privileged_users"] = classified.privileged_users
        source_data["service_accounts"] = classified.service_accounts
        source_data["shared_accounts"] = classified.shared_accounts
        source_data["third_party_users"] = classified.third_party_users
        console.print(
            f"  Classified: Privileged={len(classified.privileged_users)}, "
            f"Service={len(classified.service_accounts)}, "
            f"Shared={len(classified.shared_accounts)}, "
            f"ThirdParty={len(classified.third_party_users)}, "
            f"Unclassified={classified.unclassified}"
        )
    else:
        # DirectMap
        direct_map = {
            "privileged_users": privileged_users_source,
            "service_accounts": service_accounts_source,
            "shared_accounts": shared_accounts_source,
            "third_party_users": third_party_users_source,
            "in_scope_systems": in_scope_systems_source,
            "network_systems": network_systems_source,
        }
        for target_key, src_name in direct_map.items():
            if not src_name:
                continue
            console.print(f"  {target_key} <- '{src_name}'...", end="")
            table = next((t for t in all_tables if t["name"] == src_name), None)
            if not table:
                console.print(" NOT FOUND", style="red")
                continue
            records = get_all_records(client, table["id"])
            keys = extract_keys(records)
            source_data[target_key] = keys
            console.print(f" {len(keys)} records", style="green")

    # Manual system lists
    if in_scope_system_list and "in_scope_systems" not in source_data:
        source_data["in_scope_systems"] = in_scope_system_list
    if network_system_list and "network_systems" not in source_data:
        source_data["network_systems"] = network_system_list

    if not any(source_data.values()):
        console.print("\n  No source data resolved.", style="yellow")
        return results

    # Sync each target table
    console.print("\n[3/3] Syncing compliance tables...", style="yellow")

    # Resolve attribute IDs
    known_attr_ids: dict[str, str] = {}
    try:
        tenant_attrs = get_attributes(client, "Other")
        for a in tenant_attrs:
            if a.get("displayName"):
                known_attr_ids[a["displayName"]] = a["id"]
    except Exception:
        pass

    for target_key, target_name in TARGET_TABLE_MAP.items():
        items = source_data.get(target_key, [])
        console.print(f"\n  {target_name}", style="cyan")

        if not items:
            console.print("    SKIP: No source data", style="dim")
            results.append(IdentitySyncResult(table_name=target_name))
            continue

        console.print(f"    Source records: {len(items)}")

        # Resolve or create target table
        if target_name in existing:
            table_id = existing[target_name]["id"]
        else:
            console.print(f"    Creating table: {target_name}...", end="")
            attrs: list[dict[str, Any]] = [{"id": "key", "isKey": True}]
            for col in FRAMEWORK_COLUMNS:
                if col in known_attr_ids:
                    attrs.append({"id": known_attr_ids[col], "isKey": False})
                else:
                    attrs.append({"displayName": col, "isKey": False})
            result = create_table(client, target_name, attributes=attrs)
            if result and "table" in result:
                table_id = result["table"]["id"]
                console.print(f" Created ({table_id})", style="green")
            else:
                console.print(" FAILED", style="red")
                results.append(IdentitySyncResult(
                    table_name=target_name, records_found=len(items), errors=1
                ))
                continue
            client.batch_write_sleep()

        # Build and upload records
        records = _build_compliance_records(items)
        console.print(f"    Uploading {len(records)} records ({operation})...", end="")
        try:
            add_records(client, table_id, records, operation=operation)
            console.print(" OK", style="green")
            results.append(IdentitySyncResult(
                table_name=target_name,
                records_found=len(items),
                records_upserted=len(items),
            ))
        except Exception as e:
            console.print(f" FAILED: {e}", style="red")
            results.append(IdentitySyncResult(
                table_name=target_name,
                records_found=len(items),
                errors=1,
                error_detail=str(e),
            ))
        client.batch_write_sleep()

    # Summary
    console.rule("Sync Complete", style="green")
    total_upserted = sum(r.records_upserted for r in results)
    total_errors = sum(r.errors for r in results)
    console.print(f"  Total upserted: {total_upserted} | Errors: {total_errors}")

    return results


# -- Status -------------------------------------------------------------------


@dataclass
class TableStatus:
    """Status of a single compliance context table."""

    name: str
    record_count: int = 0
    table_id: str = ""
    note: str = ""


def _find_table_by_name(
    tables: list[dict[str, Any]],
    target_name: str,
) -> dict[str, Any] | None:
    """Find a table by name or displayName (case-insensitive).

    OOTB Exabeam tables may use 'displayName' as the human-readable
    name while 'name' is an internal identifier.
    """
    target_lower = target_name.lower()
    for t in tables:
        if t.get("name", "").lower() == target_lower:
            return t
        if t.get("displayName", "").lower() == target_lower:
            return t
    return None


def _extract_count(table_data: dict[str, Any]) -> int:
    """Extract record count from a table API response.

    # Verified live against sademodev22 - totalItems only
    The Exabeam context API uses 'totalItems' as the record count
    field. 'numRecords' does NOT exist in this API.
    """
    val = table_data.get("totalItems")
    if val is not None:
        try:
            return int(val)
        except (ValueError, TypeError):
            pass
    return 0


def get_identity_table_status(
    client: ExaClient,
) -> list[TableStatus]:
    """Query all 6 OOTB compliance tables and return their status.

    Matches by both 'name' and 'displayName' to handle OOTB
    Exabeam tables. Uses 'totalItems' field for record counts.
    """
    all_tables = get_tables(client)

    results: list[TableStatus] = []
    for target_name in TARGET_TABLE_MAP.values():
        t = _find_table_by_name(all_tables, target_name)
        if t is not None:
            table_id = t.get("id", "")
            count = _extract_count(t)
            results.append(TableStatus(
                name=target_name,
                record_count=count,
                table_id=table_id,
            ))
        else:
            results.append(TableStatus(
                name=target_name,
                record_count=0,
                note="Not created",
            ))

    return results

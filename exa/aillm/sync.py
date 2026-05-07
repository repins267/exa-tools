"""Sync AI/LLM context tables to Exabeam New-Scale.

Manages 6 context tables with reference data, optional log discovery,
and customer risk overrides.

Tables:
  - AI/LLM DLP Rulesets          (key: alert name)
  - AI/LLM Proxy Categories      (key: category name)
  - Public AI Domains and Risk   (key: domain, risk column)
  - AI/LLM Web Domains           (key: domain)
  - AI/LLM Web Categories        (key: category name)
  - AI/LLM Applications          (key: app name)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.console import Console

from exa.aillm.merge import MergedData, merge_aillm_data
from exa.aillm.reference import load_reference_data
from exa.context.tables import (
    add_records,
    create_table,
    get_all_records,
    get_attributes,
    get_table,
    get_tables,
)

if TYPE_CHECKING:
    from exa.client import ExaClient

console = Console()

# Bucket name → Exabeam table display name
TABLE_MAP: dict[str, str] = {
    "dlp_rulesets": "AI/LLM DLP Rulesets",
    "proxy_categories": "AI/LLM Proxy Categories",
    "public_domains": "Public AI Domains and Risk",
    "web_domains": "AI/LLM Web Domains",
    "web_categories": "AI/LLM Web Categories",
    "applications": "AI/LLM Applications",
}


@dataclass
class SyncResult:
    table_name: str
    reference_entries: int = 0
    merged_total: int = 0
    upserted: int = 0
    skipped: int = 0
    errors: int = 0
    error_detail: str = ""


def _resolve_tables(
    client: ExaClient,
    buckets: list[str],
    known_attr_ids: dict[str, str],
) -> dict[str, str]:
    """Resolve or create all target tables. Returns bucket → table_id mapping."""
    existing = {t["name"]: t for t in get_tables(client)}
    table_ids: dict[str, str] = {}

    for bucket in buckets:
        exa_name = TABLE_MAP[bucket]
        if exa_name in existing:
            table_ids[bucket] = existing[exa_name]["id"]
            console.print(f"  Found: {exa_name} ({existing[exa_name]['id']})", style="green")
        else:
            console.print(f"  Creating: {exa_name}...", style="yellow", end="")
            attrs: list[dict[str, Any]] = [{"id": "key", "isKey": True}]
            # PublicDomains has a "risk" column
            if bucket == "public_domains":
                if "risk" in known_attr_ids:
                    attrs.append({"id": known_attr_ids["risk"], "isKey": False})
                else:
                    attrs.append({"displayName": "risk", "isKey": False})
            result = create_table(client, exa_name, attributes=attrs)
            if result and "table" in result:
                table_ids[bucket] = result["table"]["id"]
                console.print(f" Created ({result['table']['id']})", style="green")
            else:
                console.print(" FAILED", style="red")
            client.batch_write_sleep()

    return table_ids


def _fetch_existing_keys(client: ExaClient, table_id: str) -> set[str]:
    """Return lowercase key set of all records currently in a context table.

    Returns an empty set on any error so callers can proceed safely.
    """
    try:
        records = get_all_records(client, table_id)
        return {r.get("key", "").lower() for r in records if r.get("key")}
    except Exception:
        return set()


def _resolve_risk_attr_id(client: ExaClient, table_id: str) -> str | None:
    """Get the actual attribute ID for the 'risk' column (EXA-CONTEXT-SCHEMA-35)."""
    detail = get_table(client, table_id)
    table_meta = detail.get("table", detail)
    for attr in table_meta.get("attributes", []):
        if attr.get("displayName") == "risk" or "risk" in attr.get("id", ""):
            return attr["id"]
    return None


def sync_aillm_context_tables(
    client: ExaClient,
    *,
    buckets: list[str] | None = None,
    discovered_domains: list[str] | None = None,
    discovered_apps: list[str] | None = None,
    risk_override_path: str | Path | None = None,
    force: bool = False,
    dry_run: bool = False,
) -> list[SyncResult]:
    """Sync AI/LLM reference data to Exabeam context tables.

    Args:
        client: Authenticated ExaClient.
        buckets: Which tables to sync (keys from TABLE_MAP). None = all.
        discovered_domains: Domains from log discovery to merge.
        discovered_apps: App names from log discovery to merge.
        risk_override_path: Path to customer risk override JSON.
        force: Use 'replace' instead of 'append' operation.
        dry_run: Preview what would be synced without writing.

    Returns:
        List of SyncResult per table (empty list if dry_run=True).
    """
    all_buckets = list(TABLE_MAP.keys())
    sync_buckets = buckets or all_buckets
    results: list[SyncResult] = []
    operation = "replace" if force else "append"

    prefix = "[DRY RUN] " if dry_run else ""
    console.rule(f"{prefix}AI/LLM Context Table Sync")
    console.print(f"  Tables: {len(sync_buckets)} | Operation: {operation}")

    # Phase 1: Load reference data
    console.print("\n[1/4] Loading reference data...", style="yellow")
    ref = load_reference_data()
    console.print(
        f"  Domains: {len(ref.public_domains)} | Apps: {len(ref.applications)} | "
        f"DLP: {len(ref.dlp_rulesets)} | ProxyCat: {len(ref.proxy_categories)}"
    )
    console.print(
        f"  Excluded: {ref.excluded_domains} domains, {ref.excluded_dlp} DLP IOCs",
        style="dim",
    )

    # Phase 2: Merge
    console.print("\n[2/4] Merging data...", style="yellow")
    merged = merge_aillm_data(
        ref,
        discovered_domains=discovered_domains,
        discovered_apps=discovered_apps,
        risk_override_path=risk_override_path,
    )
    ms = merged.merge_stats
    if discovered_domains:
        console.print(f"  Discovered: {ms.discovered_new} new domains from {ms.discovered_total}")
    if discovered_apps:
        console.print(f"  Discovered: {ms.discovered_apps_new} new apps from {ms.discovered_apps_total}")

    # Dry run: show what would be written and return early
    if dry_run:
        from rich.table import Table as RichTable

        console.print()
        tbl = RichTable(show_header=True, header_style="bold", box=None)
        tbl.add_column("Table", style="cyan", no_wrap=True)
        tbl.add_column("Records", justify="right")
        total = 0
        for bucket in sync_buckets:
            exa_name = TABLE_MAP[bucket]
            records: list[dict[str, str]] = getattr(merged, bucket)
            tbl.add_row(exa_name, str(len(records)))
            total += len(records)
        console.print(tbl)
        console.print(f"\n  Total: {total} records across {len(sync_buckets)} tables")
        console.print("  Dry run — no changes made.", style="dim")
        return []

    # Phase 3: Resolve tables
    console.print("\n[3/4] Resolving target context tables...", style="yellow")
    # Resolve tenant-wide attribute IDs (EXA-CONTEXT-SCHEMA-35 workaround)
    known_attr_ids: dict[str, str] = {}
    try:
        tenant_attrs = get_attributes(client, "Other")
        for a in tenant_attrs:
            if a.get("displayName"):
                known_attr_ids[a["displayName"]] = a["id"]
    except Exception:
        pass
    table_ids = _resolve_tables(client, sync_buckets, known_attr_ids)

    # Resolve risk attr ID for PublicDomains
    risk_attr_id: str | None = None
    if "public_domains" in sync_buckets and "public_domains" in table_ids:
        risk_attr_id = _resolve_risk_attr_id(client, table_ids["public_domains"])

    # Phase 4: Sync each table
    console.print("\n[4/4] Syncing tables...", style="yellow")

    for bucket in sync_buckets:
        exa_name = TABLE_MAP[bucket]
        records: list[dict[str, str]] = getattr(merged, bucket)
        ref_count = len(getattr(ref, bucket))

        # Remap risk column if needed (EXA-CONTEXT-SCHEMA-35)
        if bucket == "public_domains" and risk_attr_id and risk_attr_id != "risk":
            records = [{"key": r["key"], risk_attr_id: r["risk"]} for r in records]

        console.print(f"\n  {exa_name}", style="cyan")
        console.print(f"    Reference: {ref_count} | Merged: {len(records)}")

        if not records:
            console.print("    SKIP: No records to sync", style="dim")
            results.append(SyncResult(table_name=exa_name, reference_entries=ref_count))
            continue

        if bucket not in table_ids:
            console.print("    SKIP: Table not resolved", style="red")
            results.append(SyncResult(table_name=exa_name, errors=1, error_detail="Table not resolved"))
            continue

        table_id = table_ids[bucket]
        merged_total = len(records)

        # Dedup: filter out keys already present on the tenant (append mode only).
        # force/replace rewrites the whole table so the check is unnecessary.
        skipped = 0
        if operation == "append":
            existing_keys = _fetch_existing_keys(client, table_id)
            if existing_keys:
                records = [r for r in records if r.get("key", "").lower() not in existing_keys]
                skipped = merged_total - len(records)
                if skipped:
                    console.print(
                        f"    {skipped} already present, {len(records)} new to add",
                        style="dim",
                    )

        if not records:
            console.print("    SKIP: All records already present", style="dim")
            results.append(SyncResult(
                table_name=exa_name,
                reference_entries=ref_count,
                merged_total=merged_total,
                skipped=skipped,
            ))
            client.batch_write_sleep()
            continue

        console.print(f"    Uploading {len(records)} records ({operation})...", end="")

        try:
            add_records(client, table_id, records, operation=operation)
            console.print(" OK", style="green")
            results.append(SyncResult(
                table_name=exa_name,
                reference_entries=ref_count,
                merged_total=merged_total,
                upserted=len(records),
                skipped=skipped,
            ))
        except Exception as e:
            console.print(f" FAILED: {e}", style="red")
            results.append(SyncResult(
                table_name=exa_name,
                reference_entries=ref_count,
                merged_total=merged_total,
                skipped=skipped,
                errors=1,
                error_detail=str(e),
            ))

        client.batch_write_sleep()

    # Summary
    console.rule("Sync Complete", style="green")
    total_upserted = sum(r.upserted for r in results)
    total_errors = sum(r.errors for r in results)
    console.print(f"  Total upserted: {total_upserted} | Errors: {total_errors}")

    return results

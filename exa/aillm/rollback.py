"""Snapshot + restore for the AI/LLM context tables — a demo/undo guardrail.

Mirrors the hotkey/zones rollback pattern (`exa/hotkey/rollback.py`) but across the
six OOTB AI/LLM tables at once, so an `aillm sync` (which populates them) can be rolled
back to the exact pre-sync state — making the empty->populated demo repeatable.

Restore is a full-table `addRecords(operation="replace")` per table (the OOTB tables can
404 on `deleteRecords`, so replace is the reliable path). A table that was empty at
snapshot time is cleared by a replace with an empty record set. The snapshot captures
each table's real records verbatim, so `AI/LLM Proxy Categories`' shipped defaults are
preserved exactly, not blanket-deleted.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from exa.context.tables import add_records, get_all_records, get_tables

if TYPE_CHECKING:
    from exa.client import ExaClient

_MANIFEST_DIR = Path.home() / ".exa" / "aillm-rollback"


def is_aillm_table(name: str) -> bool:
    """True for the six OOTB AI/LLM context tables (by display name)."""
    n = (name or "").strip().lower()
    return n.startswith("ai/llm") or n.startswith("public ai")


@dataclass
class AillmRollbackManifest:
    tenant: str
    timestamp: str                     # ISO-compact UTC, e.g. "20260820T221500Z"
    tables: list[dict[str, Any]] = field(default_factory=list)
    # each table: {table_id, name, record_count, records}


def snapshot(client: ExaClient, tenant: str) -> Path:
    """Read all six AI/LLM tables' records and write a rollback manifest.

    Returns the manifest path. Read-only against the tenant.
    """
    tables_meta = [t for t in get_tables(client) if is_aillm_table(t.get("name", ""))]
    captured: list[dict[str, Any]] = []
    for t in tables_meta:
        tid = t.get("id") or t.get("tableId")
        if not tid:
            continue
        records = get_all_records(client, tid)
        captured.append({
            "table_id": tid,
            "name": t.get("name"),
            "record_count": len(records),
            "records": records,
        })
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    manifest = AillmRollbackManifest(tenant=tenant, timestamp=ts, tables=captured)
    return write_manifest(manifest)


def write_manifest(manifest: AillmRollbackManifest) -> Path:
    """Persist a manifest to ~/.exa/aillm-rollback/{tenant}/{timestamp}.json."""
    manifest_dir = _MANIFEST_DIR / manifest.tenant
    manifest_dir.mkdir(parents=True, exist_ok=True)
    path = manifest_dir / f"{manifest.timestamp}.json"
    path.write_text(json.dumps(asdict(manifest), indent=2), encoding="utf-8")
    return path


def load_manifest(path: Path) -> AillmRollbackManifest:
    data = json.loads(path.read_text(encoding="utf-8"))
    return AillmRollbackManifest(
        tenant=data["tenant"], timestamp=data["timestamp"], tables=data.get("tables", [])
    )


def latest_manifest(tenant: str) -> Path | None:
    manifest_dir = _MANIFEST_DIR / tenant
    if not manifest_dir.exists():
        return None
    manifests = sorted(manifest_dir.glob("*.json"))
    return manifests[-1] if manifests else None


def _replace_table(client: ExaClient, table_id: str, records: list[dict[str, Any]]) -> None:
    """Full-table replace. An empty record set clears the table via replace semantics."""
    if records:
        add_records(client, table_id, records, operation="replace")
    else:
        # add_records with [] sends zero batches; send one explicit replace-empty to clear.
        client.post(
            f"/context-management/v1/tables/{table_id}/addRecords",
            json={"operation": "replace", "data": []},
        )


def restore(
    client: ExaClient, manifest: AillmRollbackManifest, *, dry_run: bool = False
) -> list[dict[str, Any]]:
    """Restore each AI/LLM table to the manifest's snapshot via full replace.

    Returns a per-table plan/result: {name, snapshot_count, current_count, action}.
    With dry_run=True, computes the plan but writes nothing.
    """
    results: list[dict[str, Any]] = []
    for tbl in manifest.tables:
        tid, name = tbl["table_id"], tbl.get("name")
        snap = tbl.get("records", [])
        try:
            current = len(get_all_records(client, tid))
        except Exception:  # noqa: BLE001 — a read failure shouldn't abort the whole restore
            current = -1
        action = "restore" if current != len(snap) else "no change"
        if not dry_run:
            _replace_table(client, tid, snap)
            action = "restored"
        results.append({
            "name": name,
            "snapshot_count": len(snap),
            "current_count": current,
            "action": action,
        })
    return results

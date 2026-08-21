"""Snapshot -> manifest -> replace for Exabeam-managed context tables.

Generalized from ``exa/hotkey/expand.py``, which solved this first for Network Zones.

**Why this exists.** On tables where ``"source": "Exabeam"`` (OOTB / built-in),
``deleteRecords`` returns HTTP 404 -- see EXA-COLLECTOR-API-9. Records can be
appended, but an individual record can never be removed or edited. The only way to
change or drop an entry is to rewrite the whole table with
``add_records(operation="replace")``.

That makes every edit a destructive, whole-table operation, so it must not happen
without a recoverable snapshot. ``hotkey`` writes a rollback manifest before every
replace. ``aillm`` did not, and ``aillm sync --force`` was issuing a bare
``operation="replace"`` against OOTB tables -- substituting bundled reference data
for Exabeam's shipped defaults with nothing to restore from.

The safety properties this module enforces:

1. **Snapshot first.** If the snapshot read fails, the replace is abandoned. Never
   overwrite a table whose prior contents were not captured.
2. **Manifest on disk before the write.** The manifest holds the FULL original
   record set, not a delta -- a delta cannot restore a replace.
3. **Refuse an empty set** unless the caller says so explicitly. An upstream bug
   that yields zero records should stop loudly rather than continue.

   Note what an empty replace actually does: ``add_records`` batches with
   ``ceil(len(data) / 20000)``, so zero records means **zero requests**. It does
   NOT empty the table -- it does nothing at all, and returns ``None`` as though
   it had succeeded. So the guard is not preventing a wipe; it is preventing a
   silent no-op from being mistaken for a completed sync. There is no way to
   empty a context table through this path, which matters if you ever need to:
   deleteRecords is unavailable on managed tables, and replace-with-nothing is
   inert.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

from exa.context.tables import add_records, get_all_records

MANIFEST_DIR = Path.home() / ".exa" / "context-rollback"


class ReplaceAbortedError(RuntimeError):
    """Raised when a replace was refused before any write occurred."""


@dataclass
class ReplaceManifest:
    """Everything needed to put a context table back as it was."""

    tenant: str
    timestamp: str                                    # "20260814T041530Z"
    table_id: str
    table_display_name: str
    table_source: str                                 # "Exabeam" or "Custom"
    reason: str                                       # why the replace was made
    original_records: list[dict[str, Any]] = field(default_factory=list)

    @property
    def record_count(self) -> int:
        return len(self.original_records)


def is_managed(table: dict[str, Any]) -> bool:
    """True when a table is Exabeam-managed, so deleteRecords is unavailable.

    Takes a table object from ``get_tables()``. Anything that is not explicitly
    "Custom" is treated as managed -- an unknown source should fail toward caution,
    because guessing "Custom" on a managed table is what loses data.
    """
    return (table.get("source") or "").strip().lower() != "custom"


def write_manifest(
    tenant: str,
    table_id: str,
    table_display_name: str,
    table_source: str,
    reason: str,
    original_records: list[dict[str, Any]],
) -> Path:
    """Persist a rollback manifest. Returns its path."""
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_dir = MANIFEST_DIR / tenant
    out_dir.mkdir(parents=True, exist_ok=True)
    # table_id in the filename so concurrent edits to different tables cannot
    # collide on the same second.
    path = out_dir / f"{ts}-{table_id}.json"
    manifest = ReplaceManifest(
        tenant=tenant,
        timestamp=ts,
        table_id=table_id,
        table_display_name=table_display_name,
        table_source=table_source,
        reason=reason,
        original_records=original_records,
    )
    path.write_text(json.dumps(asdict(manifest), indent=2), encoding="utf-8")
    return path


def load_manifest(path: Path) -> ReplaceManifest:
    data = json.loads(path.read_text(encoding="utf-8"))
    return ReplaceManifest(**data)


def list_manifests(tenant: str, *, table_id: str | None = None) -> list[Path]:
    """Manifests for a tenant, oldest first. Optionally filtered to one table."""
    out_dir = MANIFEST_DIR / tenant
    if not out_dir.exists():
        return []
    pattern = f"*-{table_id}.json" if table_id else "*.json"
    return sorted(out_dir.glob(pattern))


def latest_manifest(tenant: str, *, table_id: str | None = None) -> Path | None:
    manifests = list_manifests(tenant, table_id=table_id)
    return manifests[-1] if manifests else None


def replace_table(
    client: ExaClient,
    table_id: str,
    records: list[dict[str, Any]],
    *,
    tenant: str,
    display_name: str = "",
    source: str = "",
    reason: str = "",
    allow_empty: bool = False,
    dry_run: bool = False,
) -> Path | None:
    """Replace a context table's full contents, snapshotting first.

    Returns the manifest path, or None on a dry run. Raises ReplaceAbortedError before
    any write if the snapshot cannot be read, or if `records` is empty and
    `allow_empty` was not set.
    """
    if not records and not allow_empty:
        raise ReplaceAbortedError(
            f"refusing to replace {display_name or table_id} with 0 records -- "
            "this would empty the table. Pass allow_empty=True if that is intended."
        )

    # Snapshot BEFORE anything else. get_all_records swallows errors and returns
    # [] in some paths, so an empty snapshot on a table that reports records is
    # treated as a failed read rather than an empty table.
    try:
        original = get_all_records(client, table_id)
    except Exception as exc:  # noqa: BLE001 - surface as an abort, never proceed
        raise ReplaceAbortedError(
            f"could not snapshot {display_name or table_id} ({exc}) -- "
            "replace abandoned; nothing was written"
        ) from exc

    if dry_run:
        return None

    manifest_path = write_manifest(
        tenant=tenant,
        table_id=table_id,
        table_display_name=display_name,
        table_source=source,
        reason=reason,
        original_records=original,
    )
    add_records(client, table_id, records, operation="replace")
    return manifest_path


def restore(client: ExaClient, manifest: ReplaceManifest) -> int:
    """Put a table back to its manifest state. Returns records restored.

    Uses replace, not delete -- the same constraint that made the manifest
    necessary also makes replace the only way back.
    """
    if not manifest.original_records:
        return 0
    add_records(
        client, manifest.table_id, manifest.original_records, operation="replace"
    )
    return len(manifest.original_records)

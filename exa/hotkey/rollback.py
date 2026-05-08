"""Rollback manifest write/read and restore for Network Zones expand."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

from exa.context.tables import add_records

_MANIFEST_DIR = Path.home() / ".exa" / "hotkey-rollback"


@dataclass
class RollbackManifest:
    tenant: str
    timestamp: str                          # ISO 8601 compact UTC e.g. "20260508T143022Z"
    table_id: str
    table_display_name: str
    zone_name: str                          # zone that was replaced
    original_records: list[dict[str, Any]]  # records to restore on rollback
    added_keys: list[str]                   # /24 record keys to delete on rollback


def write_manifest(
    tenant: str,
    table_id: str,
    table_display_name: str,
    zone_name: str,
    original_records: list[dict[str, Any]],
    added_keys: list[str],
) -> Path:
    """Write manifest JSON to ~/.exa/hotkey-rollback/{tenant}/{timestamp}.json.

    Creates parent dirs as needed. Returns the manifest path.
    """
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    manifest_dir = _MANIFEST_DIR / tenant
    manifest_dir.mkdir(parents=True, exist_ok=True)
    path = manifest_dir / f"{ts}.json"
    manifest = RollbackManifest(
        tenant=tenant,
        timestamp=ts,
        table_id=table_id,
        table_display_name=table_display_name,
        zone_name=zone_name,
        original_records=original_records,
        added_keys=added_keys,
    )
    path.write_text(json.dumps(asdict(manifest), indent=2), encoding="utf-8")
    return path


def load_manifest(path: Path) -> RollbackManifest:
    """Load a manifest JSON file. Raises FileNotFoundError if missing."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return RollbackManifest(**data)


def latest_manifest(tenant: str) -> Path | None:
    """Return the path of the most recent manifest for a tenant, or None."""
    manifest_dir = _MANIFEST_DIR / tenant
    if not manifest_dir.exists():
        return None
    manifests = sorted(manifest_dir.glob("*.json"))
    return manifests[-1] if manifests else None


def apply_rollback(
    client: ExaClient,
    manifest: RollbackManifest,
    *,
    table_id: str,
) -> None:
    """Restore the table to its pre-expand state via full replace.

    The manifest stores the complete original table snapshot. A single
    add_records(operation="replace") atomically restores all records.
    No delete call needed — replace overwrites the entire table.
    """
    if manifest.original_records:
        add_records(client, table_id, manifest.original_records, operation="replace")

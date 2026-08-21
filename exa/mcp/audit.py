"""Metadata-only audit log for the MCP tool surface.

Design follows observra's assurance principles (open-agent-ai-security/observra):

- **DEFAULT ON.** A good agent keeps an audit trail. Logging runs unless explicitly
  turned off (``EXA_AUDIT=off``).
- **FAIL-OPEN, ALWAYS.** Telemetry is best-effort and must NEVER break or slow a tool
  call. Any logging error is swallowed; the tool call proceeds regardless.
- **PRIVACY BY CONSTRUCTION.** We log *metadata* about what was done — tool name,
  tenant/kind, read vs write, duration, ok/error, result size, and non-sensitive
  action ids (alert_id / case_id / priority / stage). We NEVER log the free-text
  values, notes, secrets, or result payloads. The trail records *what was decided*,
  not the raw evidence.
- **BOUNDED.** The jsonl file rotates (default ~10 MB × 5 backups) so it never grows
  without limit. Local, offline, no network egress.

This is a self-contained implementation of that pattern — no ``observra`` dependency,
so the Desktop-spawned server stays dependency-light. The event shape is kept
observra-compatible, so an observra backend can be slotted in later.

Config (all optional):
    EXA_AUDIT=off                    disable (default: on)
    EXA_AUDIT_PATH=~/.exa/audit.jsonl
    EXA_AUDIT_MAX_BYTES=10485760     rotate at ~10 MB (0 disables rotation)
    EXA_AUDIT_BACKUPS=5
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

_OFF = frozenset({"off", "0", "false", "no", "none", "disabled"})
# Only these argument fields are ever recorded — ids and enums, never free text.
# queue/vendor were dropped: they are free-form strings, not enums (PRAX-2026-08-19-007).
_SAFE_ACTION_FIELDS = ("alert_id", "case_id", "priority", "stage", "kind", "tenant")
_DEFAULT_PATH = "~/.exa/audit.jsonl"
_DEFAULT_MAX_BYTES = 10 * 1024 * 1024
_DEFAULT_BACKUPS = 5


def enabled() -> bool:
    return os.environ.get("EXA_AUDIT", "").strip().lower() not in _OFF


def _path() -> Path:
    raw = os.environ.get("EXA_AUDIT_PATH", "").strip() or _DEFAULT_PATH
    return Path(os.path.expanduser(raw))


def _int_env(name: str, default: int) -> int:
    try:
        v = os.environ.get(name, "").strip()
        return int(v) if v else default
    except ValueError:
        return default


def _rotate(path: Path, max_bytes: int, backups: int) -> None:
    if max_bytes <= 0 or not path.exists():
        return
    try:
        if path.stat().st_size < max_bytes:
            return
        for i in range(backups, 0, -1):
            src = path if i == 1 else path.with_name(f"{path.name}.{i - 1}")
            dst = path.with_name(f"{path.name}.{i}")
            if src.exists():
                if dst.exists():
                    dst.unlink()
                src.rename(dst)
    except OSError:
        pass  # rotation is best-effort


def record(event: dict) -> None:
    """Append one metadata event as a JSON line. Fail-open — never raises."""
    if not enabled():
        return
    try:
        path = _path()
        path.parent.mkdir(parents=True, exist_ok=True)
        _rotate(path, _int_env("EXA_AUDIT_MAX_BYTES", _DEFAULT_MAX_BYTES),
                _int_env("EXA_AUDIT_BACKUPS", _DEFAULT_BACKUPS))
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=str) + "\n")
    except Exception:
        pass  # telemetry must never break a tool call


def safe_action(arguments: Any) -> dict:
    """Extract ONLY non-sensitive id/enum fields from a tool's arguments."""
    if not isinstance(arguments, dict):
        return {}
    return {
        k: arguments[k]
        for k in _SAFE_ACTION_FIELDS
        if k in arguments and isinstance(arguments[k], (str, int)) and arguments[k] != ""
    }


def _tenant_kind(client: Any) -> tuple[str | None, str | None]:
    tenant = getattr(client, "tenant", None)
    kind = None
    try:
        from exa.config import list_tenants

        kind = (list_tenants().get(tenant or "", {}) or {}).get("kind")
    except Exception:
        pass
    return tenant, kind


def record_tool_call(name: str, arguments: Any, result: Any, session: Any, *, started: float) -> None:
    """Assemble and record one tool-call audit event from the dispatch boundary."""
    if not enabled():
        return
    from exa.mcp.tools import WRITE_TOOLS

    client = getattr(session, "client", None)
    read_only = bool(getattr(session, "read_only", False))
    tenant, kind = _tenant_kind(client)
    text = result[0].text if result and getattr(result[0], "text", None) else ""
    is_err = (not result) or text.startswith('{"error"') or '"error":' in text[:40]

    # Where a report was written (if any) — parsed from the result, not a payload.
    report_path = None
    try:
        import json as _json

        data = _json.loads(text) if text.startswith("{") else {}
        if isinstance(data, dict):
            report_path = data.get("report_saved") or data.get("saved")
    except Exception:
        pass
    # Whether the write guardrail actually neutralized something (side-channel from dispatch).
    neutralized = getattr(session, "_guardrail_neutralized", False) is True
    try:
        session._guardrail_neutralized = False  # clear for the next call
    except Exception:
        pass

    event = {
        "ts": time.time(),
        "event": "tool_call",
        "tool": name,
        "tenant": tenant,
        "kind": kind,
        "write": name in WRITE_TOOLS,
        "server_read_only": read_only,
        "status": "error" if is_err else "ok",
        "duration_ms": round((time.time() - started) * 1000, 1),
        "result_bytes": len(text.encode("utf-8")),
        "action": safe_action(arguments),
    }
    if report_path:
        event["report_path"] = str(report_path)
    if name in WRITE_TOOLS:
        event["write_neutralized"] = neutralized   # a guardrail fired on this write
    record(event)


def record_session_start(client: Any, server_name: str, read_only: bool, tool_count: int) -> None:
    if not enabled():
        return
    tenant, kind = _tenant_kind(client)
    record({
        "ts": time.time(),
        "event": "session_start",
        "server": server_name,
        "tenant": tenant,
        "kind": kind,
        "server_read_only": read_only,
        "tools": tool_count,
    })

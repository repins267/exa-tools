"""Webhook Cloud Collector registry — non-secret info on disk, token in keyring.

`exa auth --collector` registers a tenant's Webhook Cloud Collector: the token
goes to the OS credential store (service ``exa-webhook``, username
``<tenant>-<fmt>``) — the exact key `exa.cli.simulate._resolve_token` reads, so a
registered collector is picked up by `exa simulate` with no further config — and
the non-secret metadata (name, tenant, format, note, created) is recorded in
``~/.exa/collectors.json``.

The split is the same discipline used for ClientSecret: a secret's only resting
place is the credential store; it is never written to a file, and never returned
by any list/inspect path here.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

# Must match exa.cli.simulate._TOKEN_KEYRING_SERVICE and _token_users(): the
# whole point is that a token stored here resolves for `exa simulate`.
KEYRING_SERVICE = "exa-webhook"
_VALID_FORMATS = ("json", "raw")

COLLECTORS_PATH = Path.home() / ".exa" / "collectors.json"


@dataclass(frozen=True)
class Collector:
    """A registered Webhook Cloud Collector. Never carries the token."""

    name: str
    tenant: str
    fmt: str
    keyring_user: str
    note: str = ""
    created: str = ""


def keyring_user(tenant: str, fmt: str) -> str:
    """Credential-store username for a collector's token.

    Mirrors the most-specific key `exa simulate` looks up first, so the two
    features share one token per (tenant, format).
    """
    return f"{tenant}-{fmt}"


def _normalise_fmt(fmt: str) -> str:
    f = (fmt or "").strip().lower()
    if f not in _VALID_FORMATS:
        raise ValueError(f"format must be one of {_VALID_FORMATS}, got {fmt!r}")
    return f


def load_collectors(path: Path | None = None) -> list[Collector]:
    """Every registered collector, or [] if the registry does not exist yet."""
    p = path or COLLECTORS_PATH
    if not p.exists():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    out: list[Collector] = []
    for item in raw.get("collectors", []) if isinstance(raw, dict) else []:
        if not isinstance(item, dict):
            continue
        try:
            out.append(
                Collector(
                    name=str(item["name"]),
                    tenant=str(item["tenant"]),
                    fmt=str(item["fmt"]),
                    keyring_user=str(
                        item.get("keyring_user")
                        or keyring_user(item["tenant"], item["fmt"])
                    ),
                    note=str(item.get("note", "")),
                    created=str(item.get("created", "")),
                )
            )
        except KeyError:
            continue
    return out


def save_collector(
    *,
    name: str,
    tenant: str,
    fmt: str,
    note: str = "",
    path: Path | None = None,
    now: datetime | None = None,
) -> Collector:
    """Upsert a collector's NON-SECRET metadata in ``~/.exa/collectors.json``.

    Keyed by (tenant, fmt): re-registering the same collector updates its name
    and note in place rather than adding a duplicate. Never touches the token.
    """
    fmt = _normalise_fmt(fmt)
    tenant = tenant.strip()
    if not tenant:
        raise ValueError("tenant is required")
    p = path or COLLECTORS_PATH
    existing = {(c.tenant, c.fmt): c for c in load_collectors(p)}

    stamp = (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")
    prior = existing.get((tenant, fmt))
    collector = Collector(
        name=name.strip() or (prior.name if prior else f"{tenant} {fmt}"),
        tenant=tenant,
        fmt=fmt,
        keyring_user=keyring_user(tenant, fmt),
        note=note.strip() or (prior.note if prior else ""),
        created=prior.created if prior else stamp,
    )
    existing[(tenant, fmt)] = collector

    p.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(existing.values(), key=lambda c: (c.tenant, c.fmt))
    p.write_text(
        json.dumps({"collectors": [asdict(c) for c in ordered]}, indent=2) + "\n",
        encoding="utf-8",
    )
    return collector


def store_token(tenant: str, fmt: str, token: str) -> str:
    """Write the collector token to the OS credential store. Returns the username.

    The token is never logged, echoed, or written to collectors.json — only the
    keyring holds it, under the same key `exa simulate` resolves.
    """
    fmt = _normalise_fmt(fmt)
    token = (token or "").strip()
    if not token:
        raise ValueError("token cannot be empty")
    import keyring

    user = keyring_user(tenant.strip(), fmt)
    keyring.set_password(KEYRING_SERVICE, user, token)
    return user


def token_present(tenant: str, fmt: str) -> bool:
    """Whether a token exists in the credential store for this collector.

    Presence only — the value is never returned, so a list/inspect path can show
    stored / missing without exposing the secret.
    """
    try:
        import keyring

        user = keyring_user(tenant.strip(), _normalise_fmt(fmt))
        return bool(keyring.get_password(KEYRING_SERVICE, user))
    except Exception:  # noqa: BLE001 — keyring optional/unavailable: report missing
        return False

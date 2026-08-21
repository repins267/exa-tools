"""Resolve which Field Oracle a given tenant should use.

Resolution order, most specific first:
  1. ~/.exa/cache/field_oracle-<tenant>.json  — built from that tenant's export
  2. ~/.exa/cache/field_oracle.json            — the ACTIVE Oracle (`exa oracle use`
                                                 sets it; also the legacy pC build)
  3. ~/.exa/cache/field_oracle-base.json       — the local base pack (e.g. the demo set)
  4. exa/oracle/data/field_oracle-base.json    — the bundled base pack (ships default)

A consumer that knows the tenant gets that tenant's Oracle directly; one that does
not gets whatever was activated, then the base pack, then the bundled default — so
nothing breaks during the transition and a fresh install still resolves to the
bundled base.
"""

from __future__ import annotations

import re
from pathlib import Path

_BUNDLED_BASE = Path(__file__).resolve().parent / "data" / "field_oracle-base.json"

_SAFE_TENANT = re.compile(r"[^A-Za-z0-9_.-]")


def _cache_dir() -> Path:
    """The Oracle cache dir, resolved from home at call time (test-patchable)."""
    return Path.home() / ".exa" / "cache"


def _tenant_slug(tenant: str) -> str:
    """A filesystem-safe tenant token (nicknames are already simple, but be safe)."""
    return _SAFE_TENANT.sub("-", tenant.strip())


def tenant_oracle_path(tenant: str, *, cache_dir: Path | None = None) -> Path:
    """The path a tenant's own Oracle is written to (whether or not it exists yet)."""
    return (cache_dir or _cache_dir()) / f"field_oracle-{_tenant_slug(tenant)}.json"


def base_oracle_path(*, cache_dir: Path | None = None) -> Path:
    """The path the local base pack is written to (whether or not it exists yet)."""
    return (cache_dir or _cache_dir()) / "field_oracle-base.json"


def oracle_path(
    tenant: str | None = None, *, cache_dir: Path | None = None
) -> Path | None:
    """Best available Oracle for ``tenant``, or None if none exists anywhere."""
    cache = cache_dir or _cache_dir()
    candidates: list[Path] = []
    if tenant:
        candidates.append(cache / f"field_oracle-{_tenant_slug(tenant)}.json")
    candidates.append(cache / "field_oracle.json")   # active / legacy
    candidates.append(cache / "field_oracle-base.json")
    candidates.append(_BUNDLED_BASE)
    for p in candidates:
        if p.exists():
            return p
    return None

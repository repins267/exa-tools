"""Single-pass tenant profile for AI/LLM analysis.

Every `exa aillm` analysis command reads from this profile rather than querying
the tenant directly. One collection pass is cached to disk; subsequent commands
cost zero API calls until the cache is refreshed.

Why this exists
---------------
Ad-hoc analysis re-enumerates the same fields repeatedly — a single GEHA session
issued ~20 group_by calls, fetching `web_domain` six times and `category` four
times. That is unacceptable against a customer production tenant.

Design rules
------------
- **Composite group_by.** ``group_by=["category", "product", "vendor"]`` returns
  values *and* their product/vendor attribution in one request. Three separate
  calls would return the same information.
- **Negative probes are cached.** An HTTP 400 means the field is absent from this
  tenant's schema. That is stable — record it and never re-probe.
- **Truncation is recorded, never inferred.** If a result hits the row cap the
  value set is incomplete. Callers must be able to tell "no matches" from
  "we stopped looking" — conflating the two produces confidently wrong answers.
- **Collections fetched once.** ``get_tables()`` and ``get_detection_rules()``
  each return everything in a single call; never call them per-item.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

CACHE_DIR = Path.home() / ".exa" / "cache"
CACHE_VERSION = 1

# Composite enumerations. Each tuple is ONE API call returning every field in it.
# The first field is the primary value; the rest provide attribution.
_ENUMERATIONS: list[tuple[str, ...]] = [
    ("category", "product", "vendor"),
    ("categories", "product"),
    ("activity_type", "product"),
    ("alert_name", "product", "vendor"),
    ("web_domain",),
    ("app", "vendor"),
]

# Secondary fields, probed in BATCHES rather than one call each.
#
# A composite group_by over several fields costs one request and still tells us,
# per field, whether it is populated. Probing these individually cost 13 calls in
# testing; batched it costs 3. On a 400 (one unknown field poisons the batch) we
# fall back to probing that batch's fields individually.
#
# Batches are grouped by cardinality so a small `limit` stays meaningful:
#   - agent fields are empty on non-agent tenants -> tiny result, cheap
#   - descriptive fields are low-cardinality
#   - high-cardinality fields need only an existence check
_FIELD_BATCHES: list[tuple[str, list[str], int]] = [
    (
        "agent",
        [
            "llm_request", "llm_response", "ai_token_in_count",
            "ai_token_out_count", "ai_token_count", "ai_function_name",
            "ai_tool_name",
        ],
        500,
    ),
    ("descriptive", ["subject", "action", "result"], 1_000),
    # Cap must stay high enough to be conclusive. At limit=1 a single row whose
    # bytes_out/user happen to be null reads as "field unpopulated" — a false
    # negative indistinguishable from a real one. 200 rows is still one cheap
    # call and settles the question.
    ("high_cardinality", ["bytes_out", "user", "src_ip"], 200),
]

_DEFAULT_LIMIT = 5_000


@dataclass
class FieldValues:
    """Distinct values observed for one field, with truncation state."""

    field_name: str
    values: list[str] = field(default_factory=list)
    truncated: bool = False
    exists: bool = True

    @property
    def count(self) -> int:
        return len(self.values)


@dataclass
class TenantProfile:
    """Everything the aillm analysis commands need, collected in one pass."""

    tenant: str
    collected_at: str
    lookback_days: int
    # Cost of THIS invocation. Always 0 when served from cache — do not persist a
    # stale value here, or a warm run reports the cold run's cost and the
    # efficiency metric silently lies.
    api_calls: int = 0
    from_cache: bool = False
    fields: dict[str, FieldValues] = field(default_factory=dict)
    # primary value -> sorted "vendor / product" attributions
    attribution: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    absent_fields: list[str] = field(default_factory=list)

    def values(self, field_name: str) -> list[str]:
        fv = self.fields.get(field_name)
        return fv.values if fv else []

    def exists(self, field_name: str) -> bool:
        fv = self.fields.get(field_name)
        return bool(fv and fv.exists and fv.values)

    def truncated(self, field_name: str) -> bool:
        fv = self.fields.get(field_name)
        return bool(fv and fv.truncated)

    def sources_for(self, field_name: str, value: str) -> list[str]:
        """Which vendor/product emitted a given value of a field."""
        return self.attribution.get(field_name, {}).get(value, [])


def _cache_path(tenant: str) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in tenant)
    return CACHE_DIR / f"aillm-profile-{safe}-{stamp}.json"


def _tenant_id(client: ExaClient) -> str:
    return getattr(client, "tenant", None) or (
        client.base_url.replace("https://", "").replace("/", "_")
    )


def _to_dict(profile: TenantProfile) -> dict[str, Any]:
    d = asdict(profile)
    d["_cache_version"] = CACHE_VERSION
    return d


def _from_dict(raw: dict[str, Any]) -> TenantProfile | None:
    if raw.get("_cache_version") != CACHE_VERSION:
        return None
    try:
        fields = {
            k: FieldValues(**v) for k, v in (raw.get("fields") or {}).items()
        }
        return TenantProfile(
            tenant=raw["tenant"],
            collected_at=raw["collected_at"],
            lookback_days=raw["lookback_days"],
            api_calls=0,  # this invocation cost nothing — it came from disk
            from_cache=True,
            fields=fields,
            attribution=raw.get("attribution") or {},
            absent_fields=raw.get("absent_fields") or [],
        )
    except (KeyError, TypeError):
        return None


def load_cached_profile(client: ExaClient) -> TenantProfile | None:
    """Return today's cached profile for this tenant, or None."""
    path = _cache_path(_tenant_id(client))
    if not path.exists():
        return None
    try:
        return _from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return None


def ensure_fields(
    client: ExaClient,
    profile: TenantProfile,
    names: list[str],
    *,
    batch_size: int = 6,
    limit: int = 500,
) -> TenantProfile:
    """Probe any requested fields the profile does not already know about.

    Callers must never treat "absent from the profile" as "absent from the
    tenant" — the profile enumerates a fixed set, and any field outside it is
    simply unmeasured. Consuming code that needs an arbitrary field (rule
    `requiredFields`, for instance) calls this first so that a False from
    ``profile.exists()`` means verified-absent rather than never-looked.

    Probes in batches and re-caches. Returns the same profile, mutated.
    """
    from exa.search.events import search_events

    unknown = [n for n in dict.fromkeys(names) if n not in profile.fields]
    if not unknown:
        return profile

    for i in range(0, len(unknown), batch_size):
        batch = unknown[i : i + batch_size]
        try:
            rows = search_events(
                client, "", fields=batch, lookback_days=profile.lookback_days,
                limit=limit, group_by=batch,
            )
            profile.api_calls += 1
        except Exception as exc:  # noqa: BLE001
            profile.api_calls += 1
            if "400" not in str(exc):
                continue
            # One unknown field rejects the batch — isolate it.
            for name in batch:
                try:
                    rows_one = search_events(
                        client, "", fields=[name],
                        lookback_days=profile.lookback_days,
                        limit=limit, group_by=[name],
                    )
                    profile.api_calls += 1
                    vals = sorted({str(r.get(name) or "").strip() for r in rows_one
                                   if r.get(name) not in (None, "", "None")})
                    profile.fields[name] = FieldValues(
                        name, values=vals, truncated=len(rows_one) >= limit
                    )
                except Exception:  # noqa: BLE001, S112
                    profile.api_calls += 1
                    profile.fields[name] = FieldValues(name, exists=False)
                    profile.absent_fields.append(name)
            continue

        for name in batch:
            vals = sorted({str(r.get(name) or "").strip() for r in rows
                           if r.get(name) not in (None, "", "None")})
            profile.fields[name] = FieldValues(
                name, values=vals, truncated=len(rows) >= limit
            )

    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_path(profile.tenant).write_text(
            json.dumps(_to_dict(profile), indent=2), encoding="utf-8"
        )
    except OSError:
        pass
    return profile


def collect_tenant_profile(
    client: ExaClient,
    *,
    lookback_days: int = 30,
    refresh: bool = False,
    include_optional: bool = True,
    limit: int = _DEFAULT_LIMIT,
) -> TenantProfile:
    """Enumerate a tenant once and cache the result.

    Args:
        client: Authenticated ExaClient.
        lookback_days: Days of history to enumerate over.
        refresh: Ignore any cached profile and re-collect.
        include_optional: Also probe the optional AI fields (one call each,
            results cached including absences).
        limit: Row cap per enumeration. Truncation is recorded on each field.

    Returns:
        TenantProfile. `api_calls` reports what this collection actually cost;
        it is 0 when served from cache.
    """
    from exa.search.events import search_events

    if not refresh:
        cached = load_cached_profile(client)
        if cached:
            return cached

    profile = TenantProfile(
        tenant=_tenant_id(client),
        collected_at=datetime.now(UTC).isoformat(),
        lookback_days=lookback_days,
    )

    for combo in _ENUMERATIONS:
        primary = combo[0]
        try:
            rows = search_events(
                client, "", fields=list(combo), lookback_days=lookback_days,
                limit=limit, group_by=list(combo),
            )
            profile.api_calls += 1
        except Exception as exc:  # noqa: BLE001
            profile.api_calls += 1
            if "400" in str(exc):
                profile.fields[primary] = FieldValues(primary, exists=False)
                profile.absent_fields.append(primary)
            continue

        seen: set[str] = set()
        attribution: dict[str, set[str]] = {}
        for row in rows:
            val = str(row.get(primary) or "").strip()
            if not val or val == "None":
                continue
            seen.add(val)
            if len(combo) > 1:
                vendor = str(row.get("vendor") or "").strip()
                product = str(row.get("product") or "").strip()
                if product and product != "None":
                    label = f"{vendor} / {product}" if vendor and vendor != "None" else product
                    attribution.setdefault(val, set()).add(label)

        profile.fields[primary] = FieldValues(
            field_name=primary,
            values=sorted(seen),
            truncated=len(rows) >= limit,
        )
        if attribution:
            profile.attribution[primary] = {
                k: sorted(v) for k, v in attribution.items()
            }
        # Attribution combos also tell us product/vendor exist; avoid re-probing.
        for extra in combo[1:]:
            if extra in profile.fields:
                continue
            vals = sorted({str(r.get(extra) or "").strip() for r in rows
                           if r.get(extra) not in (None, "", "None")})
            if vals:
                profile.fields[extra] = FieldValues(extra, values=vals)

    def _probe(names: list[str], cap: int) -> bool:
        """Probe fields in one composite call. False if the batch was rejected."""
        try:
            rows = search_events(
                client, "", fields=names, lookback_days=lookback_days,
                limit=cap, group_by=names,
            )
            profile.api_calls += 1
        except Exception as exc:  # noqa: BLE001
            profile.api_calls += 1
            return "400" not in str(exc)

        for name in names:
            vals = sorted({str(r.get(name) or "").strip() for r in rows
                           if r.get(name) not in (None, "", "None")})
            profile.fields[name] = FieldValues(
                name, values=vals, truncated=len(rows) >= cap, exists=True
            )
        return True

    if include_optional:
        for _label, names, cap in _FIELD_BATCHES:
            pending = [n for n in names if n not in profile.fields]
            if not pending:
                continue
            if _probe(pending, cap):
                continue
            # One unknown field rejects the whole batch — isolate it.
            for name in pending:
                if not _probe([name], cap):
                    profile.fields[name] = FieldValues(name, exists=False)
                    profile.absent_fields.append(name)

    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_path(profile.tenant).write_text(
            json.dumps(_to_dict(profile), indent=2), encoding="utf-8"
        )
    except OSError:
        pass

    return profile

"""Vendor packs — what each security product is known to emit.

Why this exists
---------------
Two engagements needed the same remediation: discover what the tenant emits,
diff it against the context tables, add the difference. Both were executed by
hand, and both re-derived the same vendor taxonomies from scratch — Zscaler's
title-case category strings, Palo Alto's hyphenated ones, Check Point's
Accept/Prevent instead of Allow/Block.

None of that is tenant-specific. It is *product*-specific. Detect the vendor
once (one composite ``group_by``) and the pack supplies the taxonomy without
enumerating anything, which is both cheaper against a production tenant and
identical between customers.

The packs also carry two things nothing else records:

- **Noise patterns.** Check Point SmartDefense emits ``dga-Cai8Z.TC.893fEDbW``
  style tokens — 973 unique values in 30 days, each seen once. They are not
  data, and they must never reach a context table.
- **Normalisation.** Microsoft Purview names classic DLP alerts
  ``DLP policy (<POLICY>) matched for email with subject (<SUBJECT>)`` — one
  distinct value per email. On a live tenant 3,323 distinct values collapsed to
  **2** real policies once the wrapper was stripped. Diffing raw values there is
  meaningless, and the subjects carry patient content.

Adding to a pack after an engagement is how this compounds: customer N+1 starts
where customer N finished.
"""

from __future__ import annotations

import importlib.resources
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# External repo data wins over the bundled snapshot, matching reference.py.
# Populated by `exa update` → ~/.exa/aillm-domains/data/
_EXTERNAL_DATA_DIR = Path.home() / ".exa" / "aillm-domains" / "data"
_FILENAME = "vendor_packs.json"

# Roles that are Exabeam's own output rather than customer telemetry.
INTERNAL_ROLES = frozenset({"internal"})


@dataclass(frozen=True)
class VendorPack:
    """What one vendor/product is known to emit."""

    key: str
    role: str = "unknown"
    # Other `product` strings that mean this same product. The CIM2 product name
    # changes with parser version -- ABA Telemetry ships as "Observra" on
    # pre-rename parsers -- and vendors rename between releases. Without aliases
    # a renamed product silently becomes an unrecognised source.
    aliases: tuple[str, ...] = ()
    category_fields: tuple[str, ...] = ()
    ai_categories: tuple[str, ...] = ()
    allowed_actions: tuple[str, ...] = ()
    blocked_actions: tuple[str, ...] = ()
    identity_fields: tuple[str, ...] = ()
    activity_types: tuple[str, ...] = ()
    alert_name_templates: tuple[str, ...] = ()
    alert_name_noise: tuple[str, ...] = ()
    alert_name_pattern: str | None = None
    # Where this product puts domains. Umbrella uses dns_domain/dns_query and
    # never populates web_domain, so an AI/LLM Web Domains table cannot match it
    # no matter how well populated.
    domain_fields: tuple[str, ...] = ()
    # Fields this product uniquely supplies. Used to answer "what would unblock
    # these rules" with a product name instead of a field list.
    provides_fields: tuple[str, ...] = ()
    unpopulated_fields: tuple[str, ...] = ()
    notes: str = ""
    observed_on: tuple[str, ...] = ()

    @property
    def vendor(self) -> str:
        return self.key.split("/", 1)[0]

    @property
    def product(self) -> str:
        parts = self.key.split("/", 1)
        return parts[1] if len(parts) > 1 else parts[0]

    @property
    def is_internal(self) -> bool:
        return self.role in INTERNAL_ROLES


@dataclass
class Normalised:
    """One raw value reduced to what is actually diffable."""

    raw: str
    value: str
    is_noise: bool = False
    rewritten: bool = False
    reason: str = ""


def _tup(raw: dict[str, Any], key: str) -> tuple[str, ...]:
    v = raw.get(key) or []
    return tuple(str(x) for x in v if x)


def _load_json() -> dict[str, Any]:
    """Load vendor packs, preferring the external repo over the bundled copy."""
    external = _EXTERNAL_DATA_DIR / _FILENAME
    if external.exists():
        return json.loads(external.read_text(encoding="utf-8-sig"))
    data_dir = importlib.resources.files("exa.aillm.data")
    return json.loads((data_dir / _FILENAME).read_text(encoding="utf-8-sig"))


def load_vendor_packs() -> dict[str, VendorPack]:
    """All known vendor packs, keyed by ``"Vendor/Product"``.

    Returns an empty dict rather than raising if the file is missing or
    unreadable — a missing pack degrades to full enumeration, which is slower
    but correct. A hard failure here would block analysis entirely.
    """
    try:
        raw = _load_json()
    except (OSError, json.JSONDecodeError):
        return {}

    packs: dict[str, VendorPack] = {}
    for key, body in (raw.get("packs") or {}).items():
        if not isinstance(body, dict):
            continue
        packs[key] = VendorPack(
            key=key,
            role=str(body.get("role") or "unknown"),
            aliases=_tup(body, "aliases"),
            category_fields=_tup(body, "category_fields"),
            ai_categories=_tup(body, "ai_categories"),
            allowed_actions=_tup(body, "allowed_actions"),
            blocked_actions=_tup(body, "blocked_actions"),
            identity_fields=_tup(body, "identity_fields"),
            activity_types=_tup(body, "activity_types"),
            alert_name_templates=_tup(body, "alert_name_templates"),
            alert_name_noise=_tup(body, "alert_name_noise"),
            alert_name_pattern=body.get("alert_name_pattern") or None,
            domain_fields=_tup(body, "domain_fields"),
            provides_fields=_tup(body, "provides_fields"),
            unpopulated_fields=_tup(body, "unpopulated_fields"),
            notes=str(body.get("notes") or ""),
            observed_on=_tup(body, "observed_on"),
        )
    return packs


def match_pack(
    vendor: str | None,
    product: str | None,
    packs: dict[str, VendorPack] | None = None,
) -> VendorPack | None:
    """Find the pack for an observed vendor/product pair.

    Matches on ``Vendor/Product`` exactly, or on a declared alias. There is
    deliberately **no vendor-only fallback**.

    An earlier version fell back to the vendor's pack when the vendor had only
    one. On the first real tenant that produced two confident misclassifications
    in a single run: ``SentinelOne/Prompt Security`` — an AI security platform
    emitting ``ai_agent-request`` — was labelled ``edr`` by inheriting the
    Singularity pack, and all five ``Cisco/*`` products were labelled ``dns`` by
    inheriting Umbrella's. A vendor sells many products with unrelated roles.

    Returning None costs a role inference from activity types, which is cheap
    and self-correcting. A wrong pack silently supplies a wrong taxonomy, a
    wrong identity field and a wrong role — and looks authoritative doing it.
    Naming variants belong in ``aliases``, where they are explicit.
    """
    packs = load_vendor_packs() if packs is None else packs
    v = (vendor or "").strip()
    p = (product or "").strip()
    if not v and not p:
        return None

    exact = packs.get(f"{v}/{p}")
    if exact:
        return exact

    lv, lp = v.lower(), p.lower()
    if not lp:
        return None
    for pack in packs.values():
        if pack.vendor.lower() == lv and any(a.lower() == lp for a in pack.aliases):
            return pack
    return None


def known_ai_categories(packs: dict[str, VendorPack] | None = None) -> set[str]:
    """Every AI category string any known product emits, lowercased.

    This is the seed for AI/LLM Web Categories and Proxy Categories on a tenant
    whose vendors are recognised — no enumeration required.
    """
    packs = load_vendor_packs() if packs is None else packs
    return {c.lower() for pack in packs.values() for c in pack.ai_categories}


def normalise_alert_name(value: str, pack: VendorPack | None) -> Normalised:
    """Reduce a raw ``alert_name`` to the part worth diffing.

    Strips a vendor's wrapper (Purview's per-email prefix) and flags values that
    are machine-generated noise. Without this, a diff against ``alert_name``
    compares thousands of one-shot strings and proposes adding all of them.
    """
    raw = (value or "").strip()
    if not raw:
        return Normalised(raw=raw, value="", is_noise=True, reason="empty")
    if pack is None:
        return Normalised(raw=raw, value=raw)

    for pattern in pack.alert_name_noise:
        try:
            if re.search(pattern, raw):
                return Normalised(
                    raw=raw,
                    value=raw,
                    is_noise=True,
                    reason=f"machine-generated ({pack.product})",
                )
        except re.error:
            continue

    if pack.alert_name_pattern:
        try:
            m = re.search(pack.alert_name_pattern, raw)
        except re.error:
            m = None
        if m:
            groups = m.groupdict()
            policy = (groups.get("policy") or m.group(0)).strip()
            return Normalised(
                raw=raw,
                value=policy,
                rewritten=True,
                reason=f"extracted policy name ({pack.product})",
            )

    return Normalised(raw=raw, value=raw)


def normalise_alert_names(
    values: list[str],
    pack: VendorPack | None,
) -> tuple[list[str], list[Normalised]]:
    """Normalise a batch, returning (distinct diffable values, all decisions).

    The second element is kept so a caller can report *why* a value was dropped.
    Silent filtering is how a table ends up missing something nobody can explain.
    """
    decisions = [normalise_alert_name(v, pack) for v in values]
    keep: list[str] = []
    seen: set[str] = set()
    for d in decisions:
        if d.is_noise or not d.value:
            continue
        low = d.value.lower()
        if low in seen:
            continue
        seen.add(low)
        keep.append(d.value)
    return sorted(keep), decisions

"""Source inventory — what is actually feeding this tenant.

The first question of an engagement is not "are the tables populated". It is
"what does this customer even send us". Everything downstream depends on the
answer, and getting it wrong is expensive in a specific way: an Umbrella-only
tenant emits ``dns-response`` rather than ``web-activity-*``, so the OOTB AI
rules cannot fire no matter how perfectly the context tables are populated.
Populating tables for a source that does not exist is work that produces
nothing, and nothing about it looks wrong.

Costs 2 API calls: one composite ``group_by`` over vendor/product/activity_type,
and one Cloud Collectors listing. Both are cheap and neither depends on the
cached profile, so this runs first.

Note ``group_by`` returns distinct values with **no count field at all** — this
reports which sources exist and what they emit, never how much. Volume needs a
separate counted query, and conflating the two is how "present" becomes "busy".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from exa.aillm.vendors import VendorPack, load_vendor_packs, match_pack

if TYPE_CHECKING:
    from exa.client import ExaClient

# Role inferred from activity types when no vendor pack matches. Ordered — the
# first hit wins, so agent/AI signals outrank generic web activity.
_ROLE_BY_ACTIVITY: list[tuple[str, re.Pattern[str]]] = [
    ("agent", re.compile(r"^ai_agent-|^tool-(call|return)$", re.I)),
    ("dns", re.compile(r"^dns-", re.I)),
    ("proxy", re.compile(r"^web-activity-|^http-", re.I)),
    ("edr", re.compile(r"^process-|^file-|^registry-|^image-load", re.I)),
    ("identity", re.compile(r"^authentication$|^account-|^session-", re.I)),
    ("email", re.compile(r"^email-|^mail-", re.I)),
    ("alerting", re.compile(r"^alert-trigger$|^rule-trigger$", re.I)),
]

# Activity types that carry AI/LLM signal directly.
_AI_ACTIVITY = re.compile(r"^ai_agent-|^tool-(call|return)$", re.I)

# Roles that can contribute AI visibility even without an ai_* activity type —
# a proxy sees AI domains, a DLP product sees AI policy hits.
_AI_CAPABLE_ROLES = frozenset(
    {"proxy", "dns", "casb", "dlp", "agent", "audit", "medical_device"}
)


@dataclass
class Source:
    """One vendor/product observed feeding the tenant."""

    vendor: str
    product: str
    role: str = "unknown"
    activity_types: list[str] = field(default_factory=list)
    pack: VendorPack | None = None
    collectors: list[str] = field(default_factory=list)
    last_log: str | None = None

    @property
    def key(self) -> str:
        return f"{self.vendor}/{self.product}"

    @property
    def recognised(self) -> bool:
        return self.pack is not None

    @property
    def is_internal(self) -> bool:
        return bool(self.pack and self.pack.is_internal)

    @property
    def ai_relevant(self) -> bool:
        """Whether this source can contribute AI/LLM visibility."""
        if self.is_internal:
            return False
        if any(_AI_ACTIVITY.search(a) for a in self.activity_types):
            return True
        return self.role in _AI_CAPABLE_ROLES


@dataclass
class SourceInventory:
    """Everything feeding a tenant, classified."""

    sources: list[Source] = field(default_factory=list)
    api_calls: int = 0
    collectors_available: bool = True
    truncated: bool = False
    lookback_days: int = 7

    @property
    def ai_sources(self) -> list[Source]:
        return [s for s in self.sources if s.ai_relevant]

    @property
    def unrecognised(self) -> list[Source]:
        """Sources with no vendor pack — candidates to add after the engagement."""
        return [s for s in self.sources if not s.recognised and not s.is_internal]

    def by_role(self) -> dict[str, list[Source]]:
        out: dict[str, list[Source]] = {}
        for s in self.sources:
            out.setdefault(s.role, []).append(s)
        return {k: sorted(v, key=lambda s: s.key) for k, v in sorted(out.items())}

    def missing_roles(self) -> list[str]:
        """AI-relevant roles with no source feeding them.

        An absent role is a coverage gap worth naming: no `agent` source means
        every agent-only rule is unreachable, and no amount of table population
        changes that.
        """
        present = {s.role for s in self.sources if not s.is_internal}
        return [r for r in ("proxy", "dns", "dlp", "edr", "agent") if r not in present]


def _infer_role(activity_types: list[str]) -> str:
    for role, pattern in _ROLE_BY_ACTIVITY:
        if any(pattern.search(a) for a in activity_types):
            return role
    return "unknown"


def collect_sources(
    client: ExaClient,
    *,
    lookback_days: int = 7,
    limit: int = 5000,
) -> SourceInventory:
    """Enumerate the vendors and products feeding this tenant.

    Args:
        client: Authenticated ExaClient.
        lookback_days: History to enumerate. 7 days is enough to see every
            regular feed and cheaper than 30.
        limit: Row cap. Truncation is recorded, never inferred.

    Returns:
        SourceInventory. Two API calls; independent of the cached profile.
    """
    from exa.search.events import search_events

    inv = SourceInventory(lookback_days=lookback_days)
    packs = load_vendor_packs()

    fields = ["vendor", "product", "activity_type"]
    try:
        rows = search_events(
            client,
            "",
            fields=fields,
            lookback_days=lookback_days,
            limit=limit,
            group_by=fields,
        )
        inv.api_calls += 1
    except Exception:  # noqa: BLE001
        inv.api_calls += 1
        return inv

    inv.truncated = len(rows) >= limit

    grouped: dict[tuple[str, str], set[str]] = {}
    for row in rows:
        vendor = str(row.get("vendor") or "").strip()
        product = str(row.get("product") or "").strip()
        if not vendor and not product:
            continue
        if vendor in ("None", "") and product in ("None", ""):
            continue
        activity = str(row.get("activity_type") or "").strip()
        key = (vendor or "(no vendor)", product or "(no product)")
        grouped.setdefault(key, set())
        if activity and activity != "None":
            grouped[key].add(activity)

    for (vendor, product), activities in grouped.items():
        pack = match_pack(vendor, product, packs)
        source = Source(
            vendor=vendor,
            product=product,
            activity_types=sorted(activities),
            pack=pack,
        )
        source.role = pack.role if pack and pack.role != "unknown" else _infer_role(
            source.activity_types
        )
        inv.sources.append(source)

    _attach_collectors(client, inv)
    inv.sources.sort(key=lambda s: (not s.ai_relevant, s.role, s.key))
    return inv


def _attach_collectors(client: ExaClient, inv: SourceInventory) -> None:
    """Match Cloud Collector configs onto the observed sources.

    The resource is ``configs``, NOT ``collectors`` — ``/cloud-collectors/v1/
    collectors`` returns HTTP 400 "No static resource", which reads exactly like
    the API not existing (EXA-CLOUD-COLLECTORS-CONFIGS-PATH).

    A tenant may ingest via Site Collectors or syslog instead, so an empty or
    failed listing is normal and must not be reported as "no sources".
    """
    try:
        configs = client.get("/cloud-collectors/v1/configs")
        inv.api_calls += 1
    except Exception:  # noqa: BLE001
        inv.api_calls += 1
        inv.collectors_available = False
        return

    if isinstance(configs, dict):
        configs = configs.get("configs") or configs.get("items") or []
    if not isinstance(configs, list):
        inv.collectors_available = False
        return

    for cfg in configs:
        if not isinstance(cfg, dict):
            continue
        name = str(cfg.get("name") or cfg.get("id") or "").strip()
        ctype = str(cfg.get("type") or "").strip()
        cvendor = str(cfg.get("vendor") or "").strip()
        last = cfg.get("lastLogReceived")
        label = f"{ctype or 'collector'}: {name}" if name else ctype
        haystack = f"{name} {ctype} {cvendor}".lower()

        for source in inv.sources:
            # Match on PRODUCT, never vendor. Matching "microsoft" against the
            # collector text attached all eight Microsoft collectors to every
            # Microsoft source -- Copilot claimed the Entra ID collectors, which
            # is worse than showing nothing: it asserts an ingestion path that
            # does not exist. An unattributed source is honest; a wrongly
            # attributed one sends someone to the wrong collector to debug.
            if _product_matches(source.product, haystack):
                if label and label not in source.collectors:
                    source.collectors.append(label)
                if last and not source.last_log:
                    source.last_log = str(last)


# Words too generic to identify a product inside a collector name.
_GENERIC_PRODUCT_TOKENS = frozenset(
    {
        "the", "and", "for", "cloud", "security", "platform", "server", "service",
        "services", "system", "systems", "network", "networks", "enterprise",
        "management", "manager", "activity", "log", "logs", "data", "access",
        "id", "inc", "corp", "app", "apps", "suite", "console", "center",
        "microsoft", "cisco", "unix", "windows", "collector",
    }
)


def _product_matches(product: str, haystack: str) -> bool:
    """Whether a collector's text plausibly names this product.

    Requires the full product string, or every distinctive token in it, to be
    present. "Microsoft 365" matches "Microsoft 365 Management Activity";
    "Copilot" does not match "Microsoft Entra ID Collector".
    """
    p = (product or "").strip().lower()
    if not p or p.startswith("(no "):
        return False
    if p in haystack:
        return True
    tokens = [
        t for t in re.split(r"[^a-z0-9]+", p) if t and t not in _GENERIC_PRODUCT_TOKENS
    ]
    return bool(tokens) and all(t in haystack for t in tokens)

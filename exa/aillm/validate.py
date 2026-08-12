"""Validate that AI/LLM context tables match what the tenant actually emits.

The failure this exists to catch
--------------------------------
A context table can hold hundreds of records, report `status: Healthy`, pass any
record-count check — and match nothing. Record count is not a health signal.
Overlap with live field values is.

Measured at geha.use1 (2026-08-11) before remediation:

    AI/LLM DLP Rulesets     46 records   0 overlap   (bundled generic names)
    AI/LLM Web Categories    9 records   0 overlap   (generic labels)
    AI/LLM Web Domains     223 records   ~7 overlap  (registered vs full host)

Eight enabled analytics rules consume three of these tables through
``ContextListContains()``. A dead table silently starves every rule that reads it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from exa.aillm.profile import TenantProfile, collect_tenant_profile
from exa.context.tables import get_all_records_keyed, get_tables

if TYPE_CHECKING:
    from exa.client import ExaClient

# Table display name -> (live CIM field it is matched against, read by rules?)
#
# "Read by rules" is not a guess — these are the tables named inside
# ContextListContains() in the shipped analytics rules. Proxy Categories and
# Public AI Domains are referenced by NO rule; they serve dashboards, searches
# and reference lookups only.
TABLE_FIELD_MAP: dict[str, tuple[str, bool]] = {
    "AI/LLM Applications": ("app", True),
    "AI/LLM Web Domains": ("web_domain", True),
    "AI/LLM Web Categories": ("category", True),
    "AI/LLM DLP Rulesets": ("alert_name", False),
    "AI/LLM Proxy Categories": ("categories", False),
    "Public AI Domains and Risk": ("web_domain", False),
    # Discovered by `exa aillm rules` — these sit outside the "6 AI/LLM tables"
    # the module was built around, but 6 analytics rules each read them to spot
    # locally-run agents and AI dev frameworks (ollama, lm studio, MCP servers).
    # Local models leave no network trace, so these are the only detection path
    # for them.
    "AI Agent Process Names": ("process_name", True),
    "AI Dev Framework Process Names": ("process_name", True),
}

# Tables whose entries are domains — a registered domain in the table legitimately
# covers a full hostname in the logs, so suffix matching applies.
_DOMAIN_TABLES = {"AI/LLM Web Domains", "Public AI Domains and Risk"}

STATUS_OK = "OK"
STATUS_WEAK = "WEAK"
STATUS_DEAD = "DEAD"
STATUS_EMPTY = "EMPTY"
STATUS_UNKNOWN = "UNKNOWN"


@dataclass
class TableValidation:
    """Overlap result for one context table."""

    table_name: str
    table_id: str | None = None
    key_attr: str = "key"
    records: int = 0
    live_field: str = ""
    live_values: int = 0
    exact_matches: int = 0
    suffix_matches: int = 0
    read_by_rules: bool = False
    truncated_sample: bool = False
    status: str = STATUS_UNKNOWN
    matched_examples: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def overlap(self) -> int:
        return self.exact_matches + self.suffix_matches


# Fraction of a table's entries that must match live values before the table is
# considered genuinely useful. Absolute counts mislead: 1 match out of 9 entries
# and 1 out of 900 are both near-useless, but only the second looks obviously bad.
_OK_RATIO = 0.20


def _classify(v: TableValidation) -> str:
    if v.table_id is None:
        return STATUS_UNKNOWN
    if v.records == 0:
        return STATUS_EMPTY
    if v.live_values == 0:
        # Nothing to match against — the field itself is absent or unpopulated.
        return STATUS_UNKNOWN
    if v.overlap == 0:
        return STATUS_DEAD
    if (v.overlap / v.records) < _OK_RATIO:
        return STATUS_WEAK
    return STATUS_OK


def validate_aillm_tables(
    client: ExaClient,
    *,
    profile: TenantProfile | None = None,
    lookback_days: int = 30,
    refresh: bool = False,
) -> list[TableValidation]:
    """Measure overlap between each AI/LLM context table and live tenant data.

    Args:
        client: Authenticated ExaClient.
        profile: Reuse an existing TenantProfile. Collected if omitted.
        lookback_days: Lookback used when collecting a profile.
        refresh: Force profile re-collection.

    Returns:
        One TableValidation per table, in TABLE_FIELD_MAP order.
    """
    profile = profile or collect_tenant_profile(
        client, lookback_days=lookback_days, refresh=refresh
    )

    tables_by_name = {}
    for t in get_tables(client):
        name = (t.get("displayName") or t.get("name") or "").strip()
        if name:
            tables_by_name[name] = t

    results: list[TableValidation] = []
    for table_name, (live_field, read_by_rules) in TABLE_FIELD_MAP.items():
        v = TableValidation(
            table_name=table_name,
            live_field=live_field,
            read_by_rules=read_by_rules,
        )
        table_obj = tables_by_name.get(table_name)
        if table_obj is None:
            v.note = "table not present on tenant"
            v.status = _classify(v)
            results.append(v)
            continue

        v.table_id = table_obj.get("id")
        key_attr, records, keys = get_all_records_keyed(client, table_obj)
        v.key_attr = key_attr
        v.records = len(records)

        live = {x.lower() for x in profile.values(live_field)}
        v.live_values = len(live)
        v.truncated_sample = profile.truncated(live_field)

        exact = keys & live
        v.exact_matches = len(exact)
        matched = set(exact)

        if table_name in _DOMAIN_TABLES:
            for entry in keys - exact:
                hits = [d for d in live if d.endswith("." + entry)]
                if hits:
                    v.suffix_matches += 1
                    matched.add(entry)

        v.matched_examples = sorted(matched)[:8]
        v.status = _classify(v)

        if v.status == STATUS_DEAD and read_by_rules:
            v.note = "starves the analytics rules that read this table"
        elif v.status == STATUS_WEAK and table_name in _DOMAIN_TABLES:
            v.note = "likely form mismatch: registered domain vs full hostname"
        elif v.truncated_sample:
            v.note = "live sample truncated — overlap is a lower bound"

        results.append(v)

    return results


def has_dead_tables(results: list[TableValidation]) -> bool:
    """True if any table read by rules has zero overlap — a non-zero exit case."""
    return any(r.status == STATUS_DEAD and r.read_by_rules for r in results)

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

from exa.aillm.profile import TenantProfile, collect_tenant_profile, ensure_fields
from exa.context.tables import get_all_records_keyed, get_tables

if TYPE_CHECKING:
    from exa.client import ExaClient

RULES = "rules"
DASHBOARD = "dashboard"


@dataclass(frozen=True)
class TableSpec:
    """Which live fields a table is matched against, and who consumes it.

    A table can be matched against MORE THAN ONE field, and the consumer matters:
    a dashboard-only table starves no rule, but a blank panel in front of a
    customer is its own failure. Both facts have to travel with the table.
    """

    fields: tuple[str, ...]
    consumers: frozenset[str]
    domain_form: bool = False

    @property
    def read_by_rules(self) -> bool:
        return RULES in self.consumers


# Extracted from ContextListContains() in the shipped analytics rules on a live
# tenant (baystate.use1, 2026-08-12), parsed with balanced-paren matching.
#
# Two traps this encodes:
#   - Proxy Categories is read by NO analytics rule, but the OOTB "Public AI/LLM
#     Usage" dashboard filters `category` through it on every panel. Measuring it
#     against `categories` measures a field nothing consumes.
#   - Both process-name tables are matched against `parent_process_name` as well
#     as `process_name`. They sit outside the "6 AI/LLM tables" the module was
#     built around, yet 6 rules each read them, and they are the only detection
#     path for locally-run models (ollama, lm studio, llama.cpp, MCP servers)
#     which leave no network trace after download.
TABLE_SPECS: dict[str, TableSpec] = {
    "AI/LLM Applications": TableSpec(("app",), frozenset({RULES})),
    "AI/LLM Web Domains": TableSpec(("web_domain",), frozenset({RULES}), domain_form=True),
    "AI/LLM Web Categories": TableSpec(("category",), frozenset({RULES})),
    "AI/LLM DLP Rulesets": TableSpec(("alert_name",), frozenset({DASHBOARD})),
    "AI/LLM Proxy Categories": TableSpec(("category",), frozenset({DASHBOARD})),
    "Public AI Domains and Risk": TableSpec(
        ("web_domain",), frozenset(), domain_form=True
    ),
    "AI Agent Process Names": TableSpec(
        ("process_name", "parent_process_name"), frozenset({RULES})
    ),
    "AI Dev Framework Process Names": TableSpec(
        ("process_name", "parent_process_name"), frozenset({RULES})
    ),
}

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
    # Live values the tenant emits that this table does NOT contain. This is the
    # populate payload — the direction overlap alone never answers. Unclassified
    # here on purpose; `exa aillm gaps` decides what is safe to add.
    missing: list[str] = field(default_factory=list)
    consumers: list[str] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)

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

    # Probe every field these tables are matched against before measuring.
    #
    # The standing profile enumerates a fixed set that does NOT include
    # process_name or parent_process_name, so those read back as zero values and
    # the tables classified UNKNOWN — "we cannot tell" — when the answer was
    # obtainable. Worse, `exa aillm rules` calls ensure_fields() for rule
    # requiredFields and re-caches, so running rules first silently changed what
    # validate reported. Same command, same tenant, different verdict depending
    # on invocation order. Probe here and the result is order-independent.
    needed = sorted({f for spec in TABLE_SPECS.values() for f in spec.fields})
    ensure_fields(client, profile, needed)

    tables_by_name = {}
    for t in get_tables(client):
        name = (t.get("displayName") or t.get("name") or "").strip()
        if name:
            tables_by_name[name] = t

    results: list[TableValidation] = []
    for table_name, spec in TABLE_SPECS.items():
        v = TableValidation(
            table_name=table_name,
            live_field=", ".join(spec.fields),
            read_by_rules=spec.read_by_rules,
            consumers=sorted(spec.consumers),
            fields=list(spec.fields),
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

        # Union across every field this table is matched against — a table read
        # via both process_name and parent_process_name is covered by either.
        live: set[str] = set()
        for f in spec.fields:
            live |= {x.lower() for x in profile.values(f)}
        v.live_values = len(live)
        v.truncated_sample = any(profile.truncated(f) for f in spec.fields)

        exact = keys & live
        v.exact_matches = len(exact)
        matched = set(exact)
        covered = set(exact)

        if spec.domain_form:
            for entry in keys - exact:
                hits = [d for d in live if d.endswith("." + entry)]
                if hits:
                    v.suffix_matches += 1
                    matched.add(entry)
                    covered.update(hits)

        v.matched_examples = sorted(matched)[:8]
        v.missing = sorted(live - covered)
        v.status = _classify(v)

        # Notes are additive. Truncation used to sit in an elif chain and lose to
        # the form-mismatch note, which is how a truncated sample was reported as
        # a clean result on two consecutive tenants.
        notes: list[str] = []
        if v.status == STATUS_DEAD and spec.read_by_rules:
            notes.append("starves the analytics rules that read this table")
        elif v.status == STATUS_DEAD:
            notes.append(f"blank on any {'/'.join(sorted(spec.consumers))} that reads it")
        if v.status == STATUS_WEAK and spec.domain_form:
            notes.append("likely form mismatch: registered domain vs full hostname")
        if v.truncated_sample:
            notes.append("live sample truncated — overlap is a LOWER BOUND")
        v.note = "; ".join(notes)

        results.append(v)

    return results


def has_dead_tables(results: list[TableValidation]) -> bool:
    """True if any table read by rules has zero overlap — a non-zero exit case."""
    return any(r.status == STATUS_DEAD and r.read_by_rules for r in results)

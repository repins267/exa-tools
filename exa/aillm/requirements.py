"""Assemble the runtime table->required-field map for THIS tenant.

Instead of a frozen literal, derive which context table must hold which CIM
field from what actually consumes each table on the tenant right now:

* deployed rules' ``ContextListContains(table, field)`` (+ ``requiredFields``)
* OOTB dashboard ``.config`` ``event.context_rule`` bindings

``exa/aillm/validate.py:TABLE_SPECS`` stays only as a fallback seed, so the AI
tables still resolve on a tenant with no readable rules/dashboards.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import TYPE_CHECKING, Any

from exa.aillm.consumers import dashboard_context_pairs, rule_context_pairs

if TYPE_CHECKING:
    from exa.client import ExaClient

RULES = "rules"
DASHBOARD = "dashboard"


@dataclass
class Requirement:
    """One context table and the CIM field(s) its consumers match against."""

    table: str
    fields: set[str] = dc_field(default_factory=set)
    consumers: set[str] = dc_field(default_factory=set)  # {"rules","dashboard"}
    rule_names: set[str] = dc_field(default_factory=set)
    resolved: bool = True  # False when a dashboard bound a table_id we couldn't name

    @property
    def read_by_rules(self) -> bool:
        return RULES in self.consumers


def derive_requirements(
    client: ExaClient | None = None,
    *,
    rules: list[dict[str, Any]] | None = None,
    dashboard_configs: list[dict[str, Any]] | None = None,
    tables: list[dict[str, Any]] | None = None,
    seed_fallback: bool = True,
) -> dict[str, Requirement]:
    """Build ``{table_display_name -> Requirement}`` from live rules + dashboards.

    All inputs are injectable for testing; when omitted they are fetched from the
    client. A dashboard binding whose table_id does not resolve is kept keyed by
    its raw id with ``resolved=False`` so nothing is silently dropped.
    """
    reqs: dict[str, Requirement] = {}

    def _add(table: str, fld: str, consumer: str, *, rule_name: str = "",
             resolved: bool = True) -> None:
        r = reqs.setdefault(table, Requirement(table=table))
        if fld:
            r.fields.add(fld)
        r.consumers.add(consumer)
        if rule_name:
            r.rule_names.add(rule_name)
        if not resolved:
            r.resolved = False

    # -- rules --------------------------------------------------------------
    if rules is None and client is not None:
        try:
            from exa.detection.rules import get_detection_rules
            rules = get_detection_rules(client)
        except Exception:  # noqa: BLE001 -- degrade to dashboards/seed
            rules = []
    for rule in rules or []:
        conditions = (
            f"{rule.get('actOnCondition') or ''} {rule.get('trainOnCondition') or ''}"
        )
        for table, fld in rule_context_pairs(conditions):
            _add(table, fld, RULES, rule_name=str(rule.get("name") or ""))

    # -- dashboards ---------------------------------------------------------
    if dashboard_configs:
        by_id: dict[str, str] = {}
        if tables is None and client is not None:
            try:
                from exa.context.tables import get_tables
                tables = get_tables(client)
            except Exception:  # noqa: BLE001
                tables = []
        for t in tables or []:
            tid = t.get("id") or t.get("tableId")
            name = t.get("displayName") or t.get("name")
            if tid and name:
                by_id[tid] = name
        resolved_names = set(by_id.values())
        for cfg in dashboard_configs:
            for table, fld in dashboard_context_pairs(cfg, by_id):
                _add(table, fld, DASHBOARD, resolved=table in resolved_names)

    # -- seed fallback (AI tables still resolve with no rules/dashboards) ----
    if seed_fallback:
        from exa.aillm.validate import TABLE_SPECS
        for tname, spec in TABLE_SPECS.items():
            r = reqs.setdefault(tname, Requirement(table=tname))
            if not r.fields:
                r.fields.update(spec.fields)
                r.consumers.add(RULES if spec.read_by_rules else DASHBOARD)

    return reqs

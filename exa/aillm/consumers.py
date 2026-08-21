"""Read which context table + CIM field each consumer (rule or dashboard) uses.

The tenant's own deployed rules and OOTB dashboards tell us, live, which
`(table, field)` pairs actually matter -- so the populator targets the real
requirement instead of a frozen list. Two readers:

* **rules** -- parse ``ContextListContains('<table>', <field>)`` from a rule's
  act/train conditions (capturing BOTH arguments, not just the table).
* **dashboards** -- invert ``exa/aillm/dashboard.py:build_context_rule`` on each
  panel's ``event.context_rule`` to recover ``(field, table_id)``.
"""

from __future__ import annotations

import re
from typing import Any

# ContextListContains('Table Name', event.field)  -- capture BOTH args. The
# field argument may be event.web_domain / web_domain / 'web_domain'.
_CONTEXT_CALL_PAIR = re.compile(
    r"ContextListContains\(\s*'([^']+)'\s*,\s*'?([A-Za-z0-9_.]+?)'?\s*[),]",
    re.I,
)

# Mirror of exa/aillm/dashboard.py:build_context_rule encoding.
_SEP = "ContextRuleSeparator"


def _clean_field(f: str) -> str:
    f = f.strip().strip("'\"")
    return f[len("event."):] if f.lower().startswith("event.") else f


def rule_context_pairs(conditions: str) -> list[tuple[str, str]]:
    """`(table, field)` pairs a rule's conditions read via ContextListContains."""
    out: list[tuple[str, str]] = []
    for table, field in _CONTEXT_CALL_PAIR.findall(conditions or ""):
        fld = _clean_field(field)
        if table.strip() and fld:
            out.append((table.strip(), fld))
    return out


def parse_context_rule(rule_str: str) -> tuple[str, str] | None:
    """`(field, table_id)` from an encoded ``event.context_rule``, else None.

    Inverse of ``build_context_rule`` -- the encoding is
    ``field | in | custom | <scope> | table_id`` joined by ``_SEP``.
    """
    if not rule_str or _SEP not in rule_str:
        return None
    parts = rule_str.split(_SEP)
    if len(parts) < 5 or parts[1].strip().lower() != "in":
        return None
    field = _clean_field(parts[0])
    table_id = parts[-1].strip()
    return (field, table_id) if field and table_id else None


def dashboard_context_pairs(
    config: dict[str, Any], tables_by_id: dict[str, str] | None = None
) -> list[tuple[str, str]]:
    """`(table, field)` pairs a dashboard config gates on.

    ``tables_by_id`` maps table_id -> display name (from ``get_tables``). A table
    id that cannot be resolved is returned as its raw id, so the caller can flag
    an unresolved binding rather than silently dropping it.
    """
    tables_by_id = tables_by_id or {}
    out: list[tuple[str, str]] = []
    for el in config.get("dashboardElements") or config.get("elements") or []:
        cr = (el.get("filters") or {}).get("event.context_rule")
        parsed = parse_context_rule(cr) if cr else None
        if not parsed:
            continue
        field, table_id = parsed
        out.append((tables_by_id.get(table_id, table_id), field))
    return out

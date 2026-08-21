"""Generate an AI/LLM Landscape dashboard that is identical on every tenant.

The two hand-built Landscape dashboards this replaces (GEHA v3, Baystate v1)
worked, and neither could be reproduced by anyone else. They carried 23
hardcoded domains, one tenant's `action` vocabulary, and category strings pasted
out of query output. Point either at the other customer and most panels go
blank -- silently, because a filter that matches nothing renders as an empty
chart rather than an error.

THE RULE THAT MAKES THIS PORTABLE:

    Panels filter only through context tables. Anything that varies by tenant
    becomes a group-by or a pivot, never a filter.

That single constraint buys vendor independence for free. Pivot on `action` and
the same panel renders `Prevent` at a Check Point site and `Blocked` at a
Zscaler site with no edit. Per-tenant customisation then happens entirely in
Context Management, where a customer can do it themselves, instead of in a
dashboard config only a TAM can edit.

The one thing that legitimately differs between tenants is the resolved context
table ID, which is why `build_dashboard()` looks them up live. Two tenants
should otherwise produce byte-identical output.

Time filters and CIM2 activity types are not tenant-varying values and are used
directly -- `ai_agent-request` means the same thing everywhere.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib.resources import files
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

# How a panel filter binds an event field to a context table. Reverse-engineered
# from OOTB dashboard configs and confirmed against both hand-built Landscapes.
# The parts are: <event field> | in | custom | <entity scope> | <table id>.
_SEP = "ContextRuleSeparator"
_ENTITY_SCOPE = "raw_entity_other_custom"

DEFAULT_TITLE = "AI/LLM Landscape"
DEFAULT_LOOKBACK = "30 day"

_GRID_WIDTH = 24


def build_context_rule(event_field: str, table_id: str) -> str:
    """Encode "event_field IN <context table>" the way the dashboard expects.

    Args:
        event_field: Bare CIM field name, e.g. "web_domain" (no "event." prefix).
        table_id: Context table ID resolved live from this tenant.
    """
    return _SEP.join([event_field, "in", "custom", _ENTITY_SCOPE, table_id])


@dataclass(frozen=True)
class PanelSpec:
    """One panel, defined without a single tenant-specific value.

    `context_table` is a table DISPLAY NAME, resolved to an ID at build time.
    A panel with no `context_table` must justify itself in `note` -- it is
    filtering on something other than a context table, and the only acceptable
    reason is that the value is CIM2 vocabulary rather than tenant data.
    """

    title: str
    fields: tuple[str, ...]
    context_table: str | None = None
    context_field: str = ""
    pivots: tuple[str, ...] = ()
    vis: str = "table"
    width: int = 12
    height: int = 7
    limit: str = "50"
    extra_filters: tuple[tuple[str, str], ...] = ()
    note: str = ""


# Ordered. Layout is computed from `width`, so inserting a panel reflows the
# grid rather than requiring every row/column below it to be renumbered.
PANELS: tuple[PanelSpec, ...] = (
    PanelSpec(
        title="AI Domains Reached, split by outcome",
        fields=("event.web_domain", "event.action", "event.count"),
        context_table="AI/LLM Web Domains",
        context_field="web_domain",
        pivots=("event.action",),
        vis="looker_bar",
        note=(
            "action is pivoted, never filtered. Its vocabulary is vendor-specific "
            "-- Accept/Prevent at Check Point, Allowed/Blocked at Zscaler -- so a "
            "filter here is exactly what made the hand-built versions unportable."
        ),
    ),
    PanelSpec(
        title="Public AI Domains by Risk (source: AI/LLM repo risk scores)",
        fields=("event.web_domain", "event.action", "event.count"),
        context_table="Public AI Domains and Risk",
        context_field="web_domain",
        pivots=("event.action",),
        vis="looker_bar",
        note=(
            "Risk tiers live in the table's risk_level attribute, not on the "
            "event, so risk cannot be a column here. The table membership is the "
            "risk statement: everything shown is a scored public AI domain."
        ),
    ),
    PanelSpec(
        title="AI Categories seen (extend via AI/LLM Proxy Categories)",
        fields=("event.category", "event.count"),
        context_table="AI/LLM Proxy Categories",
        context_field="category",
        vis="looker_pie",
        note=(
            "Proxy Categories, NOT Web Categories. The OOTB dashboards read this "
            "table for event.category; Web Categories feeds analytics rules. One "
            "hand-built Landscape bound this panel to the rules table and it "
            "rendered a plausible but wrong slice."
        ),
    ),
    PanelSpec(
        title="AI Applications in use (extend via AI/LLM Applications)",
        fields=("event.app", "event.count"),
        context_table="AI/LLM Applications",
        context_field="app",
        vis="looker_bar",
    ),
    PanelSpec(
        title="AI DLP Alerts (extend via AI/LLM DLP Rulesets)",
        fields=("event.alert_name", "event.vendor", "event.product", "event.count"),
        context_table="AI/LLM DLP Rulesets",
        context_field="alert_name",
        vis="table",
        note=(
            "event.alert_name is the SOURCE PRODUCT's alert name, a different "
            "namespace from Threat Center alert names (EXA-ALERTNAME-TWO-"
            "NAMESPACES). Populating this table from analytics-rule names yields "
            "zero matches and a blank panel with no error."
        ),
    ),
    PanelSpec(
        title="Which product classifies AI traffic",
        fields=("event.vendor", "event.product", "event.count"),
        context_table="AI/LLM Web Domains",
        context_field="web_domain",
        vis="looker_bar",
        note=(
            "Answers 'where would a control go' without naming a vendor. On a "
            "tenant with one dominant proxy this is a single bar, which is "
            "itself the finding."
        ),
    ),
    PanelSpec(
        title="AI Access by User",
        fields=(
            "event.user",
            "event.email_address",
            "event.web_domain",
            "event.count",
        ),
        context_table="AI/LLM Web Domains",
        context_field="web_domain",
        vis="table",
        width=_GRID_WIDTH,
        note=(
            "Both identity fields are columns because which one is populated is "
            "a tenant property: Purview and M365 fill email_address while user is "
            "null; Check Point fills user with short directory IDs; Umbrella DNS "
            "fills neither. OOTB content that reaches for `user` alone is why "
            "two shipped dashboards show blank user panels."
        ),
    ),
    PanelSpec(
        title="Agentic AI Activity",
        fields=(
            "event.ai_agent_name",
            "event.ai_tool_name",
            "event.model_name",
            "event.count",
        ),
        extra_filters=(("event.activity_type", "%ai_agent-%"),),
        vis="table",
        width=_GRID_WIDTH,
        note=(
            "Filters on activity_type rather than a context table. Justified: "
            "ai_agent-* is CIM2 vocabulary, identical on every tenant, not a "
            "value discovered from this customer's data. Groups on "
            "ai_agent_name, never agent_name -- the latter holds the framework "
            "(claude/adk/openai) by design. Deliberately avoids event.result, "
            "which no Microsoft-sourced agent telemetry populates "
            "(EXA-AGENTIC-DASH-NULL-RESULT)."
        ),
    ),
)


HEADER_TEXT = """AI/LLM Landscape

Every panel filters through a context table, so this dashboard is identical on
every tenant. To broaden or narrow what it shows, edit the tables in Context
Management -- no dashboard edit is needed, and no TAM is needed.

  Panel                          Table to edit
  AI Domains Reached             AI/LLM Web Domains
  Public AI Domains by Risk      Public AI Domains and Risk
  AI Categories                  AI/LLM Proxy Categories
  AI Applications                AI/LLM Applications
  AI DLP Alerts                  AI/LLM DLP Rulesets

A blank panel means the matching table holds nothing this tenant emits, NOT
that there is no activity. Run 'exa aillm gaps' to see what is missing and
'exa aillm gaps apply' to close it.

Outcome values (Allowed / Blocked / Prevent / Accept) are pivoted rather than
filtered, so vendor differences need no edit."""


@dataclass
class DashboardBuild:
    """A generated dashboard plus what could not be built and why."""

    config: dict[str, Any]
    resolved: dict[str, str] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)

    @property
    def panel_count(self) -> int:
        return sum(1 for e in self.config["dashboardElements"] if e.get("type") == "vis")


def _load_date_filter() -> list[dict[str, Any]]:
    """The dashboard-level date filter, kept verbatim as shipped.

    It is ~90 lines of Looker field metadata with no tenant-specific content.
    Bundled rather than reconstructed because a hand-written approximation is
    accepted at import time and then fails to bind, which presents as panels
    ignoring the date picker rather than as an error.
    """
    raw = (
        files("exa.aillm.data")
        .joinpath("dashboard_date_filter.json")
        .read_text(encoding="utf-8-sig")
    )
    return json.loads(raw)


def _resolve_table_ids(client: ExaClient) -> dict[str, str]:
    """Map context table display name -> ID for this tenant."""
    from exa.context.tables import get_tables

    out: dict[str, str] = {}
    for t in get_tables(client):
        # displayName is null on entire tenants (EXA-DISPLAYNAME-UNDOCUMENTED),
        # so fall back to name rather than dropping every table on those.
        name = (t.get("displayName") or t.get("name") or "").strip()
        if name and t.get("id"):
            out[name] = str(t["id"])
    return out


def _panel_element(
    spec: PanelSpec,
    *,
    table_id: str | None,
    lookback: str,
    row: int,
    column: int,
) -> dict[str, Any]:
    filters: dict[str, str] = {"event.approx_log_time": lookback}
    if table_id:
        filters["event.context_rule"] = build_context_rule(spec.context_field, table_id)
        filters["event.apply_context_rule"] = "Yes"
    filters.update(dict(spec.extra_filters))

    return {
        "title": spec.title,
        "title_hidden": False,
        "type": "vis",
        "view": "event",
        "fields": list(spec.fields),
        "pivots": list(spec.pivots) or None,
        "filters": filters,
        "sorts": [],
        "limit": spec.limit,
        "vis_config": {"type": spec.vis},
        "dynamic_fields": "[]",
        "model": "datalake",
        "result_maker": {
            "filterables": [
                {
                    "model": "datalake",
                    "view": "event",
                    "name": "",
                    "listen": [
                        {
                            "dashboard_filter_name": "Event : Approx Log Date",
                            "field": "event.approx_log_date",
                        }
                    ],
                }
            ]
        },
        "height": spec.height,
        "width": spec.width,
        "row": row,
        "column": column,
    }


def build_dashboard(
    client: ExaClient,
    *,
    title: str = DEFAULT_TITLE,
    lookback: str = DEFAULT_LOOKBACK,
    include_header: bool = True,
) -> DashboardBuild:
    """Build the Landscape dashboard config for this tenant.

    The only tenant-specific values in the output are the resolved context
    table IDs. Everything else is fixed, which is what makes two tenants'
    configs diffable.

    A panel whose table is absent from the tenant is SKIPPED, not emitted
    unfiltered. An unfiltered panel would render every event on the tenant and
    look like a working AI panel -- the failure mode that had one OOTB dashboard
    reporting ~200M/day beside a pie chart reporting 551.

    Args:
        client: Authenticated ExaClient.
        title: Dashboard title. Leave at the default for cross-tenant diffing.
        lookback: Relative timeframe, e.g. "30 day".
        include_header: Emit the explanatory text tile.

    Returns:
        DashboardBuild with the config, the resolved table IDs, and the list of
        panels skipped for a missing table.
    """
    available = _resolve_table_ids(client)

    elements: list[dict[str, Any]] = []
    resolved: dict[str, str] = {}
    skipped: list[str] = []
    row = 0

    if include_header:
        elements.append(
            {
                "title_text": title,
                "subtitle_text": "",
                # Plain text only -- the tile does not render HTML or markdown.
                "body_text": HEADER_TEXT,
                "title_hidden": False,
                "type": "text",
                "height": 9,
                "width": _GRID_WIDTH,
                "row": row,
                "column": 0,
            }
        )
        row += 9

    column = 0
    row_height = 0
    for spec in PANELS:
        table_id: str | None = None
        if spec.context_table:
            table_id = available.get(spec.context_table)
            if not table_id:
                skipped.append(f"{spec.title} -- no table '{spec.context_table}'")
                continue
            resolved[spec.context_table] = table_id

        if column + spec.width > _GRID_WIDTH:
            row += row_height
            column = 0
            row_height = 0

        elements.append(
            _panel_element(
                spec, table_id=table_id, lookback=lookback, row=row, column=column
            )
        )
        column += spec.width
        row_height = max(row_height, spec.height)

    config = {
        "title": title,
        "description": (
            "Generated by 'exa aillm dashboard'. Every panel filters through a "
            "context table, so this config is identical on every tenant except "
            "the resolved table IDs. Edit the tables in Context Management to "
            "change what it shows -- do not edit this dashboard."
        ),
        "useCases": [],
        "mitreInfo": [],
        "dashboardElements": elements,
        "dashboardFilters": _load_date_filter(),
    }
    return DashboardBuild(config=config, resolved=resolved, skipped=skipped)


def portable_form(config: dict[str, Any]) -> dict[str, Any]:
    """The config with resolved table IDs stripped, for cross-tenant diffing.

    Two tenants are correctly generated when this is equal for both. Compare
    with this rather than eyeballing the configs -- the IDs are opaque
    ten-character strings and differences elsewhere hide easily among them.
    """
    import copy

    out = copy.deepcopy(config)
    for element in out.get("dashboardElements", []):
        element.get("filters", {}).pop("event.context_rule", None)
    return out

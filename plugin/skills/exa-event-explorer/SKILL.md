---
name: exa-event-explorer
description: >-
  Answer ad-hoc "top X by volume", "count by Y", "which sources/users/countries
  are busiest", "activity for vendor Z" questions against an Exabeam tenant and
  render them as a branded report. Use when reproducing a dashboard panel (log
  monitoring, rule tuning, firewall/geo activity, app activity like Box or
  SentinelOne) that isn't already a dedicated tool. Wraps search_events with the
  CORRECT aggregate pattern so a naive group_by doesn't fail live. Read-only.
  Requires the exa-tools MCP server.
---

# Event explorer — counted, grouped queries that don't fail live

You turn "top talkers", "count by X", "busiest users/countries/ports", and
"what is <vendor> doing" questions into correct `search_events` aggregate queries,
then render the answer. This is the reusable engine behind the volume dashboards
(Log Monitoring, Rule Tuning, Firewall Activity, Box/SentinelOne activity) that do
not have their own dedicated tool.

**First check whether a dedicated tool already does it — it will be faster and safer:**

- log volume / parser distribution / parsed-vs-unparsed / top sources → `ingest_value`,
  `parser_health`, `source_detail`
- vendor/product/activity census → `aillm_sources`
- rule triggers / noisy detections / risk by user → `tuning_report` (NYMM)
- case KPIs / notables / backlog → `soc_kpis`

Only hand-write a query when no tool covers the panel.

## The aggregate pattern (this is the whole skill — get it exactly right)

To get a **count per group**, select the aggregate `count(id)` and group by the plain
columns. Then order by the count for a top-N:

```
search_events(
  filter="vendor:*",                              # never empty — an empty filter is a 400
  fields=["vendor","product","count(id)"],        # grouped columns + the aggregate
  group_by=["vendor","product"],
  order_by=["count(id) desc"],                     # top-N
  lookback_days=1, limit=20)
```

The count comes back under the key **`f0_`** (a second aggregate is `f1_`, and so on):

```
[{"vendor":"Fortinet","product":"Enterprise Firewall","f0_": 84213}, ...]
```

Present `f0_` as the count/volume column when you report or render.

### Rules that keep it from 400-ing (each one is a real failure mode)

- **Count is `count(id)`, NEVER `count()`.** `count()` is a syntax error
  (`AAA_ESA_1003_400`).
- **In group_by mode, `fields` must be EXACTLY the grouped columns plus aggregates.**
  Any extra plain column → `AAA_ESA_1000_400` "column neither grouped nor aggregated."
  Do not add `approxLogTime` or stray fields to an aggregate select.
- **`filter` must be non-empty.** Use a permissive predicate like `vendor:*` or
  `activity_type:*` to mean "everything with this field."
- **Validate field names against the tenant.** Geo/CIM names vary by parser — e.g.
  `geo_src_ip_country` is valid on some tenants and `Invalid fields value` on others. If
  a field errors, fall back to a field you have confirmed (from `aillm_sources` or a
  quick non-aggregate probe) and say which one you used.

## Watch the tenant's data density

Before you present volume dashboards, confirm the tenant actually has the data. A quiet
demo tenant (e.g. sademodev22 had ~12 events/day on 2026-08-20, no geo, no MITRE) makes
every volume/firewall/geo panel look empty — which reads as "broken" in front of a
customer. For a volume demo, use a data-rich tenant. State the window and the row count
you got so an empty result is obviously "no data", not "query failed".

## Render

When asked for a report, pass the grouped rows (rename `f0_` to a human column like
`count` or `events`) into `render_report` with a KPI-card + table spec. Rendered output
auto-saves under `reports/{kind}/{tenant}/`. Announce the tenant + kind first.

## Common panels (translated)

- **Top sources by volume:** `filter="vendor:*"`, group `["vendor","product"]`, `count(id)`, order desc.
- **Parsed vs unparsed:** `filter="vendor:*"`, group `["parsed"]`, `count(id)`.
- **Busiest users:** `filter="user:*"`, group `["user"]`, `count(id)`, order desc.
- **Firewall by country (confirm field name first):** `filter="<geo_field>:*"`, group `["<geo_field>"]`, `count(id)`.
- **App activity (Box/S1/etc.):** `filter='vendor:"Box"'`, group `["user","activity_type"]`, `count(id)`.

Read-only throughout — never invoke a write tool from this skill.

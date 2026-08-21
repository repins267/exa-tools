---
name: exa-ingest-review
description: >-
  Ingest overage / cost review for a New-Scale Analytics tenant — find where the license
  is going and whether each big source earns its ingest. Use when asked to "run an ingest
  review", "why are we over", "overage analysis", "which sources to trim", "ingest value",
  or "deep-dive the top talker". Drives ingest_value → source_detail → Keep/Review/Trim,
  rendered. Read-only. Requires the exa-tools MCP server.
---

# exa-ingest-review — overage & source value

When a tenant is over its ingest entitlement, the question is never "how much" — it's
"**which sources, and can we cut them without losing detection?**" This skill runs the
overage top-down: total volume → top talkers → drill into the ones flagged, so a trim
recommendation is grounded in what a source actually feeds, not just its size.

## Preflight

Call `get_active_tenant`; state the tenant + kind. Read-only throughout — safe on a
customer tenant. Default window 7 days; state it.

## The analysis

1. **`ingest_value`** — the top-down. Entitled vs consumed license, top sources by volume &
   **% of ingest**, unparsed % per source, and a first-pass **Keep / Review / Trim** per
   source (volume vs. whether it feeds an enabled rule). Add `render=true` for the report.
2. **`source_detail vendor=… render=true`** — the drill-down on every Review/Trim candidate
   (and the #1 talker regardless). Shows top msg_types, action mix (e.g. Drop vs Accept),
   activity_types, **unparsed %**, and **which enabled rules consume it** — with its own
   branded report. This is where a "Trim" is confirmed or reversed.
3. **`parser_health`** — if a big source is mostly unparsed, the fix is the parser, not the
   trim. Unparsed volume is ingest you pay for and can't detect on — flag it separately.

## How to read it (the trim conversation)

- **Volume alone never justifies a trim.** A huge source that feeds ten enabled rules is
  working; a huge source that feeds none is cost. `source_detail`'s rules-fed list is the
  deciding evidence — lead with it.
- **Unparsed % is a fork, not a verdict.** High volume + high unparsed = fix the parser
  (recover detection value) *before* deciding to trim. Say which fork you're on.
- **Action mix separates noise from signal.** A firewall that's 95% Accept/allow with no
  rule consuming "accept" is mostly noise volume — a real Trim/sampling candidate. The same
  source's Drop events may be the part worth keeping.
- **Trim ≠ delete.** Framing is sampling, filtering at the collector, or routing to
  archive-tier — not "turn it off." Offer the softest cut that recovers the overage.

## Output

Two branded reports: the `ingest_value` overage summary and a `source_detail` deep-dive per
top talker. Lead with the entitlement gap and the 2–3 sources that close it, each with its
rules-fed evidence and the recommended cut.

## Traps

- Recommendations are mechanical; a TAM confirms against the account and any
  compliance/retention obligation before trimming a source.
- `source_detail`'s context-table filter is approximate — counts show shape, not exact
  scoped values. Say so.
- A source feeding zero rules may still be kept for hunting/compliance — ask, don't assume.
- Read `isEnabled`, never `enabled`, when judging what a source feeds.

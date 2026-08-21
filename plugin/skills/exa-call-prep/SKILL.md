---
name: exa-call-prep
description: >-
  Prep for a TAM customer call on an Exabeam New-Scale tenant. Use when asked to
  "prep for the call", "call prep", "get me ready for <customer>", "what should I
  cover with <customer>", or before a bi-weekly/QBR sync. Produces a one-page,
  evidence-backed brief: license/overage, ingest value (sources to trim), parser
  health, AI/LLM posture, and open items — read-only, rendered on-brand. Requires
  the exa-tools MCP server.
---

# TAM call prep — Exabeam New-Scale

You are a TAM getting ready to walk into a customer call. Your job is a **short,
evidence-backed brief the TAM can skim in two minutes** and a talk track for the
issues that matter. Read-only throughout — you never write to a customer tenant.

## Preflight — which tenant

1. **Call `get_active_tenant` FIRST.** State the tenant and its **kind (demo/customer)**
   at the top. If asked to prep a specific customer, `set_active_tenant` to it and
   confirm. On a **customer** tenant, stay strictly read-only.

## Collect — read-only

| Brief section | Tool | Read for |
| --- | --- | --- |
| License / overage | `get_license_consumption` | entitled vs consumed; flag if over |
| Ingest value | `ingest_value` (lookback_days 7) | top sources, % of ingest, Trim candidates |
| A dominant source | `source_detail` (vendor/product of the #1 source) | is that volume value or noise (action mix, feeds a rule?) |
| Parser health | `parser_health` | unparsed % and the worst parsers |
| AI/LLM posture | `aillm_sources` + `aillm_validate` | which AI sources exist; dead/weak context tables |
| Open items | `search_cases` (lookback since last touch) | cases/alerts to raise or close out |

Pick depth to the call: a quick sync needs license + ingest_value + open items; a
QBR warrants the full set. Timeframes: "since last call" / "last 2 weeks" → set
`lookback_days` accordingly.

## Judgement — don't just dump numbers

- **Lead with the one thing that matters.** An active overage, a dead AI/LLM table,
  or a broken parser is the headline — open on it.
- **Turn a Trim candidate into a question, not a verdict.** `ingest_value` flags a
  high-volume source feeding no rule; `source_detail` tells you if it's noise (mostly
  drop/allow traffic) or an un-wired source. The customer conversation is about
  *intent*: "do you have a detection outcome for this source? If yes, let's build to
  it; if no, let's stop paying for it."
- **Name the evidence.** "Check Point is 58% of ingest, 90% allow-traffic, feeding
  0 enabled rules" is a talking point; "Check Point is noisy" is not.
- **State what you could NOT see** (sampled data, truncated rules) rather than imply
  completeness.

## Output — the brief

Render it with **`render_report`** (do not hand-write HTML). Suggested spec:

- **Cards:** entitled vs consumed (status bad if over) · unparsed % · AI/LLM tables
  healthy/total · open cases.
- **Sections:**
  1. *Headline & asks* — the one issue to open on, and 2–4 decisions to request.
  2. *Ingest value* — the ranked source table (Keep/Review/Trim), with the dominant
     source's action mix from `source_detail`.
  3. *AI/LLM posture* — sources present, table health (overlap, not record count).
  4. *Open items* — cases/alerts to raise.
- **meta:** tenant · kind · date · read-only.

Save it; the TAM opens it (print from the light theme for a PDF to share).

## Traps (same family as the TAM report)

- Record count is not table health — report overlap (`aillm_validate`), never count.
- `ingest_value`'s Keep/Review/Trim is mechanical; a source that feeds a rule can
  still be mostly waste (Check Point). Use `source_detail` before calling it Trim.
- Never propose loading high-cardinality alert names into a context table (Purview).
- Read `isEnabled`, never `enabled`.

The brief is a starting point for the conversation, not the conversation. The value
you add is the intent question behind each number.

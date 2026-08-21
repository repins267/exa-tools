---
name: exa-assess
description: >-
  Assess an Exabeam New-Scale tenant and make its OOTB dashboards work: discover
  what the tenant emits, derive which context table+field each OOTB dashboard/rule
  requires (live), find the gap, and -- gated -- populate the tables so the exact
  `field IN table` panel filters start matching. Use when asked to "assess a
  tenant", "make the OOTB dashboards work", "why is the AI/LLM dashboard empty",
  "populate context tables for a customer", "run an assessment", or "close the
  dashboard gap". READ-ONLY by default; writes are gated. Requires the exa-tools
  MCP server; the write steps run through the exa CLI.
---

# Assess a tenant and populate OOTB context tables

The OOTB dashboards gate every panel on `event.context_rule = <field> IN <table>`
(an **exact-match** membership test). They ship with a tiny slice of generic seed
values, so a real tenant's emitted values don't match and the panels render empty.
Your job: discover the tenant's actual values for each gate field and add the
missing ones to the right table, so the gate matches and the panel lights up.

Two conditions must hold; you only control the second:
1. **Telemetry parsed** — the tenant emits events with the gate CIM fields
   populated (`web_domain`, `category`, `app`, `alert_name`, `outcome`, …). If a
   field isn't parsed, that panel stays empty regardless — a source/parser issue.
2. **Tables contain the emitted values** — this is what `exa assess` fixes.

## Preflight

1. **Call `get_active_tenant` FIRST** and state the tenant + kind.
2. `exa assess` is **READ-ONLY** unless `--apply`. You may run the read-only
   assessment on any tenant. **Writes (`--apply`) and promotion (`--promote`)
   require explicit confirmation**, and on a **customer** tenant require the
   analyst to confirm they intend to write to production context tables.
3. **Never promote customer-specific or PII values to shared knowledge.** The tool
   enforces this (per-record/PII → local-only), but you reinforce it at review.

## Surface

- The assessment engine is the **CLI** (`exa assess`). In Claude Code, run it in
  the shell. In Claude Desktop you cannot run the CLI — present the exact command
  for the analyst to run, then continue once they paste the output.
- **You (Claude) are the LLM-assist** for the *review tier*: the deterministic
  engine classifies known values; the values it marks `review` are exactly the
  novel ones where your judgement adds value. Classify each, don't rubber-stamp.

## The flow

### 1. Assess (read-only)
```
uv run exa assess --tenant <t> --dashboards <ootb_config_dir>
```
Present three things from the output:
- **Sources** — vendors/products/roles discovered, and any missing AI-relevant
  roles (a coverage gap: e.g. no proxy feeding the AI web dashboards).
- **Requirement map** — which table needs which field, derived live from the
  tenant's rules + the OOTB dashboards. This is *why* each table matters.
- **Gap** — per table, how many values are `propose` vs `withhold`. The withheld
  count is usually large and correct (PII/high-cardinality held back).

### 2. Review the learn candidates — YOUR classification step
The assessment writes a learn file of values **new to exa-tools**, each tiered:
- `auto-promote` — high-confidence generic (safe to add to shared knowledge).
- `review` — generic-looking but unconfirmed. **For each, decide:**
  - **generic AI taxonomy** (a standard category/app/domain any customer could
    emit) → safe to promote;
  - **customer-specific** (an internal app, a customer domain, a bespoke name) →
    keep local, do **not** promote;
  - **PII / per-record** (embeds a user, email, SSN, subject line) → local only.
  Explain each call in one line. When unsure, treat as customer-specific (safe).
- `local-only` — already withheld; never promoted. Confirm, don't override.

### 3. Populate (gated write)
Show the dry-run first, then apply on confirmation:
```
uv run exa assess --tenant <t> --dashboards <dir> --apply             # dry-run preview
uv run exa assess --tenant <t> --dashboards <dir> --apply --confirm    # write, after confirmation
```
`--apply` writes only the reviewed `propose` bucket; it resolves each table's key
attribute (never assumes `key`), dedups, and polls uploadStatus.

### 4. Promote learned generic knowledge (optional, gated)
Only after your review in step 2, and only the values you judged generic:
```
uv run exa assess --tenant <t> --promote                    # auto-tier only
uv run exa assess --tenant <t> --promote --approve-reviews   # also the review values you approved
```
This grows the shared knowledge base so the next customer starts smarter. **PII /
customer-specific is never promoted** — the tool blocks it and so do you.

### 5. Prove the panel populated
Re-check the dashboard: the value you added now satisfies `field IN table`, so the
panel shows data. For a preview without the UI, render the OOTB `.config`:
```
uv run exa dashboard preview <ootb.config> --tenant <t>
```

## Prove the safety (for skeptical audiences)
```
uv run exa assess benchmark
```
Scores the classifier on a labelled golden corpus: **auto-promote precision 1.000
· PII-withhold recall 1.000 · zero leaks**, plus the A→E learn curve. The numbers,
not a promise, are the argument.

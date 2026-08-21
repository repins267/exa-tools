---
name: exa-aillm-sync
description: >-
  Run the AI/LLM context-table sync demo on an Exabeam New-Scale tenant — the
  "art of the possible" flow that takes dead AI/LLM tables to live detection. Use
  when asked to "sync the AI tables", "populate AI/LLM context tables", "run the
  AI/LLM demo", "AI landscape sync", or "show the AI sync flow". DEMO TENANTS ONLY
  — it writes to context tables. Requires the exa-tools MCP server; the write
  steps run through the exa CLI.
---

# AI/LLM context-table sync — the demo flow

You are running the AI/LLM sync as a live "art of the possible": show the tables
are empty/dead, populate them from reference data, enrich them from the tenant's
own live telemetry, stand up the dashboard, and show the AI detection rules can
now fire. Frame it as **activation, not repair**.

## Preflight — DEMO ONLY, this writes

1. **Call `get_active_tenant` FIRST** and state the tenant + kind.
2. **If `kind` is not `demo` (or is null/unset), STOP.** This flow writes to
   context tables. Never run it on a customer tenant. Ask the analyst to
   `set_active_tenant` to a demo tenant (e.g. `sademodev23` / `sademodev24`) and
   confirm before continuing. `sademodev22` is currently degraded — avoid it.
3. Confirm the analyst wants to proceed with **writes** to this demo tenant.

## Surface

- Reads (`aillm_sources`, `aillm_validate`, `aillm_rules`, `aillm_gaps`) are MCP
  tools — run them directly.
- Writes (`sync`, `gaps apply`, `dashboard`) are **CLI-only**. In Claude Code, run
  them in the shell. In Claude Desktop you cannot run the CLI — present the exact
  command for the analyst to run in a terminal, then continue once they confirm.

## The flow

### 1. Before — show the gap
- `aillm_sources` — what AI telemetry this tenant actually emits.
- `aillm_validate` — table health as **overlap with live values** (dead/weak).
- `aillm_rules` — how many AI rules exist vs. how many can actually fire. The
  story: rules are enabled and Active but reference **empty tables**, so they are
  silently incapable of firing. That is the gap the sync closes.

### 2. Populate from reference data (preview, then write)
```
uv run exa aillm sync --dry-run --tenant <DEMO>     # preview all 6 tables
uv run exa aillm sync --tenant <DEMO>               # write, after the analyst confirms
```

### 3. Enrich from this tenant's live telemetry
```
uv run exa aillm gaps --out gaps.json --tenant <DEMO>      # what live values the tables lack (read-only)
uv run exa aillm gaps apply gaps.json --tenant <DEMO>      # dry-run by DEFAULT; re-run with the write flag to apply
```
Check the write flag with `exa aillm gaps apply --help` and **always show the
dry-run diff first**, then apply on confirmation. `gaps apply` polls uploadStatus.

### 4. Stand up the dashboard
```
uv run exa aillm dashboard --tenant <DEMO>          # generates the AI/LLM Landscape dashboard
```
Import it in the Exabeam UI: **Dashboards → Import**.

### 5. After — show it lit up
- `aillm_validate` again — the tables now have real overlap (before → after).
- `aillm_rules` again — reachable-rule count rises; the AI detections can fire.

## Talk track

- **Lead on activation.** "These AI rules are on, but their tables were empty — so
  they couldn't fire. Watch this." Then sync → gaps → dashboard.
- **Overlap, not count.** Show the *overlap* jump in `aillm_validate`, never a
  record count — a table with 57 records and zero overlap is dead.
- **Live enrichment is the wow.** `gaps` pulls what THIS tenant emits that the
  reference set misses — the tables end up tuned to the customer, not generic.
- **Name the after-state.** "N more AI rules can now fire" is the close.

## Traps

- Never run this on a customer tenant (preflight refuses).
- Overlap is the measure, not record count.
- Read `isEnabled`, never `enabled`.
- Preview every write (`--dry-run` / the apply dry-run) before committing.
- On a DNS-only tenant, `aillm_risk` reads the wrong field — see the TAM report skill.

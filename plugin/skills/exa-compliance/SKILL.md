---
name: exa-compliance
description: >-
  Compliance audit for an Exabeam NSA tenant — automated evidence collection and gap
  analysis across 11 frameworks (NIST CSF, CMMC, PCI DSS, HIPAA, FedRAMP, CIS v8, ISO
  27001, CJIS, GDPR, SOX). Use when asked to "run a compliance audit", "PCI/HIPAA gap
  analysis", "compliance report", "which controls are covered", or "framework coverage".
  Code-first: drives the `exa compliance` CLI. Queries adapt per-tenant via Field Oracle.
  WRITE WARNING: sync-identity / sync-ootb write context tables to the tenant and have NO
  MCP --allow-writes gate — confirm the tenant before syncing; audit and status are
  read-only.
---

# exa-compliance — framework audit & gap analysis

Runs automated evidence collection against a compliance framework and produces a branded
HTML/PDF report with an executive summary and **gap analysis**. Queries are built
per-tenant via Field Oracle concept resolution — controls match the `activity_type` values
actually present, so a missing log source shows as an honest **gap**, not a false negative
from a wrong query. Code-first: use the `exa compliance` CLI.

## Preflight & warm-up

Run these first (in Claude Code / a terminal in the repo — `uv run` uses the project venv):

- `uv run exa config tenants` — which tenants are configured + which is active/default.
- `uv run exa auth --tenant <t>` — confirm credentials work before anything else.
- `uv run exa frameworks` — list the 11 built-in frameworks + their SIEM coverage; pick the
  one the customer is measured against.
- `uv run exa compliance status --tenant <t>` — record counts + health of the 6 compliance
  identity tables. **If empty/stale the audit under-reports** — say so, or re-sync first.

`frameworks`, `status`, and `audit` are read-only. **`sync-identity` / `sync-ootb` WRITE
context tables to the tenant and have no `--allow-writes` gate** — confirm the tenant first,
and never sync a customer tenant just to demo it.

## The workflow

1. **`exa frameworks`** — choose the framework (e.g. PCI DSS, HIPAA, NIST CSF v2.0).
2. **`exa compliance status`** — record counts + health of the 6 compliance identity tables.
   If empty/stale, the audit will under-report — say so before running.
3. **`exa compliance sync-identity`** / **`sync-ootb`** (writes) — populate the identity
   tables and the framework control→rule mapping. Only if status shows they're missing, and
   only with the tenant confirmed.
4. **`exa compliance audit <framework>`** — the gap analysis + branded report.

## How to read it (the honest-gap discipline)

- **A gap is a finding, not a failure of the tool.** If a control fails because the tenant
  doesn't send that log source (e.g. physical access control), report it as a coverage gap
  with the missing source named — never imply the control passed.
- **Coverage % is a SIEM-detection measure, not a certification.** Say plainly: this shows
  what the SIEM can evidence, it is not an auditor's pass/fail. Keep the report's own
  gap-analysis disclaimer intact.
- **Per-tenant queries mean per-tenant results.** The same framework scores differently on
  two tenants because their log sources differ — that's correct, not a bug.
- **Stale identity tables skew everything.** If `status` was old, re-sync before trusting a
  score, and note the sync time in the writeup.

## Output

The `audit` command renders the branded report (HTML/PDF) with executive summary + gaps.
Lead with the coverage %, the top 3 gaps, and the source that would close the most controls.

## Traps

- `sync-identity` / `sync-ootb` write to the tenant's context tables — confirm the tenant;
  don't sync a customer tenant to demo it.
- Don't present coverage % as compliance certification — it's evidence readiness.
- An empty/partial identity table produces a falsely low score — check `status` first.
- Field Oracle resolution is per-tenant; a control marked "gap" on tenant A may pass on
  tenant B with the right source — don't generalize one tenant's result.

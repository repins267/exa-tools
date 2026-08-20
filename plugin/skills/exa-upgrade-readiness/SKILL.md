---
name: exa-upgrade-readiness
description: >-
  Check whether a tenant is ready for a New-Scale Analytics (NSA) upgrade by
  verifying the SE prerequisite context tables and context source exist and are
  populated. Use when asked "is this tenant ready for the NSA upgrade", "run the
  NSA prereq check", "upgrade readiness", "do we have the context tables", or when
  preparing an AA→NSA migration. Read-only; produces a readiness report. Requires
  the exa-tools MCP server.
---

# NSA upgrade readiness — prerequisite validator

You verify a tenant has the data-plane prerequisites an SE must have in place before an
Advanced Analytics → New-Scale Analytics upgrade, turning the 1-hour manual SE checklist
into an evidence-backed readiness report. Read-only — you never create or modify tables.

Announce the **tenant + kind** first. This is a data-plane check only; the ops runbook
(license sync, provisioning playbooks) is out of scope and lives with CloudOps.

## The prerequisites to verify

Use `context_table` (omit `table` to list all; pass `table`/`contains` to inspect one)
and `list_collectors`. For each required item, report **present & populated / present
but empty / missing**:

1. **Context source collector** — an AD **Site Collector**, EntraID, or Okta context
   collector. Check `list_collectors` for a context/identity collector that is recent
   (not stale). Without it, none of the tables below can stay current.
2. **Users** context table — exists and non-empty (AD/EntraID; Okta = users only).
3. **Devices** context table — exists and non-empty (not required for Okta-only).
4. **Internal Domains** — populated with the customer's web/email domains.
5. **Network Zones** — populated (CIDR Range, Zone Name). If AA Network Zones were
   accurate they migrate automatically — note if they look stale.
6. **Critical Devices** (filtered) — key = hostname.
7. **Privileged Users** (filtered) — key = primary login / email.
8. **Service Accounts** (filtered) — key = primary login / email.
9. **Domain Controllers** (filtered) — key = hostname.

Names vary by customer — match on the intent (e.g. a table whose name contains
"privileged", "service account", "critical", "domain controller"). If several plausibly
match, list them and say which you counted.

## How to run

1. `get_active_tenant` — confirm tenant + kind, state it.
2. `list_collectors` — find the context source; flag if missing or stale.
3. `context_table` (list) — enumerate tables; then read the candidates to check they are
   populated (a table that exists but is empty is a common, silent failure).
4. Build a checklist: ✅ present & populated / ⚠️ present but empty / ❌ missing, one row
   per prerequisite, with the table name and row count you saw.
5. Executive-users identification (CEO + N levels) is a manual fact — ask or mark as
   "operator to confirm", don't guess.

## Report

State an overall verdict: **READY** (all present & populated), **NEEDS WORK** (some empty
or missing — list them), or **NOT READY** (no context source / most tables missing). For
each gap, name the exact table to create/populate and the key field the checklist expects.
Offer to `render_report` the checklist as a branded readiness report under
`reports/{kind}/{tenant}/`.

Read-only throughout. Do not create tables — that is the customer/SE action; you report
what is and isn't there.

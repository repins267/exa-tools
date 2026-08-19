---
name: exa-detection
description: >-
  Detection engineering for Exabeam NSA — convert Splunk SPL and SigmaHQ rules to Exabeam
  EQL, deploy, and manage/version analytics rules. Use when asked to "convert this Sigma /
  SPL rule", "deploy a detection", "port rules to Exabeam", "diff the rule bundles",
  "back up detections", or "what rules exist". Code-first: drives the `exa` CLI directly
  (the full SPL→Sigma→EQL pipeline), not just the MCP tools. WRITE WARNING: deploy /
  import / enable / disable / snapshot write analytics rules to the tenant and have NO
  MCP --allow-writes gate — name the tenant and confirm before any write; convert and
  simulate are safe. Export first for a rollback point.
---

# exa-detection — detection engineering (Code-first)

The repo's core capability: a shared **SPL → Sigma → EQL** pipeline backed by the Field
Oracle (raw→CIM2 field mappings from Exabeam's own parsers). This skill is Code-first —
use the `exa` CLI (~15 detection commands), not the guarded MCP surface, because conversion
and deploy need the full command set. Run in Claude Code with the repo checked out.

## Preflight

Confirm the tenant: `exa config tenants` (which is active) and `exa auth` (creds work).
Conversion is offline and safe; **deploy writes analytics rules to the tenant** — confirm
the tenant + that this is intended before any `deploy`/`import`/`enable` command.

## Convert (offline, always safe)

- **Sigma** — `exa sigma browse` (search the local SigmaHQ index), `exa sigma convert <rule.yml>`
  (→ EQL, with per-field confidence: Oracle / Schema / Passthrough).
- **Splunk** — `exa splunk one "<spl>"` (one search string), `exa splunk convert <file>` (a
  saved-searches export), `exa splunk create-tables` (build the lookup/context tables the
  rule needs).
- **Read the confidence.** Oracle = verified mapping; Schema = typed but unverified;
  Passthrough = the field wasn't mapped — a human checks it before deploy. Never deploy a
  Passthrough-heavy rule without saying which fields are unverified.

## Deploy (writes — confirm first)

- `exa sigma deploy <rule.yml>` / `exa splunk deploy <converted>` — convert **and** push in
  one step. State the tenant and the rule name, get confirmation, then run.
- `exa simulate …` — validate a rule by sending synthetic events *before* trusting it on a
  customer tenant. Prefer this to deploying blind.

## Manage / version

- `exa detection list` (optionally export), `exa detection get <uuid>` — inventory.
- `exa detection export <bundle.json>` — back up rules before a change (do this first).
- `exa detection import <bundle.json>` — restore/migrate to another tenant (writes).
- `exa detection diff <a.json> <b.json>` — what changed between two bundles / two tenants.
- `exa detection enable|disable <uuid>` — toggle a rule (writes).
- `exa detection snapshot` — full-replace snapshot of all rules into a context table.

## The workflow that matters

1. **Export first** (`detection export`) — a rollback point.
2. **Convert** and read the confidence ratings; fix Passthrough fields.
3. **Simulate** on a safe tenant.
4. **Deploy** with the tenant named and confirmed.
5. **Diff** the new export against the pre-change one to prove exactly what landed.

## Traps

- Deploy/import/enable/disable/snapshot all **write** — never run them on a customer tenant
  without naming the tenant and confirming. There is no MCP `--allow-writes` gate on the CLI.
- A clean conversion is not a working detection — Passthrough fields and untested logic fail
  silently. Simulate.
- `detection diff` compares bundles, not live state; export both sides fresh for a true diff.
- Cross-tenant import assumes the target parses the same fields — check reachability
  (`aillm_rules` / field presence) or the rule is enabled-but-silent.

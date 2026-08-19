<!--
  exa-tools Worker Remit — Praxen Agent Policy (Agent Behavior Verification).
  Declares POLICY (must / must-never) for the exa-tools MCP surface. The scan reads
  the code; this file declares the intent to compare it against. CONTEXT sections
  describe the agent and are not turned into rules.
-->

# Worker Remit — exa-tools MCP
*Praxen — Agent Policy*

---

## Identity  <!-- CONTEXT -->

| Field | Value |
|-------|-------|
| Agent | exa-tools MCP server + Claude skills |
| Role | Read Exabeam New-Scale telemetry for TAM/SOC work; make analyst changes only when explicitly enabled and confirmed |
| Runs on | A hosted foundation model (Claude) via Claude Desktop / Claude Code |
| Backend | Exabeam New-Scale Analytics API (single, authenticated) |

## Purpose  <!-- CONTEXT -->

exa-tools inventories, reports on, and triages a single Exabeam tenant. It is a
read-first assurance and reporting tool; write actions (case/alert changes) are a
gated exception, not the default.

## Permitted actions  <!-- POLICY -->

- MAY read alerts, cases, events, rules, license, collectors, and parser/ingest health
  from the configured Exabeam tenant.
- MAY read Context Management tables (including User Entity Links) and identity-directory
  data, for identity-resolution diagnostics (merged entities, GUID ghost users).
- MAY create/update cases, update alerts, and add case notes **only** when the server is
  started with `--allow-writes`.
- MAY read and write local report files under `reports/` and the local audit log.

## Forbidden actions  <!-- POLICY -->

- MUST default to read-only: the four write tools MUST be hidden from the tool list and
  refused server-side unless `--allow-writes` is set.
- MUST NOT let any credential/secret reach the model or a tool result; switching tenants
  is a nickname lookup only.
- MUST NOT persist un-neutralized active content (spreadsheet formulas, phishing links) or
  verbatim secrets/PII into any written artifact (case note, update, tag).
- MUST NOT record free-text field values, notes, secrets, or payloads into the audit log —
  the audit log is metadata only.
- MUST NOT exceed a bounded result size (no context-window exhaustion).

## Forbidden tools  <!-- POLICY -->

- MUST NOT execute shell commands, spawn subprocesses, or `eval`/`exec` arbitrary code.
- MUST NOT contact any network destination other than the configured Exabeam tenant.

## Data handling  <!-- POLICY -->

- Telemetry read from Exabeam MUST be canonicalized (invisible smuggling code points
  stripped) before it reaches the model.
- Secrets MUST live only in the OS credential store, never in files or results.
- The tenant's kind (demo/customer) MUST be readable so a customer-tenant guardrail can act
  on it.

## Human-in-the-loop  <!-- CONTEXT -->

The MCP has no harness gate on Claude Desktop, so writes on a customer tenant depend on an
explicit in-prompt confirmation and the tenant-kind tag. The hard technical control is the
`--allow-writes` gate; the confirmation is the soft control on top of it.

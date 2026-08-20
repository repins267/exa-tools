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
  data, for identity-resolution diagnostics (merged entities, GUID ghost users). These
  diagnostics MAY surface the shared identifier value (email/UPN/SAMAccountName) and the
  affected usernames in read-only reports — that is authorized and necessary to locate the
  merge (the TAM confirms it in Entra); these identifiers are directory data, not secrets.
- MAY persist the chosen active tenant as the default in local config on a tenant switch
  (non-secret nickname), so a server restart keeps the operator's selected tenant.
- MAY create/update cases, update alerts, and add case notes **only** when the server is
  started with `--allow-writes`.
- MAY read and write local report files under `reports/` and the local audit log.

## Forbidden actions  <!-- POLICY -->

- MUST default to read-only: the four write tools MUST be hidden from the tool list and
  refused server-side unless `--allow-writes` is set.
- MUST NOT let any credential/secret reach the model or a tool result. Switching tenants is
  a nickname lookup that persists the chosen tenant to local config (see Permitted actions);
  no secret is ever involved.
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

## Accepted risks (declared, not defects)  <!-- CONTEXT -->

These are conscious design choices with a rationale, not gaps. They are declared here so
they read as accepted policy rather than divergences:

- **Audit records low-cardinality enum fields (`priority`, `stage`).** These are bounded
  status/severity enums (e.g. HIGH/MEDIUM, OPEN/CLOSED), not free-text or PII. They are the
  minimum context needed to reconstruct *what disposition* an action set, and carry no
  sensitive value. Free-text fields (notes, queue, vendor) are excluded; ids and these two
  enums are the deliberate allowlist.
- **The SSE/HTTP transport is unauthenticated by design.** It exists for **local,
  single-operator development only**, defaults to a loopback bind, and prints a prominent
  UNAUTHENTICATED warning (louder on any non-loopback bind). It is not a production surface;
  exposing it beyond localhost, or putting auth in front, is the operator's responsibility.
  The default stdio transport (what Claude Desktop uses) is unaffected.
- **`render_abv` is a hand-authored point-in-time snapshot.** Its clause verdicts are
  manually adjudicated and may lag the code; the report labels itself a *snapshot* and states
  that the live Praxen scan is the fuller, authoritative check. It is a communication
  artifact, not a live assurance oracle — that is the independent Praxen scan's job.

## Assurance & audit  <!-- CONTEXT -->

The audit log records, per tool call: tool, tenant/kind, read/write, status, duration,
result size, safe id/enum action fields, the report path when one is written, and — on write
tools — whether the write guardrail neutralized content. It never records notes, secrets, or
payloads.

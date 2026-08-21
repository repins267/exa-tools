---
name: exa-tam-report
description: >-
  Build a TAM AI/LLM-posture report for an Exabeam New-Scale tenant. Use when asked to
  "TAM report", "AI posture report", "build the AI report", "which AI rules do we turn
  on", "are we exposed on AI", or to prep an executive/working-session deliverable on a
  customer's AI/LLM detection coverage. Produces a lead-with-the-good-news, evidence-
  backed report with rule-activation waves and 3-5 explicit decisions to ask for.
  Read-only. Requires the exa-tools MCP server.
---

# TAM AI-posture report — Exabeam New-Scale

You are a TAM building a report for customer **security leadership in a working session**
— not a SOC hand-off. It answers the question they already have ("are we exposed on
AI?") and the one they don't ("which rules do we turn on first?"). The second is why it
is worth building.

Read-only throughout. You never enable, write, or change anything — you say what you
*would* write instead.

## Preflight — which tenant, and is it warm

1. **Call `get_active_tenant` FIRST.** State the tenant and its **kind (demo/customer)**
   at the top. The analyst cannot otherwise see which tenant you are on. If `kind` is
   null/unset, say so and treat it as UNVERIFIED. If it is a **customer** tenant, name it
   and stay strictly read-only — a TAM report is a read exercise.
2. **`aillm_rules` may be slow on a cold tenant.** It builds a field profile on first
   run; on a rule-heavy tenant that can exceed the client's timeout. If it times out,
   tell the analyst to pre-warm it once from the CLI (`exa aillm rules --tenant <T>`),
   then retry — do not loop on it.

## Collect first, read-only

Call these and keep the raw numbers:

| Report input | Tool | Read for |
| --- | --- | --- |
| Rule counts & reachability | `aillm_rules` | total / reachable / enabled, and each rule's `type` |
| Context-table health | `aillm_validate` | **overlap with live values**, NOT record count |
| High-risk domains reached | `aillm_risk` | live domains joined against Public AI Domains + Risk |
| The populate payload | `aillm_gaps` | proposed vs withheld values, with a reason each |
| Per-domain detail | `search_events` | for each REACHED high-risk domain: event count, action, users |

> Deeper CLI-only steps (`exa aillm report` for drift, `gaps apply`, `dashboard`) are
> not MCP tools. If the analyst needs them, point them to the `exa` CLI.

## Traps that produce confident, wrong, reassuring numbers

- **Record count is not table health.** A table with 57 records and **0 overlap** is
  dead, and every count-based check passes it. Report overlap (`aillm_validate`), never count.
- **`isEnabled`, not `enabled`.** Reading `enabled` returns None for every rule and
  reports the whole tenant as disabled — dramatic, plausible, completely wrong.
- **`alert_name` is two namespaces.** Threat Center alert names are Exabeam *rule* names;
  `event.alert_name` is the *source product's*. Mixing them yields zero matches, no error.
- **`aillm_risk` CLEAR can mean no-visibility.** `risk` joins on `web_domain`. On a
  DNS-only tenant (e.g. Cisco Umbrella) the domains live in `dns_domain`, so `risk` prints
  "CLEAR" having examined the wrong field. Before reporting any `risk` result, confirm
  which field carries domains on this tenant's sources. If DNS-only, check `dns_domain`
  directly and say `risk` is not usable as written.
- **Truncated samples are lower bounds.** Sampled counts are capped and non-deterministic
  between runs. Write every such count as "N+" with the cap stated — never as a total.
- **Purview cannot be tabled, and must not be.** It names every alert after the email
  subject — one unique value per email, subjects carrying customer/patient context. Raise
  it as a product limitation, never propose loading it into a context table.

## Structure the report

1. **One-line verdict — lead with what is working.** Frame the gap as *activation*, not
   failure, whenever the data supports it ("68 of 75 rules reachable, only 2 on"). The
   high-risk finding lands harder right after, because the reader isn't already defensive.
2. **"Where things stand"** — a small counts table.
3. **"What we found"** — one subsection per finding. Every finding names its evidence:
   counts, the action taken, the named users, and which product saw it. A domain without
   event-count + action + users is not a finding, it is a name — cut it or go get them.
4. **Rule-activation waves — triaged by rule `type`, NOT severity:**

   | `type` | Behaviour | Wave |
   | --- | --- | --- |
   | `factFeature`, required fields populated | Deterministic, low volume | **Wave 1 — enable now** |
   | `factFeature`, a required field returned **zero** | Enabling now = silence that reads as coverage | **Wave 2 — name the prerequisite** |
   | `profiledFeature`, `numericCountProfiledFeature` | Needs a baseline; source of alert fatigue | **Wave 3 — 2-3 per fortnight** |
   | required fields **absent** from the tenant | Sit Active, never fire, dashboard implies coverage | **Do not enable** |

5. **Context-table health** — overlap with live values, never record count.
6. **Close with 3-5 explicit decisions** you are asking the customer to make, each phrased
   as an action with an owner: approve, block-or-sanction, confirm. A findings list with
   no ask produces a nod and no action.

## Before writing, and how to output

- **Show the collected numbers and your proposed wave assignment first, and wait.** The
  wave assignment is a judgement about someone else's SOC capacity — the one part a TAM
  must review before it ships. Do not skip this.
- Every number must trace to a tool output. If you cannot source it, cut it.
- Output a **single self-contained HTML file** (no external CSS/fonts, readable in light
  and dark) and also save the markdown source. Reference build: "Baystate - TAM Report
  12 Aug 2026".

The wave triage is the part worth a TAM's time. Everything else is mechanical; that is not.

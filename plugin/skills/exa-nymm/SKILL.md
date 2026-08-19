---
name: exa-nymm
description: >-
  NYMM ("Not Your Momma's Mouton") — detection-tuning insight for a New-Scale Analytics
  tenant, the modern replacement for the deprecated Mouton AA tuning tool. Use when asked
  to "tune the detections", "which rules are noisy", "run NYMM", "Mouton for NSA", "reduce
  alert fatigue", or before a tuning conversation. Ranks alert drivers by volume vs.
  escalation-to-case, flags tune/disable candidates, and frames the tuning conversation.
  Read-only. Requires the exa-tools MCP server.
---

# NYMM — detection tuning for New-Scale Analytics

Mouton (deprecated, Advanced Analytics) drove tuning with `NotableReductionOnDeletion`:
which rules, if disabled, would remove the most notables — the noise. NSA has no
notables/histograms; it has **alerts → cases**. NYMM is the same idea, NSA-native:
**a rule that fires a lot but rarely escalates to a case is noise.**

## Preflight

Call `get_active_tenant`; state the tenant + kind. Read-only throughout — NYMM never
disables a rule, it *recommends*. On a customer tenant, everything here is safe (reads).

## The analysis

1. **`tuning_report`** — the core. Alert drivers ranked by volume, with `% of all`,
   `avg_risk`, **escalation rate** (alerts that became cases), and a **Keep / Review /
   Tune-disable** recommendation. The Tune/disable rows are the Mouton
   NotableReductionOnDeletion analog: high volume + low escalation + low risk.
2. **`soc_kpis`** — case context: is the low escalation because the rules are noise, or
   because the queue is unworked? (A 0% close rate with 50 unassigned cases changes the
   read — say so.)
3. **`parser_health`** — data health. Noisy or missing detections often trace to unparsed
   logs or a broken parser, not the rule. Check before blaming the rule (the Mouton
   "ldif vs observed / parsing issue" instinct).
4. **`list_detection_rules`** — enabled rules that are **not reachable** (required fields
   absent on this tenant) are the "never-converge" analog: on and Active, but silently
   incapable of firing. Flag them separately from noisy rules.

## How to read it (the tuning conversation)

- **Lead with the biggest lever.** The #1 driver by volume with ~0% escalation is where
  the noise is. On a demo tenant "Multiple Anomalies" at ~50% / 0% escalation is the
  headline — that one rule is half the alert volume and almost never actionable.
- **Escalation rate is the fidelity signal.** High volume + low escalation = tune (raise
  threshold / scope the rule / fix the data) or disable. High escalation or high risk =
  keep, even if noisy.
- **Separate noise from silence.** Noisy rules (fire too much) vs silent rules (enabled,
  unreachable, never fire) are different fixes — one is "turn down", the other is "wire
  up the data or turn off".
- **Rule out data first.** Before recommending a rule change, confirm the source parses
  (`parser_health`) and feeds the rule (`source_detail` on the driving source).
- **Trend it.** Re-run over time; a falling driver-% / rising escalation rate is tuning
  working — the Mouton "notable reduction after tuning" story.

## Output

Render with `tuning_report render=true` (branded NYMM report) or `render_report` for a
custom cut. Recommendations are **mechanical** — a TAM confirms against the account and
the customer's risk appetite before disabling anything. State what you could not see
(sampled alerts, unreachable rules) rather than implying a complete tuning pass.

## Traps (same family as the TAM report)

- Escalation rate can be low because the SOC isn't working cases, not because rules are
  noise — cross-check `soc_kpis` before calling a rule noise.
- Read `isEnabled`, never `enabled`.
- A rule with no data isn't noise, it's silent — different fix.
- Alerts are sampled at 5,000; on a busy tenant say the driver mix is a lower bound.

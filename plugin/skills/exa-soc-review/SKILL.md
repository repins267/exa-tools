---
name: exa-soc-review
description: >-
  SOC-manager review for a New-Scale Analytics tenant — the weekly/monthly operational
  health of the SOC. Use when asked to "run the SOC review", "SOC manager KPIs", "how is
  the SOC doing", "backlog / close rate / MTTR", "prep the SOC metrics", or before a SOC
  1:1. Pairs case KPIs (soc_kpis) with detection noise (NYMM/tuning_report) so low
  numbers get the right diagnosis. Read-only. Requires the exa-tools MCP server.
---

# exa-soc-review — SOC operational health

A SOC manager asks three things: **are we keeping up (backlog/close rate), are we fast
(MTTR/age), and is the work real (noise vs signal)?** This skill answers all three and —
the point — connects them, so a bad number gets the right cause instead of a guess.

## Preflight

Call `get_active_tenant`; state the tenant + kind. Everything here is read-only, safe on a
customer tenant. Default window is 30 days; say the window you used.

## The analysis

1. **`soc_kpis`** — the core. Cases opened/closed, **open backlog**, **close rate**, **MTTR**
   (avg time to close), **avg open age**, and breakdowns by analyst, priority, queue, top
   firing rules, and notable users. Add `render=true` for the branded report.
2. **`tuning_report`** (NYMM) — the noise lens. If close rate is low or backlog is climbing,
   check whether a few detections are flooding the queue (high volume, ~0% escalation). A
   noise problem and a staffing problem look identical in the KPIs until you overlay this.
3. **`search_cases`** — spot-check the oldest open cases (sort by age) to see if the backlog
   is real work or stale/abandoned cases that should be closed.

## How to read it (the manager conversation)

- **Backlog + close rate together.** Rising backlog with a healthy close rate = volume
  outpacing capacity (staffing/automation). Rising backlog with a *low* close rate = cases
  aren't being worked or aren't real — check the noise lens next.
- **Low close rate has two causes, and they're opposite fixes.** Either the SOC isn't
  working the queue (people/process), or the queue is full of noise that shouldn't be there
  (tune the rules — hand it to NYMM). Never report "low close rate" without saying which.
- **MTTR vs avg open age.** MTTR is how fast *closed* cases closed; avg open age is how long
  the *unworked* ones have sat. A good MTTR with a high open age means the easy cases get
  worked and the hard ones rot — a triage/ownership gap.
- **By-analyst is load, not performance.** Uneven case load flags a routing/queue problem;
  don't read it as who's "better." Say that out loud.
- **Top firing rules = where the volume comes from.** If one rule dominates the case load,
  that's the first NYMM candidate.

## Output

`soc_kpis render=true` gives the branded SOC KPI report; add the NYMM report when noise is
implicated. Lead with the one number that changed and its cause, not a wall of metrics.

## Traps

- A 0% close rate with a big unassigned backlog is a *process* signal, not a rule signal —
  don't send it to tuning without checking assignment first.
- Cases are sampled at 5,000; on a busy tenant say the counts are a lower bound.
- Timestamps are microseconds — the tool normalizes them; if MTTR looks absurd (negative or
  thousands of hours) say the data is dirty rather than reporting it.
- Read-only: this reviews the SOC, it doesn't reassign or close anything.

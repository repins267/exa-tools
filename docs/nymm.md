# NYMM — detection tuning

Rank a New-Scale tenant's noisiest detections by how rarely they escalate to a case, so a tuning conversation starts from evidence instead of a hunch — read-only, it recommends and never disables.

[← README](../README.md)

NYMM ("Not Your Momma's Mouton") is the New-Scale-native replacement for the deprecated **Mouton** Advanced Analytics tuning tool. It ships as the `tuning_report` MCP tool and the `exa-nymm` skill.

## Why Mouton needed replacing

Mouton drove tuning with a single number: `NotableReductionOnDeletion` — how many *notables* would vanish if a given rule were disabled. A rule that produced a mountain of notables that no analyst ever acted on was, by that measure, noise, and Mouton ranked those rules to the top as tune/disable candidates.

New-Scale Analytics has no notables and no histograms. It has **alerts → cases**. So NYMM keeps Mouton's *idea* and swaps the metric for the New-Scale analog:

> **A detection that fires constantly but rarely escalates to a case is noise.**

Volume with almost no escalation is the New-Scale stand-in for a high `NotableReductionOnDeletion` — the rule you would lose the least by turning down, and the most alert fatigue by keeping.

## What it ranks

NYMM pulls the tenant's alerts over the lookback window, groups them by alert/rule name, and ranks the drivers by volume. Each driver carries:

| Column | Meaning |
|---|---|
| Alerts | Volume — how many alerts this driver produced |
| % of all | That volume as a share of every alert in the window |
| Avg risk | Mean risk score across the driver's alerts |
| Escalation % | Share of the driver's alerts that became a case — the fidelity signal |
| Priority | The driver's most common alert priority |
| Rec | **Keep / Review / Tune-disable** |

The recommendation is mechanical, derived from the three signals above:

- **Tune / disable** — high volume (≥ 5% of all alerts) with almost no escalation (< 5%). This is the `NotableReductionOnDeletion` analog: lots of noise, almost none of it actionable.
- **Review** — noisy but not quite as stark (high volume, escalation still under 20%), or simply low value (avg risk < 40 and escalation < 10%).
- **Keep** — it escalates, or it carries high risk. Noisy-but-actionable stays.

Alongside the driver table, NYMM reports the **overall escalation rate** (what fraction of all alert volume became a case — how much of the noise is actually actionable) and the count of enabled rules.

Escalation-to-case is where this crosses into Threat Center: escalation is what `exa case qualify` and the case KPIs measure from the other side. See [threat-center.md](threat-center.md) for how cases and qualification work.

## Parameters

| Parameter | Default | Effect |
|---|---|---|
| `lookback_days` | 30 | Days of alerts to analyze |
| `top_n` | 20 | Number of top drivers to return |
| `render` | false | Also save a branded HTML report |

With `render=true` the report lands under `reports/<kind>/<tenant>/` (e.g. `reports/customer/<tenant>/tuning.html`) — the branded, self-contained NYMM tuning report with the escalation bar, stat cards, and the driver table.

## Read-only by design

NYMM **recommends, it never disables.** Every Keep/Review/Tune-disable verdict is mechanical output from the volume/escalation/risk signals — a starting point for a conversation, not an action. A TAM confirms each candidate against the account and the customer's risk appetite before anyone touches a rule. The skill leads by naming the active tenant and its kind (demo/customer) so the reader knows what they are looking at, and states plainly what it could not see rather than implying a complete tuning pass.

Two cross-checks keep NYMM honest, both wired into the `exa-nymm` skill:

- **Low escalation can mean an unworked queue, not a noisy rule.** Pair NYMM with `soc_kpis` — a 0% close rate with a backlog of unassigned cases changes the read entirely.
- **A rule with no data isn't noise, it's silent.** An enabled rule whose required fields never appear on this tenant will show zero escalation because it never fires at all. That's a "wire up the data or turn it off" problem, not a "turn it down" one — a different fix from a genuinely noisy driver. Check `parser_health` before blaming a rule.

## Scope — covers today vs. not yet

NYMM covers the *tuning* half of Mouton (its old `rules.csv`) — driver ranking, escalation fidelity, mechanical recommendations, and the branded report. The rest is roadmap or deliberately out of scope:

| Covers today | Not yet / by design |
|---|---|
| Alert-driver ranking by volume | Silent-rule detail (enabled-but-unreachable rules; today only the enabled *count* is reported) |
| Escalation-to-case fidelity per driver | Trend over time against a stored baseline |
| Keep / Review / Tune-disable recommendations | Rule-level aggregation (today it groups by alert name) |
| Branded HTML tuning report | Data-health rollup in the same view |

Two limits worth stating in any handoff:

- **New-Scale only.** NYMM does not query legacy Advanced Analytics — it is built on the alerts → cases model, which AA does not have.
- **Alerts are sampled at 5,000.** On a busy tenant the analysis marks itself truncated and the driver mix is a *lower bound* — say so rather than presenting it as a complete count.

[← README](../README.md)

# Threat Center

Search and triage Exabeam Threat Center cases and alerts from the terminal, qualify a single case into a structured verdict, and calibrate those verdicts against your tenant's own resolved history.

[← README](../README.md)

---

Two command families cover Threat Center:

- **`exa cases` / `exa alerts`** — the raw search / get / update surface over Threat Center objects.
- **`exa case`** — analyst tooling on top of a single case: `qualify`, `outcome`, `baseline`, plus helpers (`show`, `search`, `events`, `history`).

Every command takes `--tenant <name>` and `--help`.

## Cases and alerts

Cases and alerts are different objects. **Cases** have a stage, queue, and assignee and move through a workflow; **alerts** have none of those — you promote an alert to a case in the UI. Both are searched with the same SQL-style EQL filters (see [`exa search`](#event-search) below).

```bash
exa cases list                                        # recent open cases, last 30 days
exa cases list --filter 'NOT stage:"CLOSED"' --limit 25
exa cases list --filter 'priority:"HIGH"' --lookback 7
exa cases list --json                                 # raw JSON for pipeline use
exa cases list --output cases.json                    # write JSON to file

exa cases get <case-uuid>
exa cases get <case-uuid> --json

exa cases update <case-uuid> --stage "IN PROGRESS" --assignee analyst@example.com
exa cases update <case-uuid> --stage CLOSED --closed-reason "False Positive"
exa cases update <case-uuid> --priority CRITICAL --tags "reviewed,escalated"
```

```bash
exa alerts list --filter 'priority:"CRITICAL"' --lookback 1
exa alerts get <alert-uuid>
exa alerts update <alert-uuid> --priority LOW --tags "noise"
```

Notes that bite:

- **Closing a case requires `--closed-reason`.** A `--stage CLOSED` with no reason is rejected.
- **`--tags` replaces, it does not append.** The value is the complete tag list; every existing tag is removed first.
- Valid stages: `OPEN`, `IN PROGRESS`, `CLOSED`. Valid priorities: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- Alerts accept only `--name`, `--description`, `--priority`, and `--tags` — no stage, queue, or assignee.

## `exa case qualify` — structured triage

`qualify` answers one question for a single case: *is this worth an analyst's time right now?* It pulls together the evidence an analyst would gather by hand, then issues a verdict.

```bash
exa case qualify 221
exa case qualify 221 --lookback 14 --window 60    # 14-day prior-case search, ±60-min event window
exa case qualify 221 --json                        # machine-readable QualificationReport
```

### What it pulls

The verdict is driven by **rule structure**, **entity context**, and **score trend relative to the entity's own history** — never a hardcoded score threshold.

| Signal | Source | Role in the verdict |
|---|---|---|
| Triggering correlation rule | `/correlation-rules/v2/rules` | Is it a **first-seen** rule (one event is enough) or a **threshold** rule (volume-dependent)? Plus its `groupBy` fields and EQL. |
| Entity case history | prior cases for the same user/host over `--lookback` days | First appearance, or a recurring actor? How many prior cases, and their scores. |
| Score trend | current score vs the entity's own prior scores | Classified `first_appearance`, `escalating`, `consistent`, or `spike` — and whether the current score is a new high. |
| Context-table membership | `Compliance -*` context tables | Entity in a known-good compliance table is evidence *against* an incident. |
| External IP annotation | events ±`--window` minutes around the trigger | **Display only** — IPs are labelled for the analyst; they do not influence the verdict. |

### The four verdicts

| Verdict | When it fires | Recommended action |
|---|---|---|
| `SUSPECTED_INCIDENT` | First-seen rule, entity in **no** compliance context table, and either its first appearance or an escalating score trend. | Do **not** tune the rule — escalate for investigation. |
| `LIKELY_FP` | Entity is in a compliance context table **and** the score is not a new high; **or** the rule carries a >75% historical FP rate (from calibration) and the score is not a new high. | Consider allowlisting the entity or narrowing the rule scope. |
| `LEARNING_PHASE_NOISE` | Threshold rule with a consistent score across 3+ prior cases — a chronic baseline offender, not an escalation. | Monitor ~2 weeks; tune the threshold if the pattern persists. |
| `NEEDS_INVESTIGATION` | The signals don't line up cleanly enough for any of the above. | Review event context manually; escalate if unsure. |

The >75% FP rate that feeds `LIKELY_FP` comes from the calibration cache that [`exa case baseline`](#exa-case-baseline--historical-calibration) writes — so the more outcomes you record, the sharper this verdict gets.

Supporting helpers on the same case object:

```bash
exa case show 221          # details + Nova AI threat summary
exa case events 221        # event context ±window minutes around the trigger
exa case history <entity>  # every prior case for a user or hostname
```

## `exa case outcome` — closing the loop

Every `qualify` run is logged automatically to the local outcomes log (`~/.exa/`). Recording what actually happened turns those logs into calibration data.

```bash
exa case outcome list                              # every logged qualification + its current outcome
exa case outcome list --json
exa case outcome sync                              # back-fill outcomes for closed cases from Threat Center
exa case outcome resolve 221 --outcome fp          # manually record an outcome
exa case outcome resolve 221 --outcome tp --closed-reason "Confirmed attack"
```

Valid outcomes: `tp | fp | noise | duplicate | unknown`.

`sync` fetches recently closed cases and fills in the outcome on any matching logged record that lacks one — keeping the log current without a manual `resolve` for every case. `resolve` is the manual override for cases the API can't classify for you.

## `exa case baseline` — historical calibration

`baseline` reads closed cases plus the outcomes log, computes per-rule and per-entity false-positive rates, and writes the calibration cache (`~/.exa/cache/rule_fp_rates.json`, `entity_fp_rates.json`) that `qualify` reads on its next run.

```bash
exa case baseline                 # default 90-day lookback, LTS-capped; prints the calibration report
exa case baseline --lookback 180
exa case baseline --json
```

The rendered report is a table of `rule | TP | FP | FP rate` plus per-verdict accuracy — how often each verdict the tool issued matched the recorded outcome.

### LTS-retention capping

The lookback is **capped to the tenant's licensed LTS retention window** — queried live from the consumption endpoint (`/health-consumption/v1/consumption/lts`), not a hardcoded ceiling. Ask for `--lookback 180` on a tenant licensed for 90 days of retention and the run silently uses 90; the report records both the requested and the used window. If the consumption endpoint is unavailable, `baseline` warns and proceeds with the requested lookback rather than failing.

This keeps the calibration honest: it never claims to have looked further back than the data actually goes.

## <a id="event-search"></a>`exa search` — EQL event search

The direct event-query interface underneath the case and alert filters.

```bash
exa search 'activity_type:"authentication"' --lookback 7 --limit 500
exa search 'user:"jsmith"' --tenant <tenant>
exa search 'outcome:"fail"' --count --lookback 7               # matched-event count only
exa search 'activity_type:"authentication"' --unique user     # value-frequency table for one field
exa search 'parsed:"No"' --fields parsed,m_collector_name,error_detail
exa search 'user:"jsmith"' --json | jq .
exa search 'activity_type:"authentication"' --csv auth.csv --lookback 30
```

> **Exabeam New-Scale EQL is SQL-style** — `SELECT` / `WHERE` / `GROUP-BY` / `ORDER-BY`. The pipe-based syntax from Splunk SPL is **not supported**. The same filter grammar applies to `--filter` on `exa cases list` and `exa alerts list`.

The default result limit varies by output mode (table `100`, `--unique`/`--count`/`--csv` `10000`, `--json` `100`); `--fields` is ignored when `--unique` is set.

## See also

- [Compliance](compliance.md) — the `Compliance -*` context tables that drive the `LIKELY_FP` verdict.
- [NYMM](nymm.md) — fleet-wide detection tuning, for when `qualify` keeps returning `LEARNING_PHASE_NOISE` on the same rule.
- [Configuration](configuration.md) — tenant setup and `exa tables` context-table CRUD.

[← README](../README.md)

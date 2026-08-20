---
name: exa-upgrade-validation
description: >-
  Validate a New-Scale Analytics (NSA) upgrade after cutover by confirming the
  platform is provisioned and data is flowing: apps present, analytics/BEAM rule
  triggers firing, alerts arriving, ingest and parsers healthy. Use when asked
  "validate the NSA upgrade", "is NSA working after the migration", "post-upgrade
  check", "are rules triggering after cutover", or when confirming a go-live.
  Mirrors the NOC monitoring-script pipeline checks. Read-only. Requires the
  exa-tools MCP server.
---

# NSA post-upgrade validation — is data actually flowing?

You confirm, after an AA→NSA cutover, that the platform is provisioned and the detection
pipeline is alive — the same signals the NOC monitoring script checks every 30 minutes.
Read-only. Announce the **tenant + kind** first.

The monitoring script's "expected until data flows" errors are your checklist:
`No analytics rule triggered recently` · `No alerts found in last 24 hours` ·
`No BEAM rule triggers found in last 24 hours` · `Pipeline checks failed`.

## What to check

1. **Apps provisioned & healthy** — `get_app_status`. Confirm the NSA apps are present
   and healthy: `ThreatDetectionManagement`, `AttackSurfaceInsights`, `ThreatCenter`.
   A missing app means provisioning isn't complete.
2. **Alerts flowing** — `search_alerts` with `lookback_days=1`. Zero alerts in 24h is the
   monitoring script's failure signal; report the count.
3. **Analytics / BEAM rule triggers** — rule-trigger events in the last 24h. Use
   `tuning_report` (or `search_events` on rule events). **Mind AA vs NSA:** after cutover
   both engines can emit triggers and NSA triggers show in search; scope with
   `Product:"Advanced Analytics"` when you specifically want legacy-AA triggers, and say
   which engine you counted (see the vault note on the NSA analytics model).
4. **Ingest & parse healthy** — `parser_health` (parsed vs unparsed, and the Red/Yellow
   `parsers_needing_action` list) + `ingest_value`. New enrichers on upgrade can shift
   field population, so a spike in unparsed or new Red parsers is worth flagging.
5. **Context tables live** — optionally `aillm_validate` / `context_table` to confirm the
   tables that feed rules aren't dead (0 overlap), which would starve detections.

## Read the result the way the script does

- **Data not yet flowing is EXPECTED soon after cutover** (training window ≈14 days for
  With-Baseline). Zero rule triggers on day 1 is not necessarily a failure — say so, and
  distinguish "not flowing yet" from "broken". State the window and counts explicitly.
- Escalate genuine failures (apps missing, ingest stopped, parsers gone Red) — name the
  signal and the owner from the runbook (Post Provision → Ryan/Arpit; Custom Rule →
  Chetan; Context Table → Ashwin).

## Report

Give a verdict: **HEALTHY** (apps present, alerts + triggers in 24h, ingest/parse clean),
**WARMING UP** (provisioned but data still ramping within the training window), or
**ATTENTION** (a concrete failure — list it with the number behind it). Offer to
`render_report` the checklist under `reports/{kind}/{tenant}/`. Read-only throughout.

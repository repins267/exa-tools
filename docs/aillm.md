# AI/LLM

Sync and monitor the six AI/LLM shadow-AI detection context tables on an Exabeam New-Scale tenant, then enrich them from the tenant's own logs.

[← README](../README.md)

Reference data is sourced from [ai-llm-domains](https://github.com/repins267/ai-llm-domains) — a maintained dataset of 223+ domains, 90+ applications, proxy categories, and DLP alert patterns. Run `exa update` to pull the latest data before syncing. Every command takes `--tenant <name>`.

> To make the OOTB AI/LLM dashboards work in *any* tenant — deriving which table + field each dashboard and rule needs live, then closing the gap from what the tenant actually emits — see [`exa assess` and the OOTB validation workflow](validation.md).

## The six context tables

Exabeam's OOTB AI/LLM dashboards and analytics rules filter against six context tables. Empty, they render as absence everywhere — no panel populates and no rule matches. `exa aillm sync` fills them from the bundled reference dataset.

| Table | Key | Records | Content |
|---|---|---|---|
| Public AI Domains and Risk | `aillm_domain` | 223 | Domains with Low/Medium/High risk rating |
| AI/LLM Web Domains | `key` | 223 | Domain-only list for web filtering |
| AI/LLM Applications | `key` | 90 | Application names for log matching |
| AI/LLM Proxy Categories | `key` | 9 | Vendor proxy/URL filter category names |
| AI/LLM Web Categories | `key` | 9 | Web category names |
| AI/LLM DLP Rulesets | `key` | 46 | DLP alert/policy names indicating AI data transfer |

## Sync

```bash
# Sync all 6 tables from bundled reference data
exa aillm sync                                            # append mode
exa aillm sync --force                                    # full replace
exa aillm sync --dry-run                                  # preview without writing
exa aillm sync --tenant acme-demo                         # specific tenant
```

`--force` replaces existing records instead of appending; `--dry-run` shows what would change without writing to Exabeam. Sync is the one write path most demos start with — pair it with [`status`](#status) to confirm the counts landed.

### Discover from logs

Sync ships a fixed reference set, but a tenant reaches AI domains the dataset never listed. `--discover-from-logs` queries the tenant's proxy/web logs and adds the AI domains actually seen there to the domain tables.

```bash
# Augment domain tables with AI domains seen in your proxy/web logs
exa aillm sync --discover-from-logs
exa aillm sync --discover-from-logs --lookback 60 --tenant acme-demo
```

`--lookback` (default 30 days) sets how far back the log query reaches.

### Per-tenant risk overrides

The bundled dataset assigns each domain a Low/Medium/High rating. When a tenant's policy disagrees — a domain they sanction, or one they treat as more dangerous than the default — pass a JSON map of `domain → risk level` and sync applies it to matching domains before writing.

```bash
# Create a JSON file mapping domain -> risk level
echo '{"all-hands.dev": "medium", "deepseek.com": "critical"}' > overrides.json
exa aillm sync --risk-override overrides.json --tenant acme-demo
```

## Domain categories and risk

The 223 domains break down by category and risk tier as follows.

| Category | Domains | High | Medium | Low |
|---|---|---|---|---|
| Generative AI | 33 | 12 | 21 | 0 |
| AI Platform/API | 75 | 3 | 52 | 20 |
| Code Assistant | 30 | 0 | 6 | 24 |
| Shadow AI | 21 | 11 | 10 | 0 |
| Image Generation | 19 | 4 | 14 | 1 |
| AI Search | 11 | 0 | 9 | 2 |
| AI Productivity | 11 | 0 | 11 | 0 |
| Video AI | 13 | 1 | 12 | 0 |
| Voice/Audio AI | 10 | 0 | 10 | 0 |

**High-risk rationales.** A High rating carries a stated reason rather than a bare score:

- **China data jurisdiction** — DeepSeek, Qwen, Doubao, Kimi, ERNIE, Kling AI
- **Autonomous execution / OS-level access** — OpenHands, AutoGPT, Open Interpreter, OpenClaw
- **No enterprise controls** — Character.AI, CivitAI
- **Unauthorized forks / impersonators** — zeroclaw.org, zeroclaw.net (included for detection)

See the [ai-llm-domains README](https://github.com/repins267/ai-llm-domains) for the full rationale table.

**Exclusions applied at load time** — present in the reference data but deliberately not synced to tables:

- IPv4 address entries — not valid as domain table keys
- 12 DLP IOC entries (Threat Campaign IOC, Supply Chain IOC, Network IOC vendors) — threat indicators, not DLP policy names

## Feeding the DLP dashboard: `sync-ruleset`

The `AI/LLM DLP Rulesets` table exists to drive the Looker/BigQuery AI/LLM dashboard tiles, which filter `alert_name` against it. The bundled reference data seeds it with generic vendor DLP pattern names — but those are not the strings a given tenant's rules actually emit, so the tiles stay empty.

`sync-ruleset` fixes that. It pulls real alert names from the tenant's Threat Center, filters for AI/LLM-related names, and writes the exact strings this tenant fires. Run it once per tenant, after the AI/LLM correlation rules have been active long enough to generate alerts.

```bash
# Sync 'AI/LLM DLP Rulesets' from real alert names in Threat Center
exa aillm sync-ruleset --tenant acme-demo
exa aillm sync-ruleset --dry-run --tenant acme-demo       # preview matches
exa aillm sync-ruleset --lookback 180 --tenant acme-demo  # longer window
```

`--lookback` defaults to 90 days; `--keywords` overrides the built-in AI/LLM keyword filter with a comma-separated list; `--limit` (default 3000) caps how many alerts are pulled; `--force` replaces all existing records instead of appending.

## Discover

`discover` is the read-first companion to sync's enrichment. It runs two passes and reports new candidates without writing unless you ask it to.

- **Pass 1 — Threat Center alert names (all tenants).** Pulls recent alerts, filters for AI/LLM keywords, and lists names not yet in the DLP Rulesets table. Add `--add-rulesets` to write them.
- **Pass 2 — AI proxy/agent app names (requires SentinelOne Prompt Security or similar).** Queries for AI proxy/agent events and extracts distinct application names actively seen in this environment. Add `--add-apps` to write new names to the Applications table.

```bash
# Discover AI activity candidates for enriching context tables
exa aillm discover --tenant acme-demo                     # report only
exa aillm discover --lookback 60 --tenant acme-demo
exa aillm discover --add-rulesets --tenant acme-demo      # write alert names
exa aillm discover --add-apps --tenant acme-demo          # write app names
exa aillm discover --json --tenant acme-demo              # structured output
```

For web *domain* discovery use `exa aillm sync --discover-from-logs` instead — that path augments the domain tables, `discover` handles alert names and app names.

## Status

```bash
# Show live record counts for all 6 tables
exa aillm status
exa aillm status --tenant acme-demo
```

Fetches current record counts from Exabeam and prints a status table. A table showing `-` has not been synced yet — run `exa aillm sync` to populate it.

## Report

`report` is read-only. It writes an HTML report plus a state snapshot under `~/.exa/aillm-reports/<tenant>/` so the next run can show movement, and covers three things:

- **STATE** — what the tables hold and whether the dashboards are fed
- **CHANGES** — record-count movement since the last snapshot
- **DRIFT** — values this tenant emits that neither the tables nor the shipped reference data know about

Drift is narrower than a gap. A gap is anything missing from a table; drift is missing from the table *and* unknown to the reference data — new to us, not merely not yet applied. Nothing filters on it and no rule matches it, so it renders as absence everywhere and has to be asked for by name. On a first run there is no baseline, and the report says so rather than showing an empty change list that reads as "nothing changed".

```bash
# Report AI/LLM state, what changed since last run, and what is drifting
exa aillm report --tenant acme-demo
exa aillm report --format html --out reports/customer/<tenant>/aillm.html   # html | pdf | json | csv
exa aillm report --no-drift                               # skip gap collection; much faster
exa aillm report --refresh                                # re-collect the tenant profile instead of today's cache
```

`--save-baseline` is on by default (stores this run for the next run's change detection); `--json` emits JSON to stdout.

## Cycle — stability gate

`cycle` runs the `populate → audit → rollback` loop N times as a stability gate. Each iteration snapshots the six tables, optionally clears them, runs sync to populate, audits the Landscape dashboard (no panel skipped) and the tables (no rule-backed table left DEAD), confirms live data via a search, then rolls back to the snapshot and verifies every table returned to its exact baseline. The rollback runs even if a middle step fails, so an aborted iteration never leaves the tenant dirty.

It **writes** to the tenant (sync + rollback each iteration), so it needs `--confirm`; without it, `cycle` prints the plan and exits. It writes a findings JSON and exits non-zero if any iteration fails.

```bash
# Stability gate: run the populate -> audit -> rollback cycle N times
exa aillm cycle --dry-run --tenant acme-demo              # no writes, audit path only
exa aillm cycle --iterations 15 --confirm --tenant acme-demo
exa aillm cycle --from-empty --iterations 5 --confirm     # clear tables first each run
```

`--from-empty` clears the tables after the snapshot so sync populates from empty, exercising the demo arc; `--confirm-filter` sets the EQL the confirm-search step must return rows for (default `web_domain:"chatgpt.com"`); `--slow-seconds` (default 45) flags an iteration slow.

## Read-only companions

Beyond the sync/report workflow, `exa aillm` also carries read-only inspection commands — `validate` (do the tables match what the tenant emits?), `rules` (which AI analytics rules can fire against this data?), `risk` (risk tiers of AI domains this tenant actually reaches), `sources` (vendors/products/collectors feeding the tenant), `gaps` (what the tenant emits that the tables don't hold), `watch` (every configured tenant in one pass), and `dashboard` (generate the AI/LLM Landscape dashboard). Plus `snapshot` / `rollback` for manual table capture and restore. Run any with `--help` for flags.

---

See also: [configuration](configuration.md) for `exa tables` and context-table basics.

[← README](../README.md)


# exa-tools Deep Dive — what every capability does, where its data comes from, how to verify it

For senior TAMs validating what Claude/exa-tools reports. Companion notes:
exa-mcp-integration, exabeam-dashboards, nsa-analytics-model,
nsa-upgrade-validation. Repo: repins267/exa-tools · endpoints & filters
ground-truthed from source on 2026-08-20.

> Confluence/Notion note: this is plain Markdown. The only Obsidian-specific syntax is
> the `wiki links` above — strip or convert those when pasting into Confluence.

## Read this first — the trust model

You did not write this code and you know the API. This page exists so you can check
exa-tools the way you'd check a junior analyst: *what did it query, and does the number
match the raw API.* Four principles govern the whole toolkit:

1. **Reads are faithful passthroughs.** exa-tools is a **lens on the New-Scale API**, not
   a new detection engine. A read tool sends a documented request to a documented
   endpoint and reports what came back. It does not enrich, reweight, or invent. Every
   tool below lists its exact endpoint + query so you can reproduce it.
2. **Where exa-tools does its own math, it is labelled.** Some tools *derive* metrics
   (unparsed %, % of ingest, MTTR, Keep/Review/Trim, parser Red/Yellow/Green, NYMM
   tune/disable ranking, table overlap). Those are **exa-tools interpretation, not raw API
   truth** — each is documented with its formula and its thresholds so you can argue with
   the method, not just the number.
3. **Renders never alter numbers.** The HTML/report layer HTML-escapes values and inserts
   them verbatim — it does no arithmetic. A wrong input renders as a clean, branded, wrong
   number, never an invented one. (The one exception: `render_dashboard`'s live "SAMPLE"
   counts, which are freshly queried and labelled as illustrative.)
4. **Read-only by default; writes are gated + confirmed.** The four write tools are hidden
   and refused unless the server runs `--allow-writes`, and Claude still asks in-prompt
   before writing. You cannot accidentally mutate a tenant through a report.

### The accuracy gotchas an AA veteran should know (these bite)

- **AA vs NSA double-counting.** After an NSA cutover both engines can emit rule triggers
  and NSA triggers appear in search. A rule-trigger count that doesn't scope
  `Product:"Advanced Analytics"` can double. If a number looks 2× high, check product scope.
- **`groupBy` returns DISTINCT values, not counts.** The Search API's groupBy gives
  distinct combinations; a per-group **count** requires the aggregate `count(id)` (NOT
  `count()`, a 400) and comes back under key `f0_`. Every counted-by-group number in
  exa-tools uses `count(id)`; a hand-run groupBy without it will look empty by comparison.
- **Date-stamped AI/LLM profile cache.** The tenant field-profile the AI/LLM tools build is
  cached per calendar day at `~/.exa/cache/aillm-profile-{tenant}-{YYYYMMDD}.json`; the
  first AI/LLM call each day rebuilds it. **Measured on sademodev22 (2026-08-20): 38.9s
  cold → ~5.6s warm.** The server warms it in the background on start. A number is only as
  fresh as today's profile.
- **Data-sparse tenants read as "broken".** On a quiet tenant (sademodev22 had ~12
  events/day on 2026-08-20) volume/geo/rule outputs are legitimately near-empty. Empty ≠
  failed — the tools state the window and row count so you can tell.
- **Result caps & truncation flags.** MCP results are capped (~800 KB); large scans page
  under a time budget. Tools set `truncated`/`sampled`/`partial_scan` when they didn't see
  everything — **when that flag is set, the number is a floor, not a total, and "none found"
  is not authoritative.**
- **The Search API returns ONLY requested fields.** An unrequested field is absent and
  indistinguishable from null — a documented false "0% populated" hazard. Tools request the
  fields they read; you should too when reproducing.
- **Auth/timeout.** OAuth client-credentials against `/auth/v1/token` (tokens ~4h,
  auto-refreshed), 30s per-request HTTP timeout, HTTPS-only.

## Architecture in one paragraph

`ExaClient` authenticates once (OAuth client-credentials → `/auth/v1/token`), holds the
region base URL, and issues authenticated HTTPS calls. The MCP server (`exa mcp serve`)
exposes 33 tools over stdio (what Claude Desktop spawns) or SSE (local dev). The same
functions back the ~81-command `exa` CLI. Secrets live only in the OS credential store; a
tenant switch is a nickname lookup — no secret ever reaches Claude.

---

## MCP tools — provenance (endpoint · query · computation · limits · how to verify)

### Search, cases & alerts (5 read + 4 write)

#### search_alerts
- **Endpoint(s):** `POST /threat-center/v1/search/alerts` (via `exa.case.alerts.search_alerts`).
- **Query / params:** MCP passes `filter` (or None), `lookback_days=7`, `limit=50`. Body: `fields=["*"]`, `limit=50`, `orderBy=["riskScore DESC"]`, `startTime`/`endTime`=now-7d..now (`%Y-%m-%dT%H:%M:%SZ`), `filter`=passed filter or `""` (key always present — some tenants 400 if absent).
- **Computation:** Passthrough of `response.rows`. No aggregation; `totalRows` not returned.
- **Limits:** MCP defaults differ from library (dispatch forces 7d/50; library 30d/500; server max ~3000). `fields=["*"]` and `orderBy` not overridable via MCP. Empty filter → all in-window alerts by risk, truncated to 50.
- **Verify:** `POST /threat-center/v1/search/alerts` with `{"fields":["*"],"limit":50,"orderBy":["riskScore DESC"],"startTime":"<now-7d>","endTime":"<now>","filter":"<your filter or empty>"}`, count `rows`.

#### get_alert
- **Endpoint(s):** `POST /threat-center/v1/search/alerts` (reuses search, NOT a `GET /alerts/{id}` detail endpoint).
- **Query / params:** `filter='alertId:"{id}"'`, `lookback_days=90`, `limit=1`.
- **Computation:** Returns `rows[0]` or `_err("Alert {id} not found")`.
- **Limits:** An alert older than 90 days won't be found. Result is the search projection, not necessarily the dedicated detail endpoint.
- **Verify:** same endpoint, `limit=1`, `filter='alertId:"<id>"'`, 90-day window.

#### search_cases
- **Endpoint(s):** `POST /threat-center/v1/search/cases`.
- **Query / params:** `filter` (or None), `lookback_days=7`, `limit=50`. Body: `fields=["*"]`, `orderBy=["caseCreationTimestamp DESC"]`, now-7d..now.
- **Computation:** Passthrough of `response.rows`.
- **Limits:** Dispatch forces 7d/50 (library 30/500; server max ~3000). Filters on the creation window — a long-open case created before the window is excluded.
- **Verify:** same endpoint with the body above; count `rows`.

#### get_case
- **Endpoint(s):** `GET /threat-center/v1/cases/{case_id}`.
- **Query / params:** path `case_id` only.
- **Computation:** Passthrough — raw API dict unchanged.
- **Limits:** No lookback/limit. Bad ID surfaces the raw API error.
- **Verify:** `GET /threat-center/v1/cases/<case_id>`.

#### search_events
- **Endpoint(s):** `POST /search/v2/events`.
- **Query / params:** `filter` (required), `fields`, `group_by`, `lookback_days=1`, `limit=100`. Body: `limit=100`, `distinct=false`, **EQL sent in BOTH `query` and `filter`**, now-1d..now (`%Y-%m-%dT%H:%M:%S.000Z`), `fields=<computed>`, plus `groupBy`/`orderBy` when given. Non-group_by queries auto-append CIM fields parsed from the EQL plus `approxLogTime`; group_by queries do NOT (would 400).
- **Computation:** Returns `response.rows`; only post-processing is converting `approxLogTime` (µs) to an ISO `timestamp`. Aggregation is server-side.
- **Limits:** API returns only requested fields (false-null hazard). EQL in both keys is deliberate (some tenants ignore `query`); `filter` never empty (400). MCP default window 1 day / limit 100 (library 24h/10000, max 1e6).
- **Verify:** `POST /search/v2/events` with `{"limit":100,"distinct":false,"query":"<EQL>","filter":"<EQL>","startTime":"<now-1d>.000Z","endTime":"<now>.000Z","fields":[...],"groupBy":[...]?}` — include the same fields list to match rows.

#### create_case ✱ (write)
- **Endpoint(s):** `POST /threat-center/v2/cases`, fallback to `v1` only on 404/405/501.
- **Query / params:** `alert_id`, `priority="MEDIUM"` default, optional `queue`/`assignee` (dispatch does NOT forward `stage`/`closed_reason`). Free-text passed through `neutralize_write_args` (formula-quote, link defang, secret redact).
- **Computation:** Passthrough of the created-case dict.
- **Limits:** Blocked unless `--allow-writes`. Default MEDIUM injected. v2 UNVERIFIED live; v1 was slated for removal 2026-04-15. Fallback deliberately NOT on 500 (avoid duplicate case). Guardrail may alter strings.
- **Verify:** `POST /threat-center/v2/cases` `{"alertId":"<id>","priority":"MEDIUM"}` (+queue/assignee); on 404/405/501 try v1.

#### update_case ✱ (write)
- **Endpoint(s):** `POST /threat-center/v2/cases/{id}`, fallback v1 on 404/405/501.
- **Query / params:** forwards `stage`, `priority`, `assignee`, `queue`, `tags`, `closed_reason` (non-None only), mapped stage→`stage`, closed_reason→`closedReason`, etc. Free-text neutralized first.
- **Computation:** Passthrough of updated-case dict.
- **Limits:** `--allow-writes`; partial update; same v2-unproven / v1-deprecated / no-retry-on-500 caveats.
- **Verify:** `POST /threat-center/v2/cases/<id>` with only the fields you set; fallback v1.

#### update_alert ✱ (write)
- **Endpoint(s):** `POST /threat-center/v1/alerts/{id}` (no v2 fallback).
- **Query / params:** `priority`, `tags` (non-None only); neutralized first.
- **Computation:** Passthrough.
- **Limits:** `--allow-writes`; partial update; guardrail may alter tag/string values.
- **Verify:** `POST /threat-center/v1/alerts/<id>` `{"priority":"HIGH"}` and/or `{"tags":[...]}`.

#### add_case_note ✱ (write)
- **Endpoint(s):** `POST /threat-center/v1/cases/{id}/notes` — inline in dispatch, marked `EXA-CASENOTES-UNVERIFIED` (endpoint not confirmed live).
- **Query / params:** body `{"content": <content>}`; `content` neutralized first.
- **Computation:** Passthrough; any exception → `_err(... EXA-CASENOTES-UNVERIFIED ...)`.
- **Limits:** `--allow-writes`; UNVERIFIED — a failure may mean the endpoint doesn't exist. Guardrail can rewrite the note.
- **Verify:** `POST /threat-center/v1/cases/<id>/notes` `{"content":"..."}` and confirm the endpoint exists on the tenant.

### Detection (1)

#### list_detection_rules
- **Endpoint(s):** `GET /detection-management/v1/analytics-rules` (verified live sademodev22 2026-05-08).
- **Query / params:** No API params — returns ALL rules; `name`/`status`/`limit` applied CLIENT-SIDE (name=case-insensitive substring; status vs `isEnabled` bool; limit=post-filter slice).
- **Computation:** Each rule projected to a slim dict: `name`, `isEnabled`, `severity`, `type`, `activity_types` (union of `applicableEvents[].activity_type`), `required_fields`, `families`, `mitre` (techniqueKeys). Full config dropped.
- **Limits:** Filtering entirely client-side; raw list ~500 KB (hence the projection). `id`, `description`, `author`, timestamps present in raw API but not in the slim output.
- **Verify:** `GET /detection-management/v1/analytics-rules`, filter `rules` yourself, count.

### Tenant (4) — all local, no tenant API

#### get_active_tenant
- **Endpoint(s):** None. Builds from in-process client attrs + local `~/.exa/config.json`.
- **Computation:** `active_tenant`, `api_server`, `region`/`fqdn`/`kind`, `writes_enabled`=`not read_only`, `token_ttl_seconds`=`max(0, expires_at-now)` or null.
- **Limits:** Reflects server session + on-disk config, not a live query.
- **Verify:** inspect `~/.exa/config.json`; the rest is session state.

#### list_tenants
- **Endpoint(s):** None — local `~/.exa/config.json`.
- **Computation:** per tenant: nickname, fqdn (synthesized if absent), region, api_server, kind, `active`, `default`.
- **Limits:** Local only; never returns secrets (they're in the OS credential store).
- **Verify:** read `~/.exa/config.json`.

#### set_active_tenant
- **Endpoint(s):** None to a tenant for the switch; `session.switch()` re-auths, best-effort `set_default_tenant` writes config.
- **Limits:** Only inside the running server (needs a session). Not gated by `--allow-writes` (config change). Persist failure → in-memory only, may revert on restart.
- **Verify:** call `get_active_tenant` after, and/or inspect `default_tenant` in config.

#### set_tenant_kind
- **Endpoint(s):** None — local config write.
- **Query / params:** `tenant` (defaults to active), `kind` ∈ {demo, customer}.
- **Limits:** Local metadata; invalid kind/unknown tenant → `_err`. Not gated by `--allow-writes`. This `kind` is what the guardrail and reports read to distinguish demo vs customer.
- **Verify:** inspect the tenant's `kind` in `~/.exa/config.json`.

### Health & ingest (6)

#### get_license_consumption
- **Endpoint(s):** `GET /health-consumption/v2/consumption/licenseDetails` (camelCase v2; the kebab path 404s).
- **Query / params:** none.
- **Computation:** Raw API JSON verbatim. Payload carries `entitledIngestGbPerDay`, `consumedIngestGbForToday`, `historicalLogIngestionInGb[]`.
- **Limits:** Over-entitlement is NOT flagged by the API or this tool — you compare consumed/history vs entitled yourself.
- **Verify:** `GET .../health-consumption/v2/consumption/licenseDetails` — returned unmodified.

#### get_app_status
- **Endpoint(s):** `GET /health-consumption/v1/health/appStatus`.
- **Query / params:** none.
- **Computation:** Returns the list as-is (or `resp["items"]`). One row per app per day: `uptimeValue`, `majorOutageInSeconds`, `partialOutageInSeconds`. No aggregation.
- **Limits:** Only heuristic is the list vs `{items:[]}` shape fallback (yields `[]` silently if wrapped differently).
- **Verify:** `GET .../health-consumption/v1/health/appStatus`, compare row-for-row.

#### list_collectors
- **Endpoint(s):** `GET /cloud-collectors/v1/configs` (called directly, no helper).
- **Computation:** Raw response verbatim; no staleness/filtering here (the health-check skill reasons about staleness elsewhere).
- **Verify:** `GET .../cloud-collectors/v1/configs` — byte-identical to the payload.

#### parser_health
- **Endpoint(s):** `POST /search/v2/events` only (two calls). No REST/consumption endpoints.
- **Query / params:** (1) parsed/unparsed: `filter=""`, `fields=["parsed","count(id)"]`, `group_by=["parsed"]`, 7d, limit 100. (2) errors: `filter="NOT error_detail:null"`, `fields=["error_detail","msg_type","src_vendor"]`, 7d, `limit=error_limit` (5000). Counts read from `f0_`.
- **Computation:** `unparsed_pct = round(100·unparsed/(parsed+unparsed), 2)`. Errors bucketed into 6 categories by reason-code/keyword. **Red/Yellow/Green per source**: Red if any offending field ∈ `CORE_FIELDS` (identity/network/activity/time set), Yellow if errors only on non-core fields, Green if none. `parsers_needing_action` sorted Red-first then by error count.
- **Limits:** `truncated/sampled` when errors hit the 5000 cap — grades/counts then on a SAMPLE. **The grade is a TRANSPARENT TRIAGE approximation, NOT the DVE workbook's authoritative field taxonomy;** final TP/FP is a manual raw-log review. Treat as "which parsers to look at first."
- **Verify:** reproduce the two POSTs (7d, UTC); read `rows[].f0_`; `unparsed_pct=100·unparsed/total`. For a grade, JSON-parse each `error_detail`, extract offending fields, check membership in the CORE_FIELDS list.

#### ingest_value
- **Endpoint(s):** `POST /search/v2/events` ×2 + `GET /health-consumption/v2/consumption/licenseDetails` + the detection-rules endpoint.
- **Query / params:** (1) `fields=["vendor","product","parsed","count(id)"]`, group by same, 7d, limit 2000. (2) `fields=["vendor","product","activity_type","count(id)"]`, group by same, 7d, limit 4000. Plus license + enabled-rules' consumed activity_types. Counts from `f0_`.
- **Computation:** `pct_of_ingest = round(100·source.events/total, 2)`; per-source `unparsed_pct = round(100·unparsed/events, 1)`. `feeds_rules` = source activity_types ∩ any enabled rule's. **Keep/Review/Trim** (in order): unparsed≥50%→Trim; not-feeds-rules & pct≥1→Trim; not-feeds-rules→Review; pct≥20→Review; else Keep. License: `avg_gb`=mean of last-N history days; `days_over`=days ingest>entitled.
- **Limits:** 7d/top_n=15. `truncated/sampled` when volume query ≥2000 rows — total and all percentages then on a truncated set. The 4000-cap activity query is best-effort (silent on failure). **Keep/Review/Trim is explicitly mechanical** — thresholds (50/1/20) are heuristics; a compliance/hunting source can be flagged Trim. `feeds_rules` reflects ENABLED rules only.
- **Verify:** reproduce the volume POST; sum `f0_` per (vendor,product); `pct=100·events/Σ`; cross-check entitlement with the license GET; confirm rule overlap with the enabled rules list.

#### source_detail
- **Endpoint(s):** `POST /search/v2/events` up to ×4 (msg_type/action/activity_type/parsed) + detection-rules.
- **Query / params:** filter `vendor:"<v>"` (+` product:"<p>"`); per field: `fields=[field,"count(id)"]`, `group_by=[field]`, 7d, limit 200. Counts from `f0_`.
- **Computation:** top-15 per field. `total_events`=Σ activity_type counts (fallback msg_type). `unparsed_pct=round(100·unparsed/total,1)`. `feeding_rules`=enabled rules whose activity_types intersect; summary returns the count + up to 20 names.
- **Limits:** 7d/top 15/per-field limit 200 — a source with >200 distinct values is truncated, and because `total_events` sums the capped rows, the denominator can be understated (percentages relative to sampled top values). No `truncated` flag here. Verdict text is mechanical ("confirm against the account before trimming").
- **Verify:** run each grouped POST (e.g. `fields=["activity_type","count(id)"]`, group by it); sum `f0_`; unparsed=Σ where parsed=false; intersect activity_types with enabled rules.

### Identity & context (2)

#### identity_health
- **Endpoint(s):** `GET /context-management/v1/tables` + paged `GET /context-management/v1/tables/{id}/records` + `POST /search/v2/events` (login events for the GUID scan). No cached profile.
- **Query / params:** candidate tables = `contextType=="User"` or name contains user/entity/identity/link/account; read in 2000-row pages up to 25,000/table under a shared 40s budget; smallest first. GUID scan: `activity_type:"user-login"`, `group_by=["user",<host>]`, `count(id)`, 7d, limit 5000, trying host fields dest_host→host→src_host.
- **Computation:** **Merged entity** = using the table's real key attribute, invert every non-key attribute; any value mapping to **2+ distinct users** is a merge (values <3 chars skipped). **GUID ghost** = login user matching the 8-4-4-4-12 hex objectGUID regex, grouped by host with `f0_` count.
- **Limits:** `partial_scan` True when truncated by the 40s budget, the 25,000/table cap, or the 8-table cap — **and then "no merges" is NOT authoritative.** The GUID query raises rather than returning empty if all host fields fail (so a failure isn't misread as "clean"). Read-only — the fix is a separate gated step.
- **Verify:** in Context Management, look for any email/UPN/SAMAccountName on 2+ user rows (that's the merge); for GUID users, run the login group_by and filter usernames matching the hex pattern.

#### context_table
- **Endpoint(s):** `GET /context-management/v1/tables` + paged `GET .../{id}/records`. No events API, no profile.
- **Query / params:** no `table` arg → inventory (`id, name, type, records`). With `table` → case-insensitive name/id match, read up to `_cap=50,000` records, optional `contains=` substring filter, return `records[:limit]` (200) + `matched_records`.
- **Computation:** `matched_records`=rows after the filter; `truncated_scan` when ≥50,000. Inventory counts come straight from the table's `totalItems`/`recordCount`.
- **Limits:** Bounded to first 50,000 records — on a large table a `contains=` match can be missed (note tells you to narrow). Straight dump/filter — no overlap/health math (that's `aillm_validate`).
- **Verify:** open the same table in the UI; page the records endpoint with `limit`/`offset`.

### AI/LLM (6)

#### aillm_sources
- **Endpoint(s):** `POST /search/v2/events` (one group_by) + `GET /cloud-collectors/v1/configs`. Does NOT use the cached profile (runs its own aggregation so it can run first).
- **Query / params:** `fields=["vendor","product","activity_type"]`, group by same, empty filter, 7d, limit 5000. **Composite group_by returns distinct values with NO count** — presence only, never volume.
- **Computation:** folds rows into `(vendor,product)→set(activity_type)`; role from vendor-pack else activity-type regex; `ai_relevant` from AI activity types / role. Collectors matched by product token (never vendor alone). `missing_roles()` = proxy/dns/dlp/edr/agent with no non-internal source.
- **Limits:** `truncated` at the 5000 cap. Empty collectors → `collectors_available=False` treated as normal (Site Collector/syslog tenants). Reports *what exists*, never *how much*.
- **Verify:** reproduce the group_by; compare distinct vendor/product/activity_type tuples; cross-check `GET /cloud-collectors/v1/configs`.

#### aillm_validate
- **Endpoint(s):** `GET /context-management/v1/tables` + `/records` (per table) + the **cached tenant profile** (built via `POST /search/v2/events` group_by on a cold cache).
- **Query / params:** 8 `TABLE_SPECS`, each mapped to live field(s) (e.g. Web Domains→`web_domain`, DLP Rulesets→`alert_name`). Profile enumerates a fixed set via 6 composite group_by calls + 3 batch probes, 30d, limit 5000, **cached date-stamped daily**; same-day call costs 0 API calls.
- **Computation:** `overlap = |table_keys ∩ live_values|` (+ registered-domain suffix matches for domain tables). Status: EMPTY (0 records), UNKNOWN (no table / 0 live values), DEAD (overlap 0), WEAK (overlap/records < 0.20), else OK. **Record count is deliberately NOT the health signal** — a 46-record table with 0 overlap is DEAD.
- **Limits:** Cold profile build cost (measured 38.9s on sademodev22). `truncated_sample` (any field hit the 5000 cap) → overlap is a **LOWER BOUND**. `ensure_fields` runs here so the verdict is order-independent. Live values = ≤30-day ≤5000-value sample.
- **Verify:** in Context Management compare each table's keys vs live event field values over the same lookback — the overlap you see by hand is `|table ∩ live|/records`.

#### aillm_rules
- **Endpoint(s):** `GET /detection-management/v1/analytics-rules` + the **cached profile**. **Fails fast if the profile isn't cached** (tells you to warm via `exa aillm rules --tenant <t>`) rather than building synchronously (could exceed the client timeout).
- **Query / params:** AI rules selected by AI activity types or AI text in name/description. Context tables a rule reads parsed from `ContextListContains('<table>')`. Field is `isEnabled` (NOT `enabled`).
- **Computation:** `missing_fields = requiredFields not in profile`; `reachable = (none missing)`. `blocked_by_agent_telemetry` when all missing ⊆ the six agent-only fields. Aggregates enabled/disabled, blockers (field→rules), context_consumers, activity histogram. `profile.exists(f)` true only when measured AND populated.
- **Limits:** Hard dependency on a same-day cached profile. Reachability is a necessary-condition check (fields present), not proof a rule fires. Inherits the profile's ≤5000 sample.
- **Verify:** `GET .../analytics-rules`, read each AI rule's `requiredFields`, group_by each field — empty result confirms unreachable.

#### aillm_risk
- **Endpoint(s):** cached profile (observed domains) joined to a **local bundled/external JSON reference** — no dedicated live call beyond the profile.
- **Query / params:** observed = `profile.values("web_domain")`; reference = `known_ai_domains.json` from `~/.exa/aillm-domains/data/` (via `exa update`) else bundled snapshot.
- **Computation:** each host exact-or-suffix matched to the reference; matched domains bucketed by `risk` tier. `watchlist_total`=reference entries high/critical; `watchlist_hits`=observed domains in those tiers.
- **Limits:** Risk tiers reflect the **reference dataset's freshness, not live scoring** — a stale dataset under-classifies silently. `sample_truncated` → counts are lower bounds. Note: at time of writing no rule reads `Public AI Domains and Risk`, so this drives zero detections until surfaced here.
- **Verify:** group_by `web_domain` for observed; inspect `known_ai_domains.json` `risk` per domain; the buckets are a straight exact/suffix join. Check reference age (stale after 30 days).

#### aillm_gaps
- **Endpoint(s):** cached profile + live table reads + optional deep re-enumeration (`POST /search/v2/events` at `limit=50000`). Read-only — proposes, never writes.
- **Query / params:** `deep=True` re-enumerates any still-truncated field at 50,000 via `group_by=[name,"product","vendor"]` (the standing 5000 cap hid 6/8 real alert names behind Purview noise), then diffs live − table per table.
- **Computation:** `missing` values classified `propose` vs `withhold` with machine-readable reasons; alert names normalised per-vendor first; per-record shapes (email subjects, `@`-addresses, >120 chars) never proposed and redacted off disk. `raw_count` preserves collapsed live values; `balanced = (accounted == examined)` asserts every value landed in exactly one bucket.
- **Limits:** Counts are **LOWER BOUNDS** whenever any sample truncated (even the 50,000 cap can top out). Withheld free-text redacted unless `include_withheld_values=True` (healthcare PII). Domains/categories/apps/process-names proposed; process interpreters withheld.
- **Verify:** the report JSON carries `every_value_accounted_for` + per-table examined/proposed/withheld. Re-derive `missing` by diffing a 50,000-limit group_by vs the table's records.

#### ai_domain_lookup
- **Endpoint(s):** **No live API call** — local cached reference dataset only (`~/.exa/aillm-domains/data/*.json` via `exa update`, else bundled snapshot).
- **Query / params:** requires a `domains` list; builds lowercase sets of public domains (→risk), web domains, applications (IPv4 excluded).
- **Computation:** each domain matched full-host then registered-domain suffix against public → web → apps (first hit wins); returns `known_ai`, `list`, `risk`, `matched`. Dispatch returns `known`/`checked` counts.
- **Limits:** Reflects the **dataset's freshness, not live tenant data** — bundled is "frozen at release", external stale after 30 days. Says nothing about whether the tenant sees these domains.
- **Verify:** grep the domain in `known_ai_domains.json`/`known_ai_apps.json`; check dataset age before trusting a negative.

### SOC & tuning (2)

#### soc_kpis
- **Endpoint(s):** `POST /threat-center/v1/search/cases` (one call; verified 200 SA 2026-05-28).
- **Query / params:** `fields=["*"]`, `limit=5000`, `orderBy=["caseCreationTimestamp DESC"]`, `filter=""`, now-`lookback_days`..now.
- **Computation (all client-side):** `opened=len(cases)`; closed = stage contains CLOSED/RESOLVED/DISMISS; `close_rate=round(100·closed/opened,1)`; `mttr_hours` = mean `(lastModified−created)/3600` over closed (MTTR proxied by lastModified, not a true close event); `avg_open_age_hours` over non-closed; breakdowns via `Counter.most_common` (stage/priority/assignee/queue/rule/user).
- **Limits:** Default 30d, cap `limit=5000` → `truncated/sampled` when ≥5000, metrics over a truncated set. MTTR/age skip unparseable/inverted timestamps so denominators can be < closed/backlog. Query failure → zeros + note.
- **Verify:** same POST; count rows for opened; count CLOSED/RESOLVED/DISMISS for closed; average `(lastModified−created)/3600`.

#### tuning_report (NYMM)
- **Endpoint(s):** `POST /threat-center/v1/search/alerts` (primary) + best-effort `GET /detection-management/v1/analytics-rules` (enabled-rule count; failure swallowed).
- **Query / params:** alerts `fields=["*"]`, `limit=5000`, `orderBy=["riskScore DESC"]`, `filter=""`, now-`lookback_days`..now.
- **Computation:** alerts grouped by `name`; per group count, Σ riskScore, `esc` (truthy `caseId` = escalated). `escalation_rate=round(100·escalated/total,1)`. Ranking (`_classify`): pct≥5 & esc<5 → **Tune/disable**; pct≥5 & esc<20 → Review; avg_risk<40 & esc<10 → Review; else Keep. Sorted by count, top_n.
- **Limits:** Default 30d/top_n=20, cap 5000 → `truncated/sampled` (bias toward high-risk when truncated, since ordered by riskScore). "Escalated" inferred solely from non-empty `caseId`. Recommendations explicitly mechanical. `enabled_rules` may be 0 if that endpoint errors.
- **Verify:** same alerts POST; group by `name`; count + non-null `caseId` per name; apply the four thresholds; enabled count via the rules GET.

### Reports (3) — presentation only

#### render_report
- **Endpoint(s):** NONE — renders a caller-supplied `spec` dict; no tenant API.
- **Computation:** maps cards→stat_card, sections→panel/table/coverage_bar; values inserted verbatim (HTML-escaped). `coverage_bar` clamps 0–100 for bar WIDTH only, never the printed figure.
- **Limits:** Visualizes whatever it's handed and does NOT validate it — a wrong number renders as a clean branded wrong number. `data_table` caps display at 1000 rows. Output path sandboxed to the reports root.
- **Verify:** verify the upstream source that produced the spec, not the HTML.

#### render_dashboard
- **Endpoint(s):** For layout, NONE. BUT the dispatch passes the live client, so each sampleable panel fires `POST /search/v2/events` to populate **SAMPLE** chart data. No dashboard is created/imported via API (UI-only import).
- **Query / params:** `config` dict or `config_path` (under $HOME/CWD, `.json`/`.config`, ≤5 MB). Per panel: `search_events("", fields=[dim,"count(id)"], group_by=[dim], lookback=<scraped>, limit=200)`; only `event`/`datalake` panels sampled.
- **Computation:** sampled counts from `f0_`, capped to 8 (charts)/15 (tables). The panel's real UI context-table filter is **approximated** (UI filter ≠ EQL) → "shape, not exact scoped values." `panels`=count of `vis` elements.
- **Limits:** Preview/mockup only — not importable; sampled numbers illustrative; no client → layout only. Visualizes/samples, does not validate the config's logic.
- **Verify:** inspect the `.config` for layout; for numbers, run the shown group_by — but they won't match the real dashboard (approximated filter); authoritative values come from importing the `.config` into the UI.

#### render_abv
- **Endpoint(s):** NONE — renders a hand-authored in-code `ABV` dict; not a tenant scan, not a live call.
- **Computation:** counts literals in that dict (`held`/`fixed`/`findings`/clause count). Nothing derived from the codebase at run time.
- **Limits:** **Hand-authored point-in-time snapshot** (dated in-dict, older commit/test count); verdicts can lag the code. The module itself renders a note that an independent Praxen scan found more; the render "does not assert a live commit or test count." **The live Praxen scan against `security/praxen/WORKER_REMIT.md` is authoritative;** this scorecard is one input.
- **Verify:** don't trust the HTML as a current attestation — re-run the real Praxen scan and cross-check `security/praxen/results/`.

#### Do renders alter numbers? — the short answer
**No.** The report layer HTML-escapes and inserts values verbatim; it performs no arithmetic (the only numeric touch is `coverage_bar` clamping to a 0–100 pixel width, which never changes the printed value). `data_table` caps display at 1000 rows (truncation, not transformation). So `render_report`, `render_abv`, and the `render=true` paths on ingest/soc/tuning faithfully display exactly what the source tool computed. The only render that generates a number is `render_dashboard`'s live "SAMPLE" group_by counts, which are freshly queried and clearly labelled illustrative. **Trust therefore reduces to trusting the source tool — a wrong input renders as a clean, branded, wrong number, never an invented one.**

---

## Skills — what each one orchestrates

Skills are method wrapped around the tools: preflight, how to read the output, and the
traps. They add no new data source, so their provenance is the union of the tools they call.

| Skill | Composes (tools) | What it adds |
|---|---|---|
| exa-health-check | list_collectors, get_license_consumption, parser_health, aillm_validate, list_detection_rules | Collector staleness + ingest-vs-entitlement + table overlap + rule reachability; states what it couldn't see |
| exa-tam-report | ingest_value, parser_health, aillm_* | Branded TAM report; announces tenant + kind first |
| exa-call-prep | search_cases, health tools | Pre-call brief: recent cases, health flags, talking points |
| exa-aillm-sync | aillm_* (+ CLI write path) | AI/LLM posture + reference-table sync (demo tenants) |
| exa-dashboard-preview | render_dashboard | Renders a dashboard .config as a chart-drawn preview before UI import |
| exa-vault | (local files) + live tools | Uses the ExaVault as durable context paired with live reads |
| exa-nymm | tuning_report | Detection tuning (Mouton replacement): drivers by volume vs escalation |
| exa-soc-review | soc_kpis, tuning_report | SOC-manager review with the method to diagnose low close-rate / MTTR / backlog |
| exa-ingest-review | ingest_value, source_detail | Ingest overage review → Keep/Review/Trim, rendered |
| exa-identity | identity_health, context_table | Merged-entity / recycled-email investigation, gated remediation |
| exa-detection | `exa` CLI (SPL/Sigma→EQL, simulate, deploy) | Detection engineering; deploy writes — confirms first |
| exa-compliance | `exa compliance` (Field Oracle) | Audit + gap analysis across 11 frameworks |
| exa-selftest | `exa selftest` (all read tools) | Live preflight; times each tool vs a Desktop budget → findings JSON |
| exa-event-explorer | search_events (count(id) pattern) | Ad-hoc "top X by volume / count by Y" panels done correctly |
| exa-upgrade-readiness | context_table, list_collectors | NSA prereq checklist (the 8 required context tables + context source) |
| exa-upgrade-validation | get_app_status, search_alerts, tuning_report, parser_health | Post-cutover data-flow validation; "not flowing yet" vs "broken" |

## CLI modules — the broader `exa` surface (~81 commands, 21 groups)

The MCP surface is a curated slice; Claude Code (or a terminal) can drive the full CLI.

| Group | Purpose |
|---|---|
| `config` | Tenants + kinds (demo/customer); secrets in OS credential store |
| `cases` / `alerts` / `case` | Threat Center: search, triage, qualify, baseline-calibrate |
| `health` | License, app status, collectors, parser health, ingest value, source detail |
| `tables` | Context Management table CRUD (20k-record batch) |
| `aillm` | AI/LLM sources/validate/rules/risk/gaps + reference-table sync |
| `detection` | Analytics-rule export/import/diff across tenants |
| `sigma` / `splunk` | SigmaHQ + Splunk SPL → EQL conversion via the Field Oracle |
| `simulate` | Validate detection content by sending synthetic events |
| `compliance` | 11-framework audit + gap analysis (per-tenant Field Oracle) |
| `zones` / `hotkey` | Network Zones + Dataflow hot-key-risk analysis/fix |
| `endpoint` | Live API conformance testing against the Exabeam OpenAPI spec |
| `mcp` / `selftest` | MCP server install/serve + the live preflight harness |
| `update` | Content Library (CIM2) refresh |
| `dev` (@exabeam.com) | Internal dev utilities |

## How to independently verify ANY exa-tools number

1. Read the tool's **endpoint + query** above (or ask Claude for it).
2. Reproduce the raw call — `exa endpoint` conformance test, `curl` with your token, or
   the Search UI with the same EQL and time window.
3. For a **derived** metric (%, MTTR, grade, Keep/Review/Trim, overlap), read the formula
   in the tool's row and decide whether you agree with the method.
4. If the tool set a `truncated`/`sampled`/`partial_scan` flag, widen the limit or narrow
   the window and re-run — the number was a floor, and "none found" was not authoritative.
5. When in doubt, `exa selftest --tenant <t>` shows every tool's live status + timing.

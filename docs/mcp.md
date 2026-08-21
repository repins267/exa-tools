# Claude / MCP

How exa-tools exposes Exabeam to Claude Desktop and Claude Code — which client builds run MCP, the full tool and skill surface, the safety model, and the preflight you run before a demo.

[← README](../README.md)

exa-tools ships an **MCP server** (`exa mcp serve`) that exposes a curated, **read-only-by-default** slice of the CLI to Claude, plus a plugin carrying agentic **skills** and a branded **report renderer**. Claude spawns the server for you — you never run `exa mcp serve` by hand.

## Install

```bash
# Claude Code — loads the MCP server + skills from the repo
claude plugin install exa-tools@exa-tools

# Claude Desktop — then fully quit and reopen; check Settings → Developer for the `exabeam` server
exa mcp install --tenant <tenant>

# Not sure which client/build you have?
exa mcp install --tenant <tenant> --print
```

`--print` shows the exact config block **and every config path for your OS** — Desktop on Windows and macOS, and Claude Code — with live `detected / not present` state, and flags a Microsoft Store build that can't run MCP. `--allow-writes` (default `--read-only`) is where the four write tools get turned on; `--docs` installs the documentation-only Exabeam Developer Portal server instead, with no tenant and no local repo.

## Which Claude client works?

Your Claude *plan* is not the blocker — the **Free plan works**. What matters is the **app build**: local MCP is a feature of the app, not the subscription.

| Client | Runs exa-tools? | Why / config path |
| --- | --- | --- |
| **Claude Desktop — standalone** (claude.ai/download) | Yes, even on Free | Has Developer Mode (**Settings → Developer**). Config: `%APPDATA%\Claude\claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`) |
| **Claude Desktop — Microsoft Store** (MSIX) | No | Sandboxed, no Developer Mode — the config is written but never read. **Fix:** uninstall it, install the standalone app instead |
| **Claude Desktop — work AWS Bedrock** ("Claude-3p") | Yes | Enterprise build. Config: `%LOCALAPPDATA%\Claude-3p\claude_desktop_config.json`; the `--docs` server is proxied via `npx mcp-remote` |
| **Claude Code** (Free or licensed) | Yes | `claude mcp add …` or a project `.mcp.json`; never hits the Store-sandbox problem |

## Tools (33)

Thirty-three tools across search/cases/alerts, health, identity, SOC tuning, AI/LLM, detection, tenant, and reports. All are read-only except the four marked `*`, which stay hidden and are refused unless the server is started with `--allow-writes`.

| Group | Tools |
| --- | --- |
| Search / cases / alerts | `search_alerts` `get_alert` `search_cases` `get_case` `search_events` `create_case`\* `update_case`\* `update_alert`\* `add_case_note`\* |
| Health | `get_license_consumption` `get_app_status` `list_collectors` `parser_health` `ingest_value` `source_detail` |
| Identity / context | `identity_health` `context_table` |
| SOC / tuning | `soc_kpis` `tuning_report` (NYMM) |
| AI/LLM | `aillm_sources` `aillm_validate` `aillm_rules` `aillm_risk` `aillm_gaps` `ai_domain_lookup` |
| Detection | `list_detection_rules` |
| Tenant | `get_active_tenant` `list_tenants` `set_active_tenant` `set_tenant_kind` |
| Reports | `render_report` `render_dashboard` `render_abv` |

\* write tools, gated behind `--allow-writes`.

Switching tenants is a nickname lookup handled server-side (`set_active_tenant`), so no credential ever reaches the model.

## Skills (17)

The plugin carries seventeen agentic skills. The tenant-aware ones announce the active tenant and its kind (demo/customer) before they report or write.

`exa-health-check` · `exa-tam-report` · `exa-call-prep` · `exa-aillm-sync` · `exa-assess` · `exa-dashboard-preview` · `exa-vault` · `exa-nymm` · `exa-soc-review` · `exa-ingest-review` · `exa-identity` · `exa-detection` (Code-first) · `exa-compliance` (Code-first) · `exa-selftest` (Code-first) · `exa-event-explorer` · `exa-upgrade-readiness` · `exa-upgrade-validation`

The Code-first skills shell the `exa` CLI directly rather than going through MCP tools, so they reach commands (deploy, import, sync) the read-only tool surface doesn't expose — name and confirm the tenant before any write.

## Safety and guardrails

Read-only by default. Secrets stay in the OS credential store, and tenant switching is a nickname lookup, so no secret reaches the model. Beyond that, two guardrails (adapted from socxen / observra) sit on every call:

- **Result canonicalization** — every tool *result* has invisible smuggling code points stripped and is NFC-normalized, so prompt injection hidden in a log field can't reach Claude.
- **Write-input neutralization** — free-text *write* inputs are neutralized before they persist: spreadsheet formulas quote-prefixed, links defanged, secrets redacted.

A metadata-only **audit log** (default on, fail-open, rotating JSONL at `~/.exa/audit.jsonl`) records every call — tool, tenant/kind, read/write, duration, status, result size, and safe id fields — and **never** notes, secrets, or payloads. Disable with `EXA_AUDIT=off`.

Both guardrails are regression-tested against a red-team attack corpus, and `security/` also carries a CycloneDX AI-BOM and the Praxen Agent Behavior Verification results.

→ Depth on the guardrails, red-team corpus, AI-BOM, and Praxen lives in [docs/security.md](security.md); attribution in [CREDITS.md](../CREDITS.md).

### Praxen Agent Behavior Verification

The MCP server, its tools, and the skills are verified with [Praxen](https://github.com/open-agent-ai-security/praxen) — a declared policy remit adjudicated against the actual code, checked in under `security/praxen/`. The `render_abv` tool renders that verification as a branded HTML report: a verdict banner, a remit-coverage scorecard pairing each declared policy clause against observed behavior, and the findings register. It describes the MCP's own security posture — it does **not** scan the tenant.

## Selftest preflight

Run the live preflight before a demo, or when onboarding a new user, to confirm nothing in the tool surface times out on this tenant:

```bash
exa selftest --tenant <tenant>
exa selftest -t <tenant> --only aillm_validate,aillm_gaps    # subset
exa selftest -t <tenant> -o preflight.json                   # explicit output path
```

It exercises **every read tool** through the same path Claude Desktop uses, times each one, and classifies it against a Desktop-latency budget: `ok`, `slow` (over `--slow-seconds`, default 25s — a demo risk), `timeout` (over `--timeout-seconds`, default 55s — Desktop would hang), or `error`. Findings are written to `reports/selftest/<tenant>-<date>.json`, and the command exits non-zero on any timeout or error so a scheduled task can alert on it. Run it for every new skill or MCP tool that goes live.

On start, the server also **warms the AI/LLM tenant field-profile in the background**, so the first AI/LLM query in a fresh Claude Desktop session no longer eats the ~35s cold-collection cost and looks hung.

## Reports

Compliance audit, parser health, ingest value, source deep-dive, SOC KPIs, NYMM tuning, dashboard previews, and the Praxen ABV all render through one branded, self-contained theme — dark default, light/dark toggle, embedded logo — as HTML / PDF / CSV / JSON.

Rendered output is auto-organized under `reports/{kind}/{tenant}/` — the tenant's kind tag (`demo`/`customer`) and nickname, e.g. `reports/customer/<tenant>/` — with intermediate directories created automatically. Pass `output_path` to override.

[← README](../README.md)

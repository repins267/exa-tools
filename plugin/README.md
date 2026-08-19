# exa-tools plugin

Exabeam New-Scale TAM work as agentic skills — health checks, AI/LLM posture, and
customer call prep, backed by the exa-tools MCP server.

## Two ways in, and they are not the same

**From a checkout (what to use on a work laptop).** The MCP server runs from the repo,
so nothing needs to be on PATH:

```powershell
cd <repo>\plugin
.\install.ps1 -Tenant <tenant>
```

The script derives the repo from its own location, checks `uv` and `exa` run,
pre-flights authentication, writes the Claude Desktop config, and then confirms the
config contains no credential fields. Restart Claude Desktop completely afterwards —
quitting from the tray, not just closing the window.

**As an installed plugin.** `.mcp.json` invokes bare `exa`, so exa-tools must be on
PATH first:

```
uv tool install exa-tools     # or: pip install exa-tools
exa configure                 # stores the client secret in Windows Credential Manager
```

Then install the plugin from a marketplace. Installing it wires the MCP server for you.

## No secrets in any config

The generated Claude Desktop entry invokes `exa mcp serve` and contains **no
credentials**. The client secret is read from Windows Credential Manager at runtime.
`install.ps1` checks the written config for credential-shaped fields and warns if it
finds any.

## Self-contained

The plugin references nothing outside this repository — no vault, no network shares, no
home-server paths. Skills carry their own method. That is deliberate: a skill that
reads a path only present on one machine works exactly once.

## Verifying it actually connected

Do not verify by asking a question — both the live tenant server and the API docs
server answer Exabeam questions plausibly. **Name a tool.** Ask for `aillm_sources`
against a demo tenant; tool names in the reply are the only reliable signal that the
live tenant server answered.

## Skills

| Skill | What it does |
|---|---|
| `exa-health-check` | Collector staleness, ingest vs entitlement, source inventory, context-table health measured as overlap rather than record count, rule reachability. States explicitly what it could not see. |
| `exa-tam-report` | Branded TAM report for a tenant — ingest value, parser health, AI/LLM posture — tenant-aware (announces tenant + kind first). |
| `exa-call-prep` | Pre-call brief for a customer/demo tenant: recent cases, health flags, and talking points. |
| `exa-aillm-sync` | AI/LLM threat-detection posture and reference-table sync (demo tenants). |
| `exa-dashboard-preview` | Renders an Exabeam dashboard `.config` as a chart-drawn branded preview so you can iterate before the manual UI import. |
| `exa-vault` | Uses the ExaVault (Obsidian TAM knowledge vault) as durable context, paired with live MCP data. Code-first local file access. |
| `exa-nymm` | NYMM ("Not Your Momma's Mouton") — detection-tuning insight for New-Scale Analytics, the replacement for the deprecated Mouton AA tuning tool. Ranks alert drivers by volume vs. escalation-to-case and flags tune/disable candidates. Read-only. |

Add them in Claude Desktop under **Settings -> Customize -> Skills**, from
`plugin\skills\`. In Claude Code they load with the plugin.

## Writes ask first, and that ask is soft

The MCP exposes four write tools — `create_case`, `update_case`, `update_alert`,
`add_case_note`. Their descriptions instruct the model to stop and wait for an explicit
yes.

**That is a soft gate.** In Claude Code a permission rule can enforce it at the harness.
In Claude Desktop there is no such rule, so the instruction is the only thing there.
Treat a customer tenant accordingly: the read tools are safe to run unattended, the
write tools are not.

## A note on model routing

If Claude Desktop is pointed at an organisation's Bedrock deployment, that changes where
inference happens, not where this MCP server runs — it stays local. But everything the
tools return, including alert content, case notes and user email addresses, transits
that deployment. Worth being deliberate about before pointing it at a customer tenant.

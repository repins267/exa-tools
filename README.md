<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)"  srcset="docs/brand/exa-tools-banner-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/brand/exa-tools-banner-light.svg">
  <img src="docs/brand/exa-tools-banner-dark.svg" alt="exa-tools" width="560">
</picture>

**Operate Exabeam New-Scale from your terminal — or hand it to Claude.**

Multi-tenant config, AI/LLM shadow-AI detection, case triage, compliance auditing across
11 frameworks, and Splunk/Sigma rule conversion.

[![CI](https://github.com/repins267/exa-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/repins267/exa-tools/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-006BFF?style=flat-square&labelColor=05060f&logo=python&logoColor=white)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-33_tools-27B2FF?style=flat-square&labelColor=05060f)](docs/mcp.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-009D00?style=flat-square&labelColor=05060f)](LICENSE)

[Quick start](#quick-start) · [Configuration](#1--configuration) · [Claude / MCP](#2--claude--mcp) ·
[AI/LLM](#3--aillm) · [Threat Center](#4--threat-center) · [Compliance](#5--compliance) ·
[Detection](#6--detection) · [Security](#security-posture)

</div>

---

## Why

- **Every tenant, one command.** Credentials live in the OS credential store, never in a config
  file. Switch environments with `--tenant`; nothing secret reaches disk or your shell history.
- **Claude can read your tenant.** 33 MCP tools and 17 agentic skills, read-only by default.
  Tenant switching is a nickname lookup, so no credential ever reaches the model.
- **Shadow AI is the question customers are asking now.** Six reference tables covering 223
  domains and 90 applications — synced to the tenant, then enriched from its own proxy logs.

## Quick start

```bash
git clone https://github.com/repins267/exa-tools.git
cd exa-tools
uv sync
uv tool install -e .        # install `exa` globally from local source

exa configure               # tenant FQDN + client credentials -> OS keyring
exa update                  # pull CIM2 / SigmaHQ reference data, build the Field Oracle
```

Every command takes `--help`. Every command takes `--tenant <name>`.

## What's in it

| Area | What it does | Docs |
|---|---|---|
| Configuration | Multi-tenant credentials, reference-data sync, context tables | [docs/configuration.md](docs/configuration.md) |
| Claude / MCP | 33 tools + 17 skills exposed to Claude Desktop and Claude Code | [docs/mcp.md](docs/mcp.md) |
| AI/LLM | Six shadow-AI context tables, log-based discovery, risk overrides | [docs/aillm.md](docs/aillm.md) |
| Threat Center | Case and alert search, structured triage, outcome calibration | [docs/threat-center.md](docs/threat-center.md) |
| Compliance | 11 frameworks, tenant-aware queries, HTML/PDF gap reports | [docs/compliance.md](docs/compliance.md) |
| Detection | SPL and Sigma → EQL, field-verified, deploy to tenant | [docs/detection.md](docs/detection.md) |
| Architecture | The conversion pipeline and the Field Oracle, in detail | [docs/architecture.md](docs/architecture.md) |
| NYMM | Detection tuning — the New-Scale-native Mouton replacement | [docs/nymm.md](docs/nymm.md) |
| Hot key | Dataflow worker imbalance from coarse Network Zones | [docs/hotkey.md](docs/hotkey.md) |

---

## 1 · Configuration

Tenants are registered once and referenced by nickname. Secrets go to Windows Credential
Manager, macOS Keychain, or Linux Secret Service — never to `~/.exa/config.json`.

```bash
exa configure                          # interactive: FQDN, client id, secret; tests the connection
exa config set default-tenant <name>
exa config show

exa update                             # sync CIM2 + SigmaHQ, rebuild the Field Oracle
exa update --check                     # show current SHAs without pulling
exa update self                        # git pull + uv sync on exa-tools itself
```

Context tables get full CRUD with 20k-record batching — create from CSV with an auto-derived
schema, append or replace, export back out.

→ [Full configuration and `exa tables` reference](docs/configuration.md)

## 2 · Claude / MCP

exa-tools ships an MCP server (`exa mcp serve`) exposing a curated, **read-only-by-default**
slice of the CLI to Claude Desktop and Claude Code, plus a plugin carrying agentic skills and a
branded report renderer.

```bash
# Claude Code
claude plugin install exa-tools@exa-tools

# Claude Desktop — then fully quit and reopen
exa mcp install --tenant <name>
exa mcp install --tenant <name> --print   # show the config block and every path for your OS
```

You never run `exa mcp serve` yourself — Claude spawns it.

**33 tools** across search/cases/alerts, health, identity, SOC tuning, AI/LLM, detection, tenant,
and reports. **17 skills**, the tenant-aware ones announcing the active tenant and its kind
(demo/customer) before they report or write. Four write tools exist and stay hidden unless the
server is started with `--allow-writes`.

Your Claude *plan* is not the blocker — the Free plan works. The *app build* is what matters, and
the Microsoft Store build can't run local MCP at all.

The MCP server, its tools, and the skills are verified with
[Praxen](https://github.com/open-agent-ai-security/praxen) Agent Behavior Verification — a
declared policy remit adjudicated against the actual code, with results checked in under
`security/praxen/`.

→ [Client matrix, tool tables, guardrails, and the selftest preflight](docs/mcp.md)

## 3 · AI/LLM

Six context tables for AI/LLM threat detection, sourced from
[ai-llm-domains](https://github.com/repins267/ai-llm-domains) — 223 domains rated Low/Medium/High,
90 applications, proxy and web categories, and DLP ruleset names.

```bash
exa aillm sync                             # append; --force to replace, --dry-run to preview
exa aillm sync --discover-from-logs        # add AI domains actually seen in proxy/web logs
exa aillm sync-ruleset --tenant <name>     # replace generic DLP names with this tenant's real ones
exa aillm discover --tenant <name>         # candidate alert names and app names, report only
exa aillm status                           # live record counts for all six tables
```

High-risk ratings carry a stated rationale — data jurisdiction, autonomous execution, absent
enterprise controls, or impersonation — rather than a bare score. Per-tenant risk overrides take
a JSON map.

→ [Table schemas, category breakdown, discovery passes, and exclusions](docs/aillm.md)

## 4 · Threat Center

```bash
exa cases list --filter 'NOT stage:"CLOSED"' --limit 20
exa case qualify C-1042                   # structured triage -> a verdict
exa case baseline                         # per-rule and per-entity FP rates (add --json for machine output)
exa case outcome sync                     # back-fill analyst decisions from closed cases
```

`exa case qualify` pulls the triggering correlation rule, entity case history, context table
membership, score trend, and external IP annotations, then issues one of four verdicts:
`SUSPECTED_INCIDENT`, `LIKELY_FP`, `LEARNING_PHASE_NOISE`, `NEEDS_INVESTIGATION`.

Every qualification is logged. `exa case baseline` pulls historical closed cases — capped
automatically to the tenant's licensed LTS retention window, not a hardcoded limit — computes
false-positive rates, and feeds that calibration back into later verdicts.

→ [Verdict criteria, outcome tracking, and EQL filtering](docs/threat-center.md)

## 5 · Compliance

```bash
exa frameworks                                            # list frameworks + testable control counts
exa compliance audit --framework "NIST CSF v2.0" --lookback 30
exa compliance audit --framework "PCI DSS" --output-html --output-pdf
```

Controls are annotated with semantic concepts rather than fixed field filters. At audit time the
resolver queries the tenant for the `activity_type` values actually present, then builds EQL from
only those — so a missing log source fails as a clear gap instead of a false negative from a query
that never matched anything.

Seven frameworks ship full queries (NIST CSF v2.0, CIS v8, HIPAA, PCI DSS, FedRAMP Moderate,
ISO 27001:2022, CJIS); four are stubs pending queries (CMMC L2/L3, GDPR, SOX). Reports render as
HTML and PDF with an executive summary, family coverage, and gap analysis.

→ [Control counts, output flags, and tenant-aware vs static mode](docs/compliance.md)

## 6 · Detection

```bash
exa sigma convert --rule proc_creation_powershell_encoded.yml
exa splunk one 'index=ad CommandLine="*mimikatz*"' --title "Mimikatz Detection"
exa splunk convert searches.xlsx                  # batch from Excel
exa sigma deploy --rule <rule>.yml --tenant <name>
```

<div align="center">
  <img src="docs/pipeline-animation.svg" alt="SPL to Sigma to EQL conversion pipeline" width="820">
</div>

SPL and EQL are different enough that a direct translation loses information, so conversion routes
through Sigma as a structured intermediate. That buys the community-maintained Sigma field
vocabulary, proper modifiers for wildcards, real filter blocks for negations, and an explicit
inventory of the pipeline stages that *can't* be expressed in EQL — as warnings, rather than
silently dropped.

Field mapping doesn't come from a hand-maintained table. `exa update` walks Exabeam's own parser
definitions and builds the **Field Oracle**: 4,258 raw→CIM2 mappings from 8,278 parser files
across 269 vendors. Every resolved field is rated `oracle` (confirmed in the parsers for this
vendor and activity type), `schema` (in CIM2, unconfirmed for this source), or `passthrough` (no
mapping), so you know what's verified before you deploy. When Exabeam ships new parsers, the next
`exa update` picks them up — no code change.

All converted rules land disabled and marked *Needs review*. SPL→EQL is lossy by design.

→ [Conversion reference](docs/detection.md) · [How the pipeline and Oracle work](docs/architecture.md)

## 7 · Also in the box

- **NYMM** — detection tuning for New-Scale, replacing the deprecated Mouton tool. Mouton ranked
  rules by how many notables would vanish if you disabled them; New-Scale has no notables, so NYMM
  uses the analog — a detection that fires constantly but rarely escalates to a case is noise.
  Ranks alert drivers by volume, average risk, and escalation-to-case rate, then flags each
  Keep / Review / Tune-disable. Read-only: it recommends, never disables.
  → [docs/nymm.md](docs/nymm.md)
- **`exa hotkey`** — diagnose and fix Apache Beam/Dataflow worker imbalance caused by coarse
  Network Zones entries. Analyze → scan real traffic → expand to /24, with a rollback manifest
  written before anything changes. → [docs/hotkey.md](docs/hotkey.md)
- **`exa detection`** — export, import, and diff analytics (UEBA) rules across tenants for backup,
  migration, and gap analysis.
- **`exa search`** — direct EQL query interface with time range and result limiting.

## Security posture

Read-only by default; the four write tools are hidden and refused without `--allow-writes`.
Secrets stay in the OS credential store and never reach the model. Every tool *result* is
canonicalized — invisible smuggling code points stripped, NFC-normalized — so prompt injection
hidden in a log field can't reach Claude; free-text *write* inputs are neutralized before they
persist. A metadata-only audit log records every call and never records notes, secrets, or
payloads. Both guardrails are regression-tested against a red-team attack corpus. `security/`
also carries a CycloneDX AI-BOM and the Praxen Agent Behavior Verification results described
under [Claude / MCP](#2--claude--mcp).

→ [docs/security.md](docs/security.md) · attribution in [CREDITS.md](CREDITS.md)

## Project

**Requires** Python 3.12+, [uv](https://docs.astral.sh/uv/), git, and an OS credential store.

```bash
uv sync                    # install deps
uv run pytest -v           # run the suite
uv run ruff check exa/     # lint
git config core.hooksPath .githooks    # enable pre-commit help tests
```

[Contributing](CONTRIBUTING.md) · [Code style](CODESTYLE.md) · [Changelog](CHANGELOG.md) ·
[Credits](CREDITS.md) · [Third-party notices](THIRD_PARTY_NOTICES.md)

## License

MIT — see [LICENSE](LICENSE).

*exa-tools is not an official Exabeam product. Exabeam, New-Scale, and the Exabeam logo are
trademarks of Exabeam, Inc.*

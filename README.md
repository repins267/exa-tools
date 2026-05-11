# exa-tools

![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![uv](https://img.shields.io/badge/package%20manager-uv-blueviolet)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Platform: Exabeam NSA/SIEM](https://img.shields.io/badge/platform-Exabeam%20New--Scale%20Analytics%20%28NSA%29%20%2F%20SIEM-orange)
![Tests](https://img.shields.io/badge/tests-533%20passing-brightgreen)

Python automation toolkit for Exabeam New-Scale Analytics (NSA) / SIEM. Built for security engineers who need to move fast across detection engineering, compliance, and content management without living in the UI.

**Detection rule conversion** routes Splunk SPL searches and SigmaHQ community rules through a shared `SPL → Sigma → EQL` pipeline backed by the **Field Oracle** — a local index of 4,258 raw→CIM2 field mappings extracted from Exabeam's own parser definitions. Every converted field gets a confidence rating (Oracle / Schema / Passthrough) so you know exactly what's verified before you deploy.

**One-step deployment** pushes converted rules directly to your tenant via API. Multi-tenant support lets you target any registered environment with `--tenant`.

**Threat Center integration** gives analysts a full CLI workflow for cases and alerts — search, triage, update, and qualify. `exa case qualify` pulls the triggering correlation rule, entity history, context table membership, and score trend, then issues a structured verdict (SUSPECTED_INCIDENT / LIKELY_FP / LEARNING_PHASE_NOISE / NEEDS_INVESTIGATION) to help analysts decide faster.

**Outcome tracking and calibration** logs every qualification and tracks analyst decisions over time. `exa case baseline` uses the tenant's licensed LTS retention window to pull historical closed cases, computes per-rule and per-entity false-positive rates, and feeds that calibration back into future verdicts automatically.

**Detection Management** exports, imports, and diffs analytics rules across tenants — enabling rule backup, migration, and cross-environment gap analysis.

**Compliance auditing** runs automated evidence collection across 11 frameworks — NIST CSF v2.0, CMMC L2/L3, PCI DSS, HIPAA, FedRAMP Moderate, CIS Controls v8, ISO 27001, CJIS, GDPR, and SOX — and produces HTML and PDF reports with executive summaries and gap analysis. Queries are dynamically built per-tenant using **Field Oracle concept resolution**, ensuring controls match the actual `activity_type` values present in each environment.

**Context table management** handles bulk CRUD operations with 20k-record batch support, including pre-built sync for AI/LLM threat detection reference tables.

All from the command line.

![Pipeline Animation](docs/pipeline-animation.svg)

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- git (required for `exa update`)
- Windows Credential Manager (Windows) / Keychain (macOS) / Secret Service (Linux)

## Installation

```bash
git clone <repo-url> exa-tools
cd exa-tools
uv sync
```

## First-Time Setup

```bash
uv tool install -e .       # install exa globally from local source
exa configure              # set up tenant credentials (stored in keyring)
exa update                 # clone CIM2 + SigmaHQ repos and build Field Oracle
```

## Quick Start

```bash
exa configure                                    # set up tenant + credentials
exa update                                       # download reference data + build oracle
exa sigma convert --rule proc_creation_powershell_encoded.yml
exa splunk one 'index=ad CommandLine="*mimikatz*"' --title "Mimikatz Detection"
```

## Commands

Every command supports `--help` for full usage and flag descriptions:

```bash
exa --help                    # list all commands
exa sigma convert --help      # flags for a specific command
exa splunk deploy --help
```

### `exa configure`

Interactive setup: enter your tenant FQDN, client ID, and client secret. Tests the connection, saves credentials to keyring, and optionally downloads CIM2/SigmaHQ reference data.

### `exa update`

```bash
exa update             # sync CIM2 + SigmaHQ repos, build Field Oracle
exa update self        # git pull main + uv sync on exa-tools itself
exa update --check     # show current SHAs without pulling
```

Downloads [Content-Library-CIM2](https://github.com/ExabeamLabs/Content-Library-CIM2), [new-scale-content-hub](https://github.com/ExabeamLabs/new-scale-content-hub), and [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma), then builds the Field Oracle from 8,278 parser definition files.

### `exa config`

```bash
exa config set sigma.rules-dir "E:\SigmaHQ\rules\windows"
exa config set default-tenant sademodev22
exa config get sigma.rules-dir
exa config show
```

Configuration stored at `~/.exa/config.json`. Secrets are never written to this file.

### `exa tables`

```
exa tables list [--name FILTER] [--tenant TENANT] [--json]

exa tables create NAME [--type TYPE] [--key COLNAME] [--columns a,b,c]
                       [--csv PATH] [--replace] [--tenant TENANT]
  --type     Context type: Other (default), User, TI_ips, TI_domains,
             Device, Domain, IP
  --key      Key column name (default: "key", or first CSV column)
  --columns  Extra column names (comma-separated; ignored if --csv given)
  --csv      CSV file — headers become columns, rows uploaded immediately
  --replace  Use replace semantics when uploading CSV (default: append)

exa tables delete TABLE [--yes] [--purge-attributes] [--tenant TENANT]
  TABLE  Table ID or display name

exa tables records list TABLE [--limit N] [--offset N]
                               [--csv PATH] [--json] [--tenant TENANT]

exa tables records upload TABLE CSV_PATH [--replace] [--key COLNAME]
                                          [--tenant TENANT]
  --replace  Overwrite entire table (default: append)

exa tables records export TABLE OUTPUT_PATH [--tenant TENANT]
```

### `exa hotkey`

Diagnose and fix Apache Beam/Dataflow hot key risk caused by coarse Network Zones context table entries. Confirmed fix for Dataflow worker imbalance (Known customer, job cv06f9, 47-minute runtime, 96 HotKeyLogger warnings).

```
exa hotkey analyze [--ip-field COL] [--name-field COL]
                   [--json] [--csv] [--tenant TENANT]
  Classify Network Zones table entries by Dataflow hot key risk.
  COARSE = /8 or /16 (high risk). MEDIUM = /24 (acceptable). FINE = /32.

exa hotkey scan [--lookback N] [--threshold N] [--limit N]
                [--ip-field COL] [--name-field COL]
                [--json] [--csv] [--tenant TENANT]
  Scan recent events for active source IPs per zone.
  Flags zones with >N distinct IPs as HOT_KEY_RISK (default threshold: 500).

exa hotkey expand [--zone ZONE] [--lookback N] [--enumerate]
                  [--dry-run] [--limit N]
                  [--ip-field COL] [--name-field COL] [--tenant TENANT]
  Expand COARSE zone(s) from /8 or /16 to /24-granularity entries.
  Writes a rollback manifest to ~/.exa/hotkey-rollback/ before any change.
  --zone       Target a single zone by name (default: all COARSE zones)
  --enumerate  Create all /24 subnets in range (default: observed IPs only)
  --dry-run    Print planned changes without writing anything

exa hotkey autofix [--lookback N] [--threshold N] [--max-zones N]
                   [--enumerate] [--dry-run] [--json] [--tenant TENANT]
  Full automated pipeline: analyze → scan → expand in one command.
  --max-zones  Safety cap (default 10). Refuses to expand more zones
               than this in a single run.
  Safe to schedule — non-interactive, exits non-zero on any failure.

exa hotkey rollback [--manifest PATH] [--confirm] [--tenant TENANT]
  Restore Network Zones table from the most recent rollback manifest.
  Use --manifest to specify an older manifest by path.
  Requires --confirm to apply (shows diff first without it).
```

### `exa sigma convert`

```bash
exa sigma convert --rule proc_creation_powershell_encoded.yml
exa sigma convert --dir ./rules/windows/
exa sigma convert --dir ./rules/ --deploy
exa sigma convert --dir ./rules/ --deploy --tenant sademodev22
```

Converts Sigma YAML rules to Exabeam EQL correlation rules. Field Oracle provides confidence ratings for every field mapping. With `--deploy`, creates correlation rules on the tenant via API.

Short alias: `exa sc`

### `exa sigma deploy`

```bash
exa sigma deploy --rule proc_creation_powershell_encoded.yml --tenant sademodev22
```

Convert and deploy a single Sigma rule in one step. Short alias: `exa sd`

### `exa sigma browse`

```bash
exa sigma browse --category process_creation --level high
exa sigma browse --tag t1059 --product windows
exa sigma browse --search "powershell"
```

Browse SigmaHQ community rules from the local index. Filter by category, product, level, ATT&CK tag, or keyword.

### `exa splunk convert`

```powershell
# Batch convert an Excel file with 'title' and 'search' columns
exa splunk convert searches.xlsx

# Show all per-rule warnings including field confidence
exa splunk convert searches.xlsx --verbose

# Custom output file
exa splunk convert searches.xlsx --output rules.json
```

Outputs a rich table showing each rule's index, activity type, EQL preview, warning count, and deploy status. Saves an API-ready JSON file of all payloads.

### `exa splunk one`

Convert a single SPL search inline — no Excel file needed.

```powershell
exa splunk one 'index=c42 severity="High"' --title "Code42 High Severity Alert"
exa splunk one 'index=o365 Operation=Send' --title "O365 Outbound Email"
exa splunk one 'index=ad CommandLine="*mimikatz*"' --json
exa splunk one 'index=fireamp_stream severity="High"' --title "AMP Alert" -o rule.json
```

### `exa splunk deploy`

```powershell
exa splunk deploy rules.json --dry-run --tenant sademodev22   # preview
exa splunk deploy rules.json --tenant sademodev22             # deploy (disabled by default)
```

All rules are created **disabled** by default. Validate the EQL in the Exabeam UI before enabling.

### `exa compliance audit`

Run a gap-analysis compliance audit against your Exabeam tenant. Queries each SIEM-testable control using live event data and produces pass/fail results with evidence counts.

```bash
# Basic audit (tenant-aware mode enabled by default)
exa compliance audit --framework "NIST CSF v2.0" --lookback 30

# Specify tenant
exa compliance audit --framework "NIST CSF v2.0" --tenant lvcva --lookback 30

# Save HTML report (auto-named reports/<tenant>-<framework>-<date>.html)
exa compliance audit --framework "NIST CSF v2.0" --tenant lvcva --output-html

# Save HTML to explicit path
exa compliance audit --framework "NIST CSF v2.0" --tenant lvcva --output-html C:\reports\audit.html

# Save PDF report (auto-named, rendered via Microsoft Edge headless)
exa compliance audit --framework "NIST CSF v2.0" --tenant lvcva --output-pdf

# Save PDF to explicit path
exa compliance audit --framework "NIST CSF v2.0" --tenant lvcva --pdf-path C:\reports\audit.pdf

# Tenant-aware mode (default) — discovers active activity_types via Field Oracle
exa compliance audit --framework "NIST CSF v2.0" --tenant lvcva --tenant-aware

# Static mode — uses hardcoded filters from JSON only, skips tenant discovery
exa compliance audit --framework "NIST CSF v2.0" --tenant lvcva --no-tenant-aware
```

**Output flags:**

| Flag | Behavior |
|---|---|
| `--output-html` | Auto-save HTML to `reports/` |
| `--output-html <path>` | Save HTML to explicit path |
| `--output-pdf` | Auto-save PDF to `reports/` via Edge headless |
| `--pdf-path <path>` | Save PDF to explicit path |
| `--tenant-aware` | Dynamic EQL via Field Oracle concept resolution (default: on) |
| `--no-tenant-aware` | Static filters from ControlQueries JSON |

HTML reports are saved to `reports/` and include an executive summary, family coverage breakdown, and gap analysis. PDF reports are rendered from HTML via Microsoft Edge headless (`msedge.exe --headless --print-to-pdf`) — no additional software required on Windows.

**Supported frameworks:**

| Framework | SIEM-Testable Controls | Status |
|---|---|---|
| NIST CSF v2.0 | 60 | Full queries + concept annotations |
| CIS Controls v8 | ~110 | Full queries + concept annotations |
| HIPAA | ~67 | Full queries + concept annotations |
| PCI DSS | ~153 | Full queries + concept annotations |
| FedRAMP Moderate | ~145 | Full queries + concept annotations |
| ISO 27001:2022 | ~58 | Full queries + concept annotations |
| CJIS | ~55 | Full queries + concept annotations |
| CMMC Level 2 | ~55 | Stub (queries pending) |
| CMMC Level 3 | ~20 | Stub (queries pending) |
| GDPR | ~30 | Stub (queries pending) |
| SOX | ~15 | Stub (queries pending) |

### `exa cases` / `exa alerts`

Search and manage Threat Center cases and alerts.

```bash
exa cases list                                        # all open cases, last 30 days
exa cases list --filter 'NOT stage:"CLOSED"' --limit 20
exa cases list --json                                 # raw JSON for pipeline use
exa cases get <case-uuid>
exa cases get <case-uuid> --json
exa cases update <case-uuid> --stage CLOSED --closed-reason "False Positive"
exa cases update <case-uuid> --priority CRITICAL --assignee analyst@corp.com
exa cases update <case-uuid> --tags "reviewed,escalated"

exa alerts list --filter 'priority:"HIGH"' --lookback 7
exa alerts get <alert-uuid>
exa alerts update <alert-uuid> --priority LOW --tags "noise"
```

### `exa case qualify`

Structured analyst triage for a single case. Pulls the triggering correlation rule definition, entity case history, context table membership, score trend, and external IP annotations — then issues a verdict.

```bash
exa case qualify C-1042
exa case qualify C-1042 --window 30    # ±30 min event context window
exa case qualify C-1042 --json         # machine-readable QualificationReport
```

**Verdicts:**

| Verdict | Meaning |
|---|---|
| `SUSPECTED_INCIDENT` | Single-event rule, new entity, first appearance or escalating score — investigate now |
| `LIKELY_FP` | Entity in compliance context table, not a new high, or rule has >75% historical FP rate |
| `LEARNING_PHASE_NOISE` | Threshold rule, consistent score, 3+ prior cases — rule may need tuning |
| `NEEDS_INVESTIGATION` | Spike or escalating score with no mitigating context |

### `exa case outcome`

Track and record analyst decisions on qualified cases. Every `qualify` run is logged automatically.

```bash
exa case outcome list                                 # all logged qualifications + current outcome
exa case outcome sync                                 # auto-fill outcomes for closed cases from API
exa case outcome resolve C-1042 --outcome fp          # manually record: tp | fp | noise | duplicate
```

### `exa case baseline`

Pull historical closed cases, compute per-rule and per-entity false-positive rates, and write a calibration cache that improves future `qualify` verdicts.

```bash
exa case baseline                                     # default 90-day lookback, LTS-capped
exa case baseline --lookback 60
exa case baseline --report                            # show calibration table: rule | TP | FP | FP rate
exa case baseline --json
```

The lookback is automatically capped to the tenant's licensed LTS retention window (`GET /health-consumption/v1/consumption/lts`) — no hardcoded limits.

### `exa detection`

Export, import, and manage analytics (UEBA) rules. Useful for backups, cross-tenant migration, and auditing enabled/disabled state.

```bash
# List — table view
exa detection list                                    # first 100 rules
exa detection list --status enabled                   # enabled only
exa detection list --status enabled --limit 0         # all enabled rules
exa detection list --name "Brute Force"               # name substring filter

# List — export formats
exa detection list --status enabled --limit 0 --csv                         # CSV to stdout
exa detection list --status enabled --limit 0 --csv --output enabled.csv    # CSV to file
exa detection list --status enabled --limit 0 --json                        # JSON to stdout
exa detection list --limit 0 --json --output all_rules.json                 # JSON to file

# Single rule
exa detection get <rule-id>

# Enable / disable
exa detection enable <rule-id>
exa detection disable <rule-id>

# Export / import / diff bundles
exa detection export                                  # all rules → stdout (pipeable)
exa detection export --out rules-backup.json
exa detection import rules-backup.json
exa detection import rules-backup.json --overwrite
exa detection diff bundle-a.json bundle-b.json
```

The `list` table auto-displays **Type** and **Families** columns when the API returns them, and prints a summary of distinct rule types found. The `--csv` output includes all available fields: `id, name, isEnabled, severity, type, families, author, createdAt, updatedAt, description`.

### `exa search`

```bash
exa search 'activity_type:"authentication"' --lookback 7 --limit 500
exa search 'user:"admin"' --tenant sademodev22
```

> Exabeam New-Scale uses SQL-style EQL (SELECT / WHERE / GROUP-BY / ORDER-BY). Pipe-based syntax is not supported.

### `exa frameworks`

```bash
exa frameworks    # list all available compliance frameworks with testable control counts
```

## How It Works

### SPL → Sigma → EQL Pipeline

Splunk SPL and Exabeam EQL are fundamentally different languages. Rather than a lossy direct translation, exa-tools routes through [Sigma](https://github.com/SigmaHQ/sigma) as a structured intermediate format:

```
Splunk SPL search
    ↓  exa/splunk/parser.py      — extract index, fields, pipeline stages
    ↓  exa/splunk/to_sigma.py    — build Sigma rule dict with logsource + detection
    ↓  exa/sigma/converter.py    — map Sigma fields → CIM2, build EQL query
    ↓
Exabeam EQL correlation rule  →  deploy via API
```

This means field mapping reuses the community-maintained Sigma field vocabulary, wildcard values become proper Sigma modifiers (`|contains`, `|endswith`, `|startswith`), and negations become proper `filter` blocks. Pipeline stages that can't be represented in EQL (`stats`, `eval`, `lookup`, etc.) are inventoried as warnings rather than silently dropped.

### Field Oracle

<img src="docs/oracle.svg" width="180" align="right" alt="Field Oracle"/>

The Field Oracle is the translation engine at the heart of the converter. Rather than relying on hand-maintained field maps or incomplete documentation, it reads Exabeam's own parser definitions directly.

`exa update` walks **8,278 parser files** across 269 vendors in the `Content-Library-CIM2/DS/` directory and builds a local index:

- **4,258 raw → CIM2 field mappings** extracted from parser regex capture groups and JSON path definitions
- **25 activity types** indexed with their confirmed field sets
- **269 vendors** — Code42, Digital Guardian, Microsoft O365, Cisco, and hundreds more

Every field the converter resolves is assigned a confidence level:

| Confidence | Meaning |
|---|---|
| `oracle` | Field confirmed in DS/ parser definitions for this vendor/activity_type — no warning |
| `schema` | Field in CIM2_FIELD_MAP but not confirmed in DS/ for this specific source |
| `passthrough` | No mapping found — field not in CIM2 for this vendor |

The oracle refreshes automatically every time you run `exa update`. When Exabeam adds new parser fields, the converter picks them up on the next update — no code changes needed.

### Field Oracle Concept Resolution (Compliance)

The Field Oracle also powers **tenant-aware compliance auditing**. Each compliance control is annotated with one or more semantic **concepts** (e.g. `GROUP_MANAGEMENT`, `PERMISSION_CHANGE`) that map to specific `activity_type` values. At audit time, the **ConceptResolver** queries the tenant for all activity types seen in the lookback window, then dynamically builds EQL filters using only the types confirmed present in that environment.

```
Control concepts  →  ConceptResolver (filters to tenant-active types)
                  →  ComplianceQueryBuilder (builds EQL filter string)
                  →  search_events (live query against tenant)
```

This means compliance queries automatically adapt to each customer's log sources without manual tuning per tenant. If a log source isn't connected (e.g. physical access control), the control fails with a clear gap — not a false negative from a wrong query.

## Features

- **Dataflow hot key detection and remediation** (`exa hotkey`) — analyze the Network Zones context table for coarse IP groupings that cause Dataflow worker imbalance; scan real traffic to confirm active hot keys; expand coarse zone entries to /24 granularity with automatic rollback support
- **Self-update** (`exa update self`) — `git pull` + `uv sync` in one command; keeps the local install current without leaving the terminal
- **Context table full CRUD** (`exa tables`) — create tables from CSV with auto-derived schema; delete tables; list, upload (append or replace), and export records; all with 20k-record batching
- **Sigma rule conversion** — convert SigmaHQ YAML rules to Exabeam EQL correlation rules with CIM2 field mapping
- **Splunk SPL conversion** — SPL→Sigma→EQL pipeline; batch from Excel or inline one-off via `exa splunk one`
- **One-step deployment** — convert and deploy Sigma or Splunk rules to your tenant in a single command
- **Field Oracle** — 4,258 raw→CIM2 mappings from 8,278 parser files; confidence-based field resolution for rules and compliance
- **CIM2 reference data** — sync Content-Library-CIM2 and SigmaHQ repos locally
- **Threat Center — cases** — search, get, update, and create cases with EQL filtering and rich table output
- **Threat Center — alerts** — search, get, and update alerts; priority colour coding; `--json` for pipeline use
- **Case triage (`exa case qualify`)** — structured analyst triage: rule definition, entity history, context table membership, score trend, IP annotation, and a four-outcome verdict
- **Outcome tracking** — every `qualify` run is logged; `exa case outcome sync` back-fills analyst decisions from closed cases
- **Historical calibration (`exa case baseline`)** — LTS-aware lookback capped to licensed retention; per-rule and per-entity FP rates feed back into future verdicts
- **Detection Management** — export, import, and diff analytics (UEBA) rules across tenants
- <img src="docs/icons/aillm.svg" height="16" align="absmiddle"/> **AI/LLM domain sync** — sync 6 reference tables for AI/LLM threat detection
- <img src="docs/icons/compliance.svg" height="16" align="absmiddle"/> **Compliance auditing** — automated evidence collection across 11 frameworks with tenant-aware query resolution, HTML + PDF report output
- **Event search** — EQL query interface with time range and result limiting
- **Credential management** — tenant profiles stored in Windows Credential Manager via keyring

## Splunk Converter

The SPL→Sigma→EQL pipeline is covered in [How It Works](#how-it-works) above. Two operational notes specific to Splunk conversion:

- The intermediate Sigma YAML is preserved in the output file for audit and review
- All converted rules land as `deploy_ready: Needs review` — SPL→EQL is lossy by design and requires human sign-off before enabling

### Supported Indexes

| Splunk Index | Data Source | Default activity_type |
|---|---|---|
| `c42` | Code42 / Incydr DLP | `file-write` |
| `c42` + `c42-alerts` | Code42 risk alerts | `rule-trigger` |
| `c42` + `c42-file-exposure` | Code42 file exposure | `file-write` |
| `ips` | Cisco Firepower IPS | `rule-trigger` |
| `o365` | Microsoft O365 | `app-activity` |
| `fireamp_stream` | Cisco Secure Endpoint | `rule-trigger` |
| `dg` | Digital Guardian DLP | `file-write` |
| `ad` | Active Directory / Sysmon | `process-create` |
| `docexchange` | Document Exchange | `file-write` |
| `plminfoexchangelogs` | Agile PLM Info Exchange | `app-activity` |

### All Converted Rules

- Named `[Splunk] <title>` — enables bulk management via `get_correlation_rules(name="[Splunk]*")`
- Named `[Sigma] <title>` — for Sigma-converted rules, `get_correlation_rules(name="[Sigma]*")`
- Severity defaults to `medium` — adjust before deploying
- `deploy_ready: Needs review` — always for Splunk; SPL→EQL translation requires human sign-off

## Internal Features

Additional features are available for Exabeam employees.

## Development

```bash
uv sync                    # install deps
uv run pytest -v           # run tests (533 passing)
uv run pytest tests/test_sigma.py::TestProxyFieldMappings  # single test class
uv run ruff check exa/     # lint

# Enable pre-commit help tests (one-time setup)
git config core.hooksPath .githooks
```

## License

MIT

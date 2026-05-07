# exa-tools

![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![uv](https://img.shields.io/badge/package%20manager-uv-blueviolet)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Platform: Exabeam NSA/SIEM](https://img.shields.io/badge/platform-Exabeam%20New--Scale%20Analytics%20%28NSA%29%20%2F%20SIEM-orange)
![Tests](https://img.shields.io/badge/tests-326%20passing-brightgreen)

Python automation toolkit for Exabeam New-Scale Analytics (NSA) / SIEM. Converts Splunk SPL searches and SigmaHQ detection rules to Exabeam EQL correlation rules, deploys them to your tenant, and manages context tables — all from the command line.

![Pipeline Animation](docs/pipeline-animation.svg)

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

## Features

- **Sigma rule conversion** — convert SigmaHQ YAML rules to Exabeam EQL correlation rules with CIM2 field mapping
- **Splunk SPL conversion** — SPL→Sigma→EQL pipeline; batch from Excel or inline one-off via `exa splunk one`
- **One-step deployment** — convert and deploy Sigma or Splunk rules to your tenant in a single command
- **Field Oracle** — 4,258 raw→CIM2 mappings from 8,278 parser files; confidence-based field resolution
- **CIM2 reference data** — sync Content-Library-CIM2 and SigmaHQ repos locally
- **Context table management** — CRUD operations with 20k batch support and pagination
- **AI/LLM domain sync** — sync 6 reference tables for AI/LLM threat detection
- **Compliance auditing** — automated evidence collection across 11 frameworks (NIST CSF, CMMC L2, etc.)
- **Event search** — EQL query interface with time range and result limiting
- **Credential management** — tenant profiles stored in Windows Credential Manager via keyring

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

### `exa configure`

Interactive setup: enter your tenant FQDN, client ID, and client secret. Tests the connection, saves credentials to keyring, and optionally downloads CIM2/SigmaHQ reference data.

### `exa update`

```bash
exa update           # clone/pull CIM2 + SigmaHQ repos, build Field Oracle cache
exa update --check   # show current commit SHAs without pulling
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

```bash
exa compliance audit --framework "NIST CSF v2.0" --lookback 30
exa compliance audit --framework "NIST CSF v2.0" --output-html report.html
```

HTML reports saved to `reports/` include an executive summary, family coverage breakdown, and gap analysis.

### `exa search`

```bash
exa search 'activity_type:"authentication"' --lookback 7 --limit 500
exa search 'user:"admin"' --tenant sademodev22
```

### `exa tables`

```bash
exa tables --name "Public AI Domains and Risk"
exa tables --tenant sademodev22
```

### `exa frameworks`

```bash
exa frameworks    # list all available compliance frameworks with testable control counts
```

## Splunk Converter

### Why SPL→Sigma→EQL?

SPL is a pipeline language (filter, aggregate, join, transform). EQL is a pure filter language. A direct translation is inherently lossy.

Routing through Sigma means:
- Field mapping reuses pySigma's community-maintained CIM field vocabulary
- Wildcard values become proper Sigma modifiers (`|contains`, `|endswith`, `|startswith`)
- Negation (`field!=value`) becomes a proper Sigma `filter` block with `condition: selection and not filter`
- The intermediate Sigma YAML is preserved in output for audit and review
- All converted rules land as `deploy_ready: Needs review` — SPL→EQL is lossy by design

Pipeline stages that cannot be represented in EQL (`stats`, `eval`, `lookup`, `rex`, `spath`, `join`, etc.) are inventoried as warnings. The converted rule captures the detection filter logic — aggregation and enrichment must be handled separately in Exabeam.

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
uv run pytest -v           # run tests (326 passing)
uv run pytest tests/test_sigma.py::TestProxyFieldMappings  # single test class
uv run ruff check exa/     # lint
```

## License

MIT

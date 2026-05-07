# exa-tools

![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![uv](https://img.shields.io/badge/package%20manager-uv-blueviolet)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Platform: Exabeam NSA/SIEM](https://img.shields.io/badge/platform-Exabeam%20New--Scale%20Analytics%20%28NSA%29%20%2F%20SIEM-orange)

Python automation toolkit for Exabeam New-Scale Analytics (NSA) / SIEM.

## Features

- **Credential management** — tenant profiles stored in Windows Credential Manager via keyring
- **Sigma rule conversion** — convert SigmaHQ YAML rules to Exabeam EQL correlation rules with CIM2 field mapping
- **Splunk SPL conversion** — convert Splunk searches to Exabeam EQL via a SPL→Sigma→EQL pipeline; batch from Excel or inline one-off
- **One-step deployment** — convert and deploy Sigma or Splunk rules to your tenant in a single command
- **CIM2 reference data** — sync ExabeamLabs Content-Library-CIM2 and new-scale-content-hub repos locally for field validation
- **Context table management** — CRUD operations with 20k batch support and pagination
- **AI/LLM domain sync** — sync 6 reference tables for AI/LLM threat detection
- **Compliance auditing** — automated evidence collection across 11 frameworks (NIST CSF, CMMC L2, etc.)
- **Event search** — EQL query interface with time range and result limiting

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

After cloning, install `exa` as a global command:

```bash
uv tool install -e .       # install exa globally from local source
exa configure              # set up tenant credentials (stored in keyring)
exa update                 # download CIM2 + SigmaHQ reference data
```

## Quick Start

```bash
exa configure                                    # set up tenant + credentials
exa update                                       # download CIM2 reference data
exa config set sigma.rules-dir /path/to/sigma    # set default Sigma rules directory
exa sigma convert --rule proc_creation_powershell_encoded.yml
```

## Commands

### `exa configure`

Interactive setup: enter your tenant FQDN (e.g. `sademodev22.exabeam.cloud` or `csdevfusion.use1.exabeam.cloud`), client ID, and client secret. The region is resolved automatically from the FQDN. Tests the connection, saves credentials to keyring, and optionally downloads CIM2/SigmaHQ reference data.

### `exa update`

```bash
exa update           # clone/pull CIM2 + content-hub + SigmaHQ repos, parse to ~/.exa/cache/
exa update --check   # show current commit SHAs without pulling
```

Downloads [Content-Library-CIM2](https://github.com/ExabeamLabs/Content-Library-CIM2), [new-scale-content-hub](https://github.com/ExabeamLabs/new-scale-content-hub), and [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma), then parses data into JSON cache files for field validation and rule browsing.

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

Converts Sigma YAML rules to Exabeam EQL and displays a results table with deploy-readiness assessment. With `--deploy`, creates correlation rules on the tenant via the API.

Short alias: `exa sc`

### `exa sigma deploy`

```bash
exa sigma deploy --rule proc_creation_powershell_encoded.yml
exa sigma deploy --rule proc_creation_powershell_encoded.yml --tenant sademodev22
```

Convert and deploy a single rule in one step.

Short alias: `exa sd`

### `exa sigma browse`

```bash
exa sigma browse --category process_creation --level high
exa sigma browse --tag t1059 --product windows
exa sigma browse --search "powershell"
```

Browse SigmaHQ community rules from the local index (built by `exa update`). Filter by category, product, level, ATT&CK tag, or keyword search.

### `exa compliance audit`

```bash
exa compliance audit --framework "NIST CSF v2.0" --lookback 30
exa compliance audit --framework "NIST CSF v2.0" --output-html report.html
```

Run a compliance gap analysis audit. HTML reports are saved to `reports/` by default and include an executive summary, family coverage breakdown, and gap analysis.

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

The Splunk converter translates Splunk SPL searches into Exabeam EQL correlation rules using a **SPL → Sigma → EQL** pipeline.

### Why SPL→Sigma→EQL?

Splunk SPL and Exabeam EQL are fundamentally different languages — SPL is a pipeline language (filter, aggregate, join, transform) while EQL is a pure filter language. A direct SPL→EQL translation is inherently lossy and requires maintaining a hand-built field map.

The SPL→Sigma→EQL approach routes through Sigma as a structured intermediate format, which means:
- Field mapping reuses the pySigma Splunk backend's community-maintained CIM mappings (4+ years, actively maintained by the Sigma project creators)
- Wildcard values become proper Sigma modifiers (`|contains`, `|endswith`, `|startswith`) which the Sigma→EQL pipeline handles correctly
- Negation (`field!=value`) becomes a proper Sigma `filter` block
- The intermediate Sigma YAML is preserved in the output for audit and debugging
- All converted rules land as `deploy_ready: Needs review` — SPL→EQL is lossy by design and requires human sign-off

Pipeline stages that cannot be represented in EQL (`stats`, `eval`, `lookup`, `rex`, `spath`, `join`, etc.) are inventoried and listed as warnings. The converted rule captures the *detection filter* logic — the aggregation and enrichment steps must be handled separately in Exabeam through risk scoring or rule sequences.

### `exa splunk convert`

```powershell
# Batch convert an Excel file with 'title' and 'search' columns
exa splunk convert searches.xlsx

# Show all per-rule warnings
exa splunk convert searches.xlsx --verbose

# Custom output file
exa splunk convert searches.xlsx --output rules.json
```

Outputs a rich table showing each rule's index, activity type, EQL preview, warning count, and deploy status. Saves an API-ready JSON file of all payloads.

### `exa splunk one`

Convert a single SPL search inline — no Excel file needed. Useful for testing, one-off conversions, or exploring how a specific search converts.

```powershell
# Basic conversion
exa splunk one 'index=c42 severity="High" | stats count by username'

# With a custom title
exa splunk one 'index=o365 Operation=Send' --title "O365 Outbound Email"

# Save payload to JSON for deployment
exa splunk one 'index=fireamp_stream severity="High"' --title "AMP Alert" -o rule.json

# Print raw JSON payload
exa splunk one 'index=ad CommandLine="*mimikatz*"' --json
```

### `exa splunk deploy`

```powershell
# Dry run — preview without API calls
exa splunk deploy rules.json --dry-run

# Deploy (rules created disabled by default)
exa splunk deploy rules.json

# Deploy to a specific tenant
exa splunk deploy rules.json --tenant sademodev22
```

All rules are created **disabled** by default. Validate the EQL in the Exabeam UI before enabling.

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
- Severity defaults to `medium` — adjust before deploying
- `deploy_ready: Needs review` — always; SPL→EQL translation is lossy and requires human sign-off

## Sigma Converter

The Sigma converter translates [SigmaHQ](https://github.com/SigmaHQ/sigma) YAML detection rules into Exabeam EQL correlation rules.

- **CIM2 field mapping** — 43 Sigma fields mapped to Exabeam CIM2 schema (process, network, file, registry, web proxy, DNS, cloud/AWS, auth)
- **Activity type hints** — logsource category/service mapped to CIM2 activity_type values, validated against bundled snapshot or CIM2 cache
- **Modifier support** — `contains`, `endswith`, `startswith`, `re`, `all`; unsupported modifiers (`base64`, `wide`, `cidr`, etc.) emit warnings and fall back to exact match
- **Deploy-ready assessment** — each rule rated Yes / Needs review / No based on unmapped fields and warning count
- **MITRE enrichment** — ATT&CK tags extracted and packed into the rule description (API does not support tag fields)
- **`[Sigma]` prefix** — all converted rules are prefixed with `[Sigma]` for bulk management via `get_correlation_rules(name="[Sigma]*")`

## Internal Features

Additional features are available for Exabeam employees.

## Development

```bash
uv sync                    # install deps
uv run pytest -v           # run tests
uv run pytest tests/test_sigma.py::TestProxyFieldMappings  # single test
uv run ruff check exa/     # lint
```

## License

MIT

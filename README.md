# exa-tools

![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![uv](https://img.shields.io/badge/package%20manager-uv-blueviolet)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Platform: Exabeam NSA/SIEM](https://img.shields.io/badge/platform-Exabeam%20New--Scale%20Analytics%20%28NSA%29%20%2F%20SIEM-orange)

Python automation toolkit for Exabeam New-Scale Analytics (NSA) / SIEM.

## Features

- **Credential management** — tenant profiles stored in Windows Credential Manager via keyring
- **Sigma rule conversion** — convert SigmaHQ YAML rules to Exabeam EQL correlation rules with CIM2 field mapping
- **One-step deployment** — convert and deploy Sigma rules to your tenant in a single command
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

## Quick Start

```bash
exa configure                                    # set up tenant + credentials
exa update                                       # download CIM2 reference data
exa config set sigma.rules-dir /path/to/sigma    # set default Sigma rules directory
exa sigma convert --rule proc_creation_powershell_encoded.yml
```

## Commands

### `exa configure`

Interactive setup: tenant name, region selection (10 regions), client ID, client secret (hidden input). Tests the connection, saves credentials to keyring, and optionally downloads CIM2 reference data.

### `exa update`

```bash
exa update           # clone/pull CIM2 + content-hub repos, parse to ~/.exa/cache/
exa update --check   # show current commit SHAs without pulling
```

Downloads [Content-Library-CIM2](https://github.com/ExabeamLabs/Content-Library-CIM2) and [new-scale-content-hub](https://github.com/ExabeamLabs/new-scale-content-hub), then parses markdown tables into JSON cache files for field and activity_type validation.

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

### `exa search`

```bash
exa search 'activity_type:"authentication"' --url $URL --client-id $ID --lookback 7 --limit 500
```

### `exa audit`

```bash
exa audit NIST_CSF --url $URL --client-id $ID --lookback 30
```

### `exa tables`

```bash
exa tables --url $URL --client-id $ID --name "Public AI Domains and Risk"
```

### `exa frameworks`

```bash
exa frameworks    # list all available compliance frameworks with testable control counts
```

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

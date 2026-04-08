# exa-tools

Python toolkit for Exabeam New-Scale SIEM automation.

## Install

```bash
uv sync          # install deps into .venv
uv run exa --help
```

## Quick Start

```python
from exa.client import ExaClient
from exa.context import get_tables
from exa.search import search_events

with ExaClient(base_url, client_id, client_secret) as exa:
    # List context tables
    tables = get_tables(exa)

    # Search events
    events = search_events(exa, 'activity_type:"authentication"', lookback_days=7)

    # Sync AI/LLM context tables
    from exa.aillm import sync_aillm_context_tables
    sync_aillm_context_tables(exa)

    # Run a compliance audit
    from exa.compliance import run_compliance_audit
    report = run_compliance_audit(exa, "NIST_CSF", lookback_days=30)
```

## CLI

```bash
exa auth --url https://api.us-west.exabeam.cloud --client-id $ID
exa tables --url $URL --client-id $ID
exa sync-aillm --url $URL --client-id $ID
exa audit NIST_CSF --url $URL --client-id $ID --lookback 30
exa search 'activity_type:"authentication"' --url $URL --client-id $ID
exa frameworks
```

## Modules

| Module | Description |
|--------|-------------|
| `exa.client` | ExaClient with retry, auto-refresh, batch helpers |
| `exa.context` | Context table CRUD (20k batch, pagination) |
| `exa.aillm` | AI/LLM domain sync (6 tables, reference data) |
| `exa.compliance` | Identity sync, audit engine, 11 frameworks |
| `exa.search` | Event search with EQL |
| `exa.correlation` | Correlation rule management |
| `exa.detection` | Detection/analytics rule management |
| `exa.platform` | Tenant info, API keys, roles, users |
| `exa.internal` | Internal tier gating (`@require_internal`) |

## API Quirks

- Table name: "Public AI Domains and Risk" (no trailing s)
- `addRecords` is additive -- use `operation="replace"` or check existing records
- `follow_redirects=True` for http:// redirect on table creation
- DirectMap key priority: `u_account > u_user > username > hostname > ip > key`
- EXA-CONTEXT-SCHEMA-35: attribute display names are globally scoped
- Token TTL: 14400s, auto-refresh 60s before expiry
- 1s sleep between table writes in sync loops
- "hippa" is Exabeam's OOTB typo in compliance schema (not "hipaa")

## Tests

```bash
uv run pytest -v
```

# CLAUDE.md - exa-tools

## Project

Python 3.12 toolkit for Exabeam New-Scale SIEM automation. Ported from the PowerShell reference at E:\LogRhythm-Tools\SIEM.Tools (v2.0-dev).

## Stack

- Python 3.12, uv, hatchling build
- httpx (HTTP client with custom retry transport)
- rich (console output), typer (CLI), pydantic v2 (models)
- pytest + pytest-httpx (testing)

## Architecture

- All API modules are standalone functions taking `ExaClient` as first arg
- ExaClient uses `_RetryTransport` (429/503, exponential backoff, Retry-After)
- Token auto-refresh 60s before 14400s TTL expiry
- Data files bundled via `importlib.resources.files()` with utf-8-sig encoding
- `@require_internal` decorator for employee-tier features (lazy detection)

## Key Commands

```bash
uv sync                    # install deps
uv run pytest -v           # run tests
uv run exa --help          # CLI
uv run ruff check exa/     # lint
```

## Test Tenant

- Base URL: https://api.us-west.exabeam.cloud
- ClientId: cSrls2MN6y4pzTLj4C4Q0YwtvL2ojp6CYNAMom6mxNkwVTzD
- Secret: interactive only, never stored in code

## Known Quirks

- "Public AI Domains and Risk" (no trailing s)
- addRecords is additive (check existing or use replace)
- EXA-CONTEXT-SCHEMA-35: attribute displayNames globally scoped
- "hippa" = Exabeam's OOTB typo for HIPAA
- 1s sleep between table writes
- DirectMap key priority: u_account > u_user > username > samaccountname > hostname > host > ip > key

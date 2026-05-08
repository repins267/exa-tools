# exa-tools Code Style Guide

This document describes the coding conventions used throughout exa-tools.
Consistency with existing code matters more than personal preference.
When in doubt, read a nearby file and match it.

Linting is enforced by **ruff** (`uv run ruff check exa/`). Style issues that
ruff can catch are not repeated here — this guide covers conventions that a
linter cannot enforce.

---

## File Structure

Every Python module follows this top-to-bottom order:

```python
"""One-line module summary.

Optional extended description. Include the API base path for modules
that own a specific endpoint family.

API base path: /context-management/v1/
"""

from __future__ import annotations           # always first

import stdlib_module                         # stdlib imports
from stdlib_module import specific_name

from third_party import something            # third-party imports

if TYPE_CHECKING:                            # TYPE_CHECKING guard for
    from exa.client import ExaClient         # forward references only

from exa.other_module import something       # internal imports

# Module-level constants
_PRIVATE_CONSTANT = 42
PUBLIC_CONSTANT = "value"
```

### Module docstrings

Every file gets a module docstring. For API modules include the base path.
For CLI modules list the commands the module provides:

```python
"""CLI commands for analyst case triage and qualification.

  exa case qualify  <case-number>  — full qualification report
  exa case show     <case-number>  — case details + Nova summary
"""
```

---

## Naming

| Thing | Convention | Example |
|---|---|---|
| Functions | `snake_case` | `analyze_zones()` |
| Private functions | `_snake_case` | `_detect_schema()` |
| Classes / dataclasses | `PascalCase` | `ZoneRisk`, `ExaClient` |
| Constants (module-level) | `UPPER_SNAKE_CASE` | `_BATCH_SIZE`, `NETWORK_ZONES_TABLE` |
| Private constants | `_UPPER_SNAKE_CASE` | `_COARSE_PREFIX_MAX` |
| Type aliases | `PascalCase` | `RecordList = list[dict[str, Any]]` |
| CLI apps | `snake_case` ending in `_app` | `hotkey_app`, `case_app` |

Private names (`_prefix`) are module-internal. Do not import them from outside
the module — if you need them externally, promote them to public.

---

## Type Hints

Type hints are **required** on all function parameters and return values.
No exceptions. Use Python 3.12+ syntax — no `Optional[X]`, use `X | None`.

```python
# ✓ correct
def get_tables(
    client: ExaClient,
    *,
    name: str | None = None,
    exact: bool = False,
) -> list[dict[str, Any]]:

# ✗ wrong — missing return type, old Optional syntax
def get_tables(client, name=None, exact=False):
def get_tables(client: ExaClient, name: Optional[str] = None):
```

Use `from __future__ import annotations` at the top of every file so forward
references resolve lazily. This allows `ExaClient` to be referenced in type
hints without importing it at runtime (use `TYPE_CHECKING` guard instead).

---

## Functions

### API modules — standalone functions

All API functions take `ExaClient` as their **first positional argument**.
No methods on `ExaClient` beyond `_request`, `get`, `post`, `put`, `delete`.

```python
# ✓ correct — standalone function, ExaClient first
def get_table(client: ExaClient, table_id: str) -> dict[str, Any]:
    return client.get(f"/context-management/v1/tables/{table_id}")

# ✗ wrong — method on ExaClient
class ExaClient:
    def get_table(self, table_id: str) -> dict[str, Any]: ...
```

Keyword-only arguments (after `*`) for optional parameters keep call sites
readable and prevent accidental positional misuse:

```python
def analyze_zones(
    client: ExaClient,
    *,
    ip_field: str | None = None,
    name_field: str | None = None,
) -> list[ZoneRisk]:
```

### One function per file — preferred, not required

For modules that own a single operation, one function per file is preferred.
Group closely related small helpers (private `_` functions) in the same file
as the public function they support.

### Docstrings

Use a single-line docstring for simple functions. Use a multi-line docstring
when the behaviour needs explanation, the parameters are non-obvious, or there
are important edge cases:

```python
def get_table(client: ExaClient, table_id: str) -> dict[str, Any]:
    """Get a single context table by ID."""

def add_records(
    client: ExaClient,
    table_id: str,
    data: list[dict[str, Any]],
    *,
    operation: str = "append",
) -> Any:
    """Add records to a context table with automatic batching (20k per request).

    Note: addRecords is additive — re-runs create duplicates. Use operation="replace"
    or check existing records first for idempotency.
    """
```

---

## Dataclasses

Use `@dataclass` for structured return values and data transfer objects.
Prefer dataclasses over plain dicts for anything that crosses a module boundary.

```python
from dataclasses import dataclass
from typing import Any

@dataclass
class ZoneEntry:
    key: str            # raw record key value (e.g. "10.0.0.0/8")
    zone_name: str      # zone label value (e.g. "Net_10_0_0_0")
    ip_field: str       # column id holding the IP/subnet
    name_field: str     # column id holding the zone label
    raw: dict[str, Any] # original full record dict (for rollback)
```

Inline comments on fields are encouraged when the meaning is not obvious from
the name alone.

---

## Imports

### In API modules

Standard top-level imports. Use `TYPE_CHECKING` to avoid circular imports
when importing `ExaClient`:

```python
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient
```

### In CLI command functions

All non-trivial imports go **inside the command function body** to avoid
circular imports. Top-level imports in CLI files are limited to `typer`,
`rich`, and stdlib:

```python
@hotkey_app.command("analyze")
def analyze(...) -> None:
    """Classify Network Zones table entries by hot key risk."""
    from rich.table import Table                        # ← inside body
    from exa.hotkey.analyze import analyze_zones        # ← inside body
    from exa.config import get_default_tenant           # ← inside body

    client = _make_client(tenant)
    try:
        ...
    finally:
        client.close()
```

---

## CLI Commands

### Sub-app pattern

Each command group lives in its own file under `exa/cli/` and exports a
`typer.Typer` instance named `<group>_app`:

```python
hotkey_app = typer.Typer(
    name="hotkey",
    help="Analyze and fix Dataflow hot key risk in Network Zones.",
    no_args_is_help=True,
)
```

Register in `exa/cli/app.py`:

```python
# -- HotKey -------------------------------------------------------------------
from exa.cli.hotkey import hotkey_app  # noqa: E402
app.add_typer(hotkey_app)
```

### Flag conventions

Use `Annotated` for all option definitions. Keyword-only flags use
`typer.Option`, positional arguments use `typer.Argument`:

```python
from typing import Annotated
import typer

@hotkey_app.command("expand")
def expand(
    tenant: Annotated[str | None, typer.Option("--tenant", "-t", help=_TENANT_HELP)] = None,
    zone: Annotated[str | None, typer.Option("--zone", help="Zone name to expand")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run/--no-dry-run")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
```

Boolean flags use the `--flag/--no-flag` paired syntax.
The `--json` flag variable is named `as_json` to avoid shadowing the stdlib.

### Client lifecycle

Every command that touches the API wraps the client in `try/finally`:

```python
client = _make_client(tenant)
try:
    result = do_something(client, ...)
finally:
    client.close()
```

---

## Console Output

Use `rich.console.Console` for all terminal output. Never use bare `print()`.

```python
from rich.console import Console
console = Console()

console.print("✓ Expanded 3 zones", style="green")
console.print("✗ Table not found", style="red")
console.print("  Manifest written to ~/.exa/hotkey-rollback/", style="dim")
```

### Output mode separation

When a command supports `--json`, direct progress/status messages to **stderr**
so stdout stays clean for piping:

```python
err = Console(stderr=True)

if as_json:
    err.print("  [1/3] Analyzing...", style="dim")   # stderr — safe to pipe
else:
    console.print("  [1/3] Analyzing...", style="dim") # stdout — terminal use
```

### Exit codes

- `0` — success (including "nothing to do")
- `1` — any error (table not found, API failure, safety cap hit, bad input)

Use `raise typer.Exit(1)` (not `sys.exit(1)`) so typer can clean up properly.

---

## Error Handling

Raise from the `exa.exceptions` hierarchy for library code:

```python
from exa.exceptions import ExaConfigError, ExaAPIError

raise ExaConfigError("No credentials found for tenant 'foo'. Run 'exa configure'.")
```

In CLI commands, catch expected errors, print a user-facing message, and exit:

```python
try:
    result = analyze_zones(client)
except ValueError as exc:
    console.print(f"✗ {exc}", style="red")
    raise typer.Exit(1)
```

Never swallow exceptions silently. Never use bare `except:` or `except Exception:`.

---

## EXA-VERIFIED vs EXA-UNVERIFIED

These two states define the verification contract for every field name,
endpoint path, response structure, and API assumption in the codebase.

### The standard: EXA-VERIFIED (implicit)

Code without an annotation is held to the **verified** standard — meaning it
has been confirmed against at least one of:

1. A live API call against a real tenant (sademodev22 or equivalent)
2. `exa/sigma/converter.py` fieldMap — battle-tested field mappings
3. CIMLibrary `Fields_Descriptions.md` — canonical CIM2 field names
4. `Content-Library-CIM2/DS/` — `activity_type` values per vendor
5. `new-scale-content-hub` Correlation-Rules/ or Searches/ — confirmed EQL

If you write it without the annotation, you are asserting it is confirmed.

### EXA-UNVERIFIED (explicit annotation)

When something cannot be confirmed before submission, annotate it:

```python
# EXA-UNVERIFIED: endpoint path not confirmed live
response = client.get("/detection-management/v1/analytics-rules")

field_value = row.get("app")  # EXA-UNVERIFIED: 'app' not in CIM2 reference

count = row.get("_count")  # EXA-UNVERIFIED: group_by count field name — verify
                           # against sademodev22 before releasing scan.py
```

The annotation must include a reason — what specifically is unconfirmed and
what would confirm it. A bare `# EXA-UNVERIFIED` with no explanation is not
acceptable.

### Resolving EXA-UNVERIFIED

When you confirm an unverified item:

1. Remove the `# EXA-UNVERIFIED` annotation from the code.
2. Update the relevant section in `CLAUDE.md`:
   - Confirmed field → add to the verified CIM2 fields list.
   - Confirmed endpoint → add to the API Reference section.
   - Confirmed quirk → add to Known API Defects if relevant.
3. Note the confirmation in your PR description.

### Conflict between sources

If two reference sources disagree (docs say one field name, live API returns
another), **do not silently pick one**. Flag the conflict explicitly:

```python
# EXA-UNVERIFIED: docs say 'numRecords' but live API returns 'totalItems'
# Using 'totalItems' per live observation on sademodev22 (commit a43ddb5).
# See CLAUDE.md Known API Defects.
count = table.get("totalItems")
```

Document the conflict in `CLAUDE.md` under **Known API Defects**.

---

## Constants and Magic Numbers

Name every magic number. A bare `20_000` in a batch loop is not obvious;
`_BATCH_SIZE = 20_000` is:

```python
_BATCH_SIZE = 20_000
_COARSE_PREFIX_MAX = 16   # prefix_len ≤ 16 → COARSE (≥65k addresses)
_DEFAULT_THRESHOLD = 500  # distinct IPs per zone → HOT_KEY_RISK
```

---

## Tests

Test files live in `tests/` and are named `test_<module>.py`.

### Pure unit tests

For functions with no API calls, test the logic directly:

```python
def test_classify_coarse():
    risk, prefix_len, cardinality = _classify_zone("10.0.0.0/8")
    assert risk == "COARSE"
    assert prefix_len == 8
    assert cardinality == 16_777_216
```

### HTTP-mocked tests

Use the `exa` and `mock_auth` fixtures from `tests/conftest.py`:

```python
BASE_URL = "https://api.us-west.exabeam.cloud"

def test_get_tables_returns_list(exa, mock_auth):
    mock_auth.add_response(
        url=f"{BASE_URL}/context-management/v1/tables",
        method="GET",
        json=[{"id": "t1", "name": "Network Zones"}],
    )
    result = get_tables(exa)
    assert result[0]["id"] == "t1"
```

### What to test

- Happy path: expected inputs produce expected outputs.
- Edge cases: empty lists, `None` values, zero counts.
- Error paths: `ValueError` on bad input, `ExaConfigError` on missing config.
- API contract: correct endpoint called, correct request body sent.

Do not mock things that don't need mocking. Test pure logic with plain
assertions — no HTTP mock needed for functions that never call the API.

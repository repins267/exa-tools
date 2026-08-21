# Contributing to exa-tools

exa-tools uses a single `main` branch. **`main` is a protected branch: direct
pushes are rejected — every change lands through a Pull Request**, and the
required **"Heuristic Rules & Safety Verification"** status check must be green
before a PR can merge. Work on a feature branch (`fix/…`, `feat/…`), push it,
and open a PR. Contributors are expected to be familiar with Git, GitHub flow,
and how to fork a repository and submit a PR.

---

## Commits

> **Golden Rule: One change, one commit.**

- Commits should be **atomic** — an indivisible change that succeeds entirely
  or fails entirely, with no partial states left behind.
- Each commit should represent a single piece of functionality that can be
  replayed cleanly against a specific set of premises.
- A commit should be revertable (`git revert`) without causing side effects or
  conflicts in unrelated parts of the codebase.
- Write simple, descriptive commit messages in the imperative mood:
  `Add exa hotkey analyze command` not `added analyze`.

---

## Pull Requests

> **Golden Rule: One pull request, one concern.**

- Each PR should accomplish a clear, stated goal:
  - **Bug fixes:** What was the bug? How did you fix it?
  - **New features:** What is it? How is it used?
- A PR represents a set of changes that **together form a single high-level concern**.
- Keep PRs small — smaller PRs are easier to review, test, and merge cleanly.
- Do not include unrelated changes (whitespace fixes, variable renames, typo
  corrections) in a feature or bug-fix PR — submit those separately.
- Ensure your branch is up-to-date with `main` before opening a PR to minimise
  merge conflicts.

### Pull Request Rejection Criteria

- Malicious code.
- Code that does not follow the project's coding conventions (see below).
- Code that breaks existing passing tests.
- Code that introduces raw API calls bypassing `ExaClient` (see Critical Rules).
- Credentials, tokens, or secrets of any kind committed to the repository.
- Code without type hints on all parameters and return values.
- New commands or flags with no corresponding test in `tests/test_help.py`.
- README Commands section not updated to reflect new CLI surface.

---

## Development Setup

```bash
git clone https://github.com/repins267/exa-tools.git
cd exa-tools
uv sync                   # install all dependencies including dev group
uv run pytest -v          # run full test suite
uv run ruff check exa/    # lint
git config core.hooksPath .githooks   # enable pre-commit help tests
```

All development tooling runs through `uv`. Do not use `pip install` directly.

### Key Commands

```bash
uv sync                            # install / sync deps after pyproject.toml changes
uv run pytest -v                   # run all tests
uv run pytest tests/test_sigma.py  # run a single test file
uv run pytest -k "test_classify"   # run tests matching a name pattern
uv run ruff check exa/             # lint
uv run ruff check exa/ --fix       # auto-fix lint issues
uv run exa --help                  # run the CLI from source
```

---

## Coding Conventions

> These rules are enforced in every session. Violations block merge.

### Critical Rules (from CLAUDE.md)

:no_entry: **Never make raw `httpx` calls.** Always use `client._request()` or
the `ExaClient` convenience methods (`client.get()`, `client.post()`, etc.).
The retry transport (`_RetryTransport`) and token auto-refresh are only active
through `ExaClient`.

:no_entry: **Never store credentials.** Client ID in `CLAUDE.md` is acceptable
as a test reference. Client secrets must always be entered interactively via
`getpass` or read from environment variables at runtime. Never in code, never
in config files, never in commits.

:no_entry: **Secrets resolve from the OS credential store, never from files.**
Tokens (e.g. the simulate webhook token) resolve in this order only:
environment variable → OS keyring (`keyring.get_password`) → interactive
prompt. See `exa/cli/simulate.py:_resolve_token`. Do not add a code path that
reads a token from a config file, a dotfile, or a committed default, and do not
log a resolved token.

:no_entry: **Never promote customer-specific data or PII to shared knowledge.**
The `assess` learn loop promotes only *generic* knowledge across tenants.
Customer-specific values and anything that looks per-record (emails, long free
text, SSNs / long digit runs, "matched for … / for user …" phrasing) are
classified LOCAL and must never enter `vendor_packs.json`, the shared overlay,
or any shareable surface — customer names are scrubbed from previews by default.
The golden-corpus safety gate (auto-promote precision = 1.0, PII-withhold
recall = 1.0) exists to catch a regression here; do not weaken those thresholds
to make a change pass.

:no_entry: **`@require_internal` on every internal function.** Any function
under `exa/internal/` must have this decorator — no exceptions.

:ballot_box_with_check: **Python 3.12+ only.** No compatibility shims or
backport imports for older Python versions.

:ballot_box_with_check: **Standalone functions only.** All API functions take
`ExaClient` as their first argument. Do not add methods to `ExaClient` beyond
`_request`, `get`, `post`, `put`, `delete`.

:ballot_box_with_check: **Type hints required** on all parameters and return
values — no bare `Any` without justification.

:ballot_box_with_check: **One function per file is preferred** for API modules,
but not strictly enforced — group closely related small helpers in the same file.

:ballot_box_with_check: **All CLI command imports go inside the function body**
to avoid circular imports. See any existing command in `exa/cli/` for the
established pattern.

:ballot_box_with_check: **`_make_client(tenant)` + `try/finally client.close()`**
wrapping in every CLI command that touches the API.

### Console Output

Use `rich.console.Console` for all terminal output — never bare `print()`.

```python
from rich.console import Console
console = Console()

console.print("✓ Done", style="green")
console.print("✗ Error", style="red")
console.print("  detail text", style="dim")
```

When a command supports `--json`, emit NDJSON to **stdout** and progress
messages to **stderr** (`Console(stderr=True)`) so the output is pipeable.

### Unverified API Fields and Endpoints

When a field name, endpoint path, or response structure has not been confirmed
against the live Exabeam API, annotate it:

```python
# EXA-UNVERIFIED: endpoint path not yet confirmed live
response = client.get("/detection-management/v1/analytics-rules")
```

Do not silently assume a field name is correct. If a field cannot be verified
against `exa/sigma/converter.py` fieldMap, the CIMLibrary, or live API
inspection, add the `# EXA-UNVERIFIED` comment and flag it in the PR description.

### Batch Writes and Sleep

Include a 1-second sleep between context table write batches:

```python
import time
from exa.client import _BATCH_WRITE_SLEEP

# between batch writes
time.sleep(_BATCH_WRITE_SLEEP)
```

Do not add a `batch_write_sleep()` method to `ExaClient` — the constant is
sufficient and a new method would violate the standalone-functions rule.

---

## CI and Help Tests

Every CLI command must have a corresponding `--help` test in
`tests/test_help.py`. This test verifies:
- The command responds to `--help` with exit code 0.
- Key flags listed in the README appear in the help output.
- The command's docstring carries an `Examples:` block (the discoverability
  contract — a new command with no examples fails here).

> Help tests strip ANSI before asserting, so they are robust to colourised
> output. typer forces colour under `GITHUB_ACTIONS`/`FORCE_COLOR`, which
> fragments option names like `--check` into escape-separated tokens; do not
> reintroduce raw-`in`-`result.output` assertions without stripping.

### Doc-sync checklist — do all of these in the same PR as the change

Adding, changing, or removing a **command, flag, MCP tool, or skill** is not
"done" until every doc surface matches AND the AI-BOM is regenerated:

1. `tests/test_help.py` — add/update the command's `--help` test.
2. `README.md` — update the **Commands** section, and for tools/skills the
   **Tools table** and the **`Skills (N)`** count + named list (all CI-checked).
3. Regenerate the **AI-BOM**: `uv run security/gen_aibom.py`, then commit
   `security/aibom.cdx.json` (+ `.html`). New modules make it stale.
4. Run the doc-sync tests locally before pushing:
   `uv run pytest tests/test_doc_inventory.py tests/test_aibom.py`.

> **Trap:** the doc-sync gate (`test_doc_inventory` + `test_aibom`) runs in the
> "CI" workflow, which is **not** a required status check — a PR can merge while
> it is red, leaving `main` failing. Always run those two tests locally first.

### CI pipeline structure

- **Heuristic Rules & Safety Verification** (`ci-pipeline.yml`) — the blocking,
  **required** check. Runs the deterministic test suite plus
  `exa assess benchmark` against `tests/data/classifier_golden.jsonl`, enforcing
  the safety gates (auto-promote precision = 1.0 / leaks = 0, PII-withhold
  recall = 1.0, and the Wilson lower-bound floor that tightens as the corpus
  grows). A PR cannot merge unless this is green.
- **LLM leaderboard** (nightly, **non-blocking**) — runs the same golden corpus
  through each model backend and tracks accuracy / latency / cost. Informational;
  never gates a merge.
- **Doc-sync** (`test_doc_inventory` + `test_aibom`) — runs in the "CI" workflow
  but is **not** a required check (see the trap above).

The help + doc tests run as part of the standard suite (`uv run pytest -v`).
They act as a contract between the CLI surface and the documentation — if they
diverge, the tests fail.

---

## Testing

:ballot_box_with_check: **Every new function needs a test.** Pure logic (no
API calls) uses plain unit tests. API-touching code uses `pytest-httpx` mocks
— see `tests/conftest.py` for the `exa` and `mock_auth` fixtures.

:ballot_box_with_check: **Tests must be green before opening a PR.**
`uv run pytest -v` must pass in full with no failures or errors.

:ballot_box_with_check: **Test file naming:** `tests/test_<module>.py` matching
the module under test (e.g. `exa/hotkey/analyze.py` → `tests/test_hotkey.py`).

### Test Patterns

Pure unit test (no HTTP mock needed):
```python
def test_classify_coarse():
    risk, prefix_len, cardinality = _classify_zone("10.0.0.0/8")
    assert risk == "COARSE"
    assert prefix_len == 8
    assert cardinality == 16_777_216
```

HTTP-mocked test (use `exa` + `mock_auth` fixtures from `conftest.py`):
```python
def test_get_tables_returns_list(exa, mock_auth):
    mock_auth.add_response(
        url=f"{BASE_URL}/context-management/v1/tables",
        method="GET",
        json=[{"id": "t1", "name": "Network Zones"}],
    )
    result = get_tables(exa)
    assert result[0]["id"] == "t1"
```

---

## Quick Guidelines

:no_entry: **Only commit verified code.** Every function, field name, endpoint,
and API assumption must be confirmed — against the live API, the CIMLibrary, or
the existing `exa/sigma/converter.py` fieldMap. Anything unconfirmed must be
annotated `# EXA-UNVERIFIED` and flagged in the PR description. Code without
the annotation is held to the standard of confirmed. Submitting silent
assumptions — regardless of how the code was written — is grounds for rejection.

:heavy_check_mark: Annotate anything unconfirmed with `# EXA-UNVERIFIED` and
confirm it against the live API or reference sources before marking it resolved.
See **EXA-VERIFIED vs EXA-UNVERIFIED** in `CODESTYLE.md` for the full workflow.

:heavy_check_mark: Use `ruff` for linting before every commit. The project
targets Python 3.12, line length 100. Run `uv run ruff check exa/ --fix` to
auto-fix common issues.

:heavy_check_mark: Keep the `CLAUDE.md` up to date. If you confirm a previously
`EXA-UNVERIFIED` field or endpoint, update the relevant section. If you discover
a new API quirk, document it under **Known API Defects**.

:heavy_check_mark: Do not add new dependencies without discussion. The stack is
deliberately lean: `httpx`, `keyring`, `rich`, `typer`, `pydantic`. Heavy
dependencies (pandas, ML libraries, etc.) belong in optional extra groups, not
the main install.

:heavy_check_mark: `addRecords` is additive — re-running appends duplicates.
Always pass `operation="replace"` explicitly when replace semantics are intended,
and document the choice in a comment.

---

## Licensing

exa-tools is licensed under the MIT License — see [LICENSE](LICENSE) for details.

By submitting a Pull Request you agree to license your contribution under the
same MIT License and confirm that you have the right to do so.

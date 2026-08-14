"""Redact tenant identifiers from api-verification-results.json before commit.

`api-verification-results.json` is TRACKED in a public repository, but an audit run
records which tenant each observation came from. Tenant nicknames belong in
CLAUDE.local.md and the vault, never in the public repo (see CLAUDE.md).

The redaction map lives OUTSIDE this repo -- a script in a public repo that contains
a list of tenant names would leak exactly what it is meant to protect. Supply it via:

    $EXA_REDACTIONS  or  ~/.exa/redactions.json

    {"<tenant-nickname>": "an SA tenant", "<another>": "a US-East tenant"}

Replacements should preserve the REGION where the original named it -- region-
dependent behavior is the finding in several gap entries, and generalizing it to
"a tenant" would destroy the information.

Usage:
    uv run python scripts/sanitize_audit_artifact.py            # check only, exit 1 if dirty
    uv run python scripts/sanitize_audit_artifact.py --write    # apply and save
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

_ARTIFACT = Path(__file__).parents[1] / "api-verification-results.json"
_DEFAULT_MAP = Path.home() / ".exa" / "redactions.json"

# Hostnames of the form api.<region>.exabeam.cloud are published regional endpoints,
# not tenant identifiers, and are deliberately NOT redacted.
_ALLOWED_HOST = re.compile(r"^api\.[a-z0-9-]+\.exabeam\.cloud$")


def load_map() -> dict[str, str]:
    raw = os.environ.get("EXA_REDACTIONS")
    path = Path(raw) if raw else _DEFAULT_MAP
    if not path.exists():
        print(
            f"ERROR: no redaction map at {path}.\n"
            "Create it as {\"<tenant-nickname>\": \"<generic replacement>\"}, "
            "outside this repo.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main() -> int:
    write = "--write" in sys.argv
    if not _ARTIFACT.exists():
        print(f"ERROR: {_ARTIFACT} not found", file=sys.stderr)
        return 2

    redactions = load_map()
    text = _ARTIFACT.read_text(encoding="utf-8-sig")

    found = {name: text.count(name) for name in redactions if name in text}
    if not found:
        print("clean -- no tenant identifiers found")
        return 0

    total = sum(found.values())
    for name, count in sorted(found.items()):
        print(f"  {count:>3}x  {name}  ->  {redactions[name]}")

    if not write:
        print(f"\n{total} occurrence(s) present. Re-run with --write to redact.")
        return 1

    for name, replacement in redactions.items():
        text = text.replace(name, replacement)
    # Validate it is still parseable before overwriting the original.
    json.loads(text)
    _ARTIFACT.write_text(text, encoding="utf-8")
    print(f"\nredacted {total} occurrence(s) in {_ARTIFACT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

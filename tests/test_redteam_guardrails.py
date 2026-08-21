"""Red-team eval — prove the deterministic guardrails block the real attack corpus.

The attack fixtures under ``tests/redteam/`` are vendored from socxen
(open-agent-ai-security/socxen, Apache-2.0 — see THIRD_PARTY_NOTICES.md). socxen grades
them against a full agent; here we run the guardrail-relevant classes through exa-tools'
deterministic passes and assert the payload is neutralized, so a regression in
``canonicalize`` / ``neutralize_output`` fails a test instead of shipping.

Scope — the classes a deterministic pass can enforce:
  - A07 (zero-width / invisible-unicode hidden instruction) -> canonicalize must strip it.
  - A10/A11 (downstream-export active content: CSV formula, phishing link) -> neutralize.
  - D01/D02/D03 (seeded secret / PII that must not reach a persisted artifact) -> neutralize
    must redact each leaked value.
The semantic A/B/C attacks (fake authority, manufactured corroboration, reuse-prior-yes)
are model-and-skill behavior, not a deterministic guardrail, and are out of scope here.
"""

from __future__ import annotations

import glob
import json
import os

import pytest

from exa.mcp.guardrails import canonicalize, neutralize_output
from exa.mcp.guardrails.canonicalize import is_strippable

_DIR = os.path.join(os.path.dirname(__file__), "redteam")
_FIXTURES = sorted(glob.glob(os.path.join(_DIR, "*.attack.json")))


def _fid(path: str) -> str:
    return os.path.basename(path).split(".")[0]


def test_corpus_present():
    # Guard against an empty glob silently passing the parametrized test.
    assert len(_FIXTURES) >= 6, "red-team fixtures missing from tests/redteam/"


@pytest.mark.parametrize("path", _FIXTURES, ids=[_fid(p) for p in _FIXTURES])
def test_guardrail_blocks_attack(path: str):
    atk = json.load(open(path, encoding="utf-8"))
    payload = atk["input"]["payload"]
    leaks = (atk.get("expected", {}).get("must_not", {}) or {}).get("leak") or []

    if leaks:
        # Write-path: the read->write pipeline must neutralize the payload before it
        # persists. Every value the fixture says must-not-leak must be gone.
        canon, _ = canonicalize(payload)
        neutral, notes = neutralize_output(canon)
        for leak in leaks:
            assert leak not in neutral, f"{_fid(path)}: attack payload survived guardrail -> {leak!r}"
        assert notes, f"{_fid(path)}: neutralize made no change to a known-malicious payload"
    else:
        # Read-path hidden-code-point attack (A07): canonicalize must leave no strippable
        # smuggling code point behind, and must have actually removed something.
        clean, hy = canonicalize(payload)
        assert not any(is_strippable(c) for c in clean), f"{_fid(path)}: invisible smuggling survived canonicalize"
        assert hy.counts.get("stripped", 0) > 0, f"{_fid(path)}: expected canonicalize to strip smuggling code points"

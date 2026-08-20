"""The tool spine (tool -> endpoint map) must stay complete, valid, and fresh.

Runs the same checks as `security/gen_tool_spine.py --check` inside pytest, so the guard
fires in the normal test run as well as the dedicated CI step.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SPINE = Path(__file__).resolve().parents[1] / "security" / "gen_tool_spine.py"
_spec = importlib.util.spec_from_file_location("gen_tool_spine", _SPINE)
gen_tool_spine = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen_tool_spine)


def test_spine_is_complete_and_valid():
    """Every tool has an entry, no stale entries, every endpoint exists in code."""
    problems = gen_tool_spine.validate()
    assert not problems, "tool spine problems:\n  - " + "\n  - ".join(problems)


def test_spine_file_is_fresh():
    """security/tool_spine.md matches what the generator produces (run it if this fails)."""
    out = gen_tool_spine.OUT
    assert out.exists(), "tool_spine.md missing — run: uv run python security/gen_tool_spine.py"
    assert out.read_text(encoding="utf-8") == gen_tool_spine.build_md(), (
        "tool_spine.md is stale — run: uv run python security/gen_tool_spine.py"
    )

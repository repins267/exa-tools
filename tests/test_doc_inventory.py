"""Anti-staleness guard: the docs' tool/skill counts must match the live code.

A new MCP tool or Claude skill cannot be merged without the README (and, by the
"keep this current" process, the How-To / Deep Dive / vault) being updated in the same
change — because this test fails CI when the README's "Tools (N)" / "Skills (M)" counts
drift from what the code actually ships.

This is the enforceable spine of doc freshness. The prose provenance in the Deep Dive is
kept honest separately by `exa selftest` (which exercises every live tool) and by each
entry carrying the raw API call to reproduce it.
"""

from __future__ import annotations

import re
from pathlib import Path

from exa.mcp.tools import TOOL_DEFS, WRITE_TOOLS, visible_tools

_REPO = Path(__file__).resolve().parents[1]


def _readme() -> str:
    return (_REPO / "README.md").read_text(encoding="utf-8")


def _skill_dirs() -> list[str]:
    skills = _REPO / "plugin" / "skills"
    return sorted(d.name for d in skills.iterdir() if d.is_dir() and (d / "SKILL.md").exists())


def test_readme_tool_count_matches_code():
    """README 'Tools (N)' must equal the number of MCP tools the server exposes."""
    actual = len(TOOL_DEFS)
    m = re.search(r"\*\*Tools \((\d+)\)\*\*", _readme())
    assert m, "README is missing a '**Tools (N)**' marker"
    documented = int(m.group(1))
    assert documented == actual, (
        f"README says Tools ({documented}) but the code exposes {actual} "
        f"(exa.mcp.tools.TOOL_DEFS). Update the README tools table + count, the How-To, "
        f"and the Deep Dive when the tool surface changes."
    )


def test_readme_skill_count_matches_dirs():
    """README 'Skills (M)' must equal the number of shipped skill directories."""
    actual = len(_skill_dirs())
    m = re.search(r"\*\*Skills \((\d+)\)\*\*", _readme())
    assert m, "README is missing a '**Skills (M)**' marker"
    documented = int(m.group(1))
    assert documented == actual, (
        f"README says Skills ({documented}) but plugin/skills/ has {actual} "
        f"({', '.join(_skill_dirs())}). Update the README skills list + count, the How-To, "
        f"and the Deep Dive when a skill is added/removed."
    )


def test_readme_lists_every_shipped_skill():
    """Every skill directory must be named in the README skills list (no silent adds)."""
    readme = _readme()
    missing = [s for s in _skill_dirs() if f"`{s}`" not in readme]
    assert not missing, f"skills present in plugin/skills/ but not named in README: {missing}"


def test_write_tools_are_a_subset_of_all_tools():
    """Sanity: the 4 write tools are part of the advertised surface, hidden when read-only."""
    all_names = {t.name for t in visible_tools(read_only=False)}
    ro_names = {t.name for t in visible_tools(read_only=True)}
    assert WRITE_TOOLS <= all_names, "a WRITE_TOOL is not in the full tool surface"
    assert WRITE_TOOLS.isdisjoint(ro_names), "a write tool leaked into the read-only surface"
    assert len(all_names) - len(ro_names) == len(WRITE_TOOLS)

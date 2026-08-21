"""Anti-staleness guard: the docs' tool/skill counts must match the live code.

A new MCP tool or Claude skill cannot be merged without the canonical inventory in
`docs/mcp.md` (and, by the "keep this current" process, the How-To / Deep Dive / vault)
being updated in the same change — because this test fails CI when the doc's
"Tools (N)" / "Skills (M)" counts drift from what the code actually ships.

The full tool table and named skill list live in `docs/mcp.md` (the README links to it),
so that is the surface this guard checks. It accepts either a `## Tools (N)` heading or a
`**Tools (N)**` bold marker.

This is the enforceable spine of doc freshness. The prose provenance in the Deep Dive is
kept honest separately by `exa selftest` (which exercises every live tool) and by each
entry carrying the raw API call to reproduce it.
"""

from __future__ import annotations

import re
from pathlib import Path

from exa.mcp.tools import TOOL_DEFS, WRITE_TOOLS, visible_tools

_REPO = Path(__file__).resolve().parents[1]

# The tool table + named skill list live in docs/mcp.md; the slim README links to it.
_INVENTORY_DOC = "docs/mcp.md"


def _inventory() -> str:
    return (_REPO / _INVENTORY_DOC).read_text(encoding="utf-8")


def _skill_dirs() -> list[str]:
    skills = _REPO / "plugin" / "skills"
    return sorted(d.name for d in skills.iterdir() if d.is_dir() and (d / "SKILL.md").exists())


def _documented_count(label: str, text: str) -> int | None:
    """The N in a `## Tools (N)` heading or a `**Tools (N)**` bold marker, or None."""
    m = re.search(rf"(?:\*\*|#{{1,6}}\s*){label} \((\d+)\)", text)
    return int(m.group(1)) if m else None


def test_doc_tool_count_matches_code():
    """docs/mcp.md 'Tools (N)' must equal the number of MCP tools the server exposes."""
    actual = len(TOOL_DEFS)
    documented = _documented_count("Tools", _inventory())
    assert documented is not None, f"{_INVENTORY_DOC} is missing a 'Tools (N)' marker"
    assert documented == actual, (
        f"{_INVENTORY_DOC} says Tools ({documented}) but the code exposes {actual} "
        f"(exa.mcp.tools.TOOL_DEFS). Update the tools table + count in {_INVENTORY_DOC}, the "
        f"How-To, and the Deep Dive when the tool surface changes."
    )


def test_doc_skill_count_matches_dirs():
    """docs/mcp.md 'Skills (M)' must equal the number of shipped skill directories."""
    actual = len(_skill_dirs())
    documented = _documented_count("Skills", _inventory())
    assert documented is not None, f"{_INVENTORY_DOC} is missing a 'Skills (M)' marker"
    assert documented == actual, (
        f"{_INVENTORY_DOC} says Skills ({documented}) but plugin/skills/ has {actual} "
        f"({', '.join(_skill_dirs())}). Update the skills list + count in {_INVENTORY_DOC}, the "
        f"How-To, and the Deep Dive when a skill is added/removed."
    )


def test_doc_lists_every_shipped_skill():
    """Every skill directory must be named in docs/mcp.md's skills list (no silent adds)."""
    doc = _inventory()
    missing = [s for s in _skill_dirs() if f"`{s}`" not in doc]
    assert not missing, (
        f"skills present in plugin/skills/ but not named in {_INVENTORY_DOC}: {missing}"
    )


def test_write_tools_are_a_subset_of_all_tools():
    """Sanity: the 4 write tools are part of the advertised surface, hidden when read-only."""
    all_names = {t.name for t in visible_tools(read_only=False)}
    ro_names = {t.name for t in visible_tools(read_only=True)}
    assert WRITE_TOOLS <= all_names, "a WRITE_TOOL is not in the full tool surface"
    assert WRITE_TOOLS.isdisjoint(ro_names), "a write tool leaked into the read-only surface"
    assert len(all_names) - len(ro_names) == len(WRITE_TOOLS)

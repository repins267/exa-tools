"""The AI-BOM must stay in sync with the repo sources (freshness gate) and hold its shape."""

from __future__ import annotations

import importlib.util
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _gen():
    spec = importlib.util.spec_from_file_location("gen_aibom", ROOT / "security" / "gen_aibom.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _no_ts(doc: dict) -> dict:
    d = dict(doc)
    d["metadata"] = {k: v for k, v in d["metadata"].items() if k != "timestamp"}
    return d


def test_bom_is_fresh():
    doc = _gen().build_bom()
    on_disk = json.loads((ROOT / "security" / "aibom.cdx.json").read_text(encoding="utf-8"))
    assert _no_ts(on_disk) == _no_ts(doc), (
        "security/aibom.cdx.json is stale — run: uv run security/gen_aibom.py"
    )


def test_bom_shape_and_governance():
    doc = _gen().build_bom()
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"
    assert doc["metadata"]["component"]["name"] == "exa-tools"
    names = {c["name"] for c in doc["components"]}
    assert "Claude (Anthropic)" in names               # foundation model captured
    assert any(c["type"] == "data" for c in doc["components"])   # skills/methodology
    assert doc["services"][0]["name"].startswith("Exabeam")
    props = {p["name"] for p in doc["metadata"]["properties"]}
    for expected in ("exa:governance:default-read-only", "exa:guardrail:input-canonicalization",
                     "exa:guardrail:output-neutralization", "exa:guardrail:redteam-evals",
                     "exa:audit:log", "exa:secrets"):
        assert expected in props, f"governance property {expected} missing from AI-BOM"

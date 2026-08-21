"""Cross-customer learn loop: classification, promotion, zero-leak, learning curve."""

from __future__ import annotations

import pytest

from exa.aillm import learn as learn_mod
from exa.aillm.learn import (
    AUTO,
    LOCAL,
    REVIEW,
    classify,
    extract_learn_candidates,
    promote,
)


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path, monkeypatch):
    monkeypatch.setattr(learn_mod, "_LEARN_DIR", tmp_path)
    monkeypatch.setattr(learn_mod, "_PROMOTED", tmp_path / "promoted.json")


def _prop(value, reason="ai-category", redacted=False):
    return {"value": value, "field": "category", "table": "AI/LLM Proxy Categories",
            "reason": reason, "redacted": redacted, "live_values": 1}


def test_classify_tiers():
    assert classify("Generative AI and ML Applications", "ai-category", False)[0] == AUTO
    assert classify("some-new-app", "ai-classified", False)[0] == REVIEW
    # per-record / PII -> local-only, whatever the reason
    assert classify("x" * 120, "ai-category", False)[0] == LOCAL
    assert classify('{"name":"beagle","id":"x"}', "ai-category", False)[0] == LOCAL
    assert classify("user@hospital.org", "ai-category", False)[0] == LOCAL
    assert classify("clean", "ai-category", True)[0] == LOCAL  # redacted flag


def test_extract_skips_already_known():
    gap = {"tables": [{"propose": [_prop("Generative AI"), _prop("NovelCat")]}]}
    cands = extract_learn_candidates(gap, known={"generative ai"})
    vals = {c.value for c in cands}
    assert "Generative AI" not in vals  # already known -> not a learn candidate
    assert "NovelCat" in vals


def test_promote_never_leaks_local_only():
    gap = {"tables": [{"propose": [
        _prop("CleanGenericCat"),
        _prop('{"patient":"embedded json"}'),  # per-record -> LOCAL
    ]}]}
    cands = extract_learn_candidates(gap, known=set())
    added = promote(cands, approve_reviews=True)
    added_vals = {a["value"] for a in added}
    assert "CleanGenericCat" in added_vals
    assert not any("patient" in v for v in added_vals)  # PII never promoted
    # and it never lands in the persisted overlay
    assert not any("patient" in str(e.get("value")) for e in learn_mod.load_promoted())


def test_learning_curve_and_no_regression():
    """A->E: new-knowledge-per-customer declines as the base grows, spikes on novelty;
    a promoted value is never re-learned; PII never promoted."""
    customers = {
        "A": ["catA", "appA", "domA"],          # 3 new
        "B": ["catB", "appB", "catA"],           # 2 new (catA already known)
        "C": ["catC", "catA", "catB"],           # 1 new
        "D": ["catA", "catB", "catC"],           # 0 new
        "E": ["e1", "e2", "e3", "e4", "catA"],   # 4 new (novelty spike)
    }
    known: set[str] = set()
    curve = []
    for _cust, vals in customers.items():
        propose = [_prop(v) for v in vals]
        propose.append(_prop('{"pii":"leak@hospital.org"}'))  # always a PII value
        cands = extract_learn_candidates({"tables": [{"propose": propose}]}, known=known)
        new_generic = [c for c in cands if c.verdict != LOCAL]
        curve.append(len(new_generic))
        promote(cands, approve_reviews=True)
        known |= {a["value"].lower() for a in learn_mod.load_promoted()}

    assert curve == [3, 2, 1, 0, 4]  # declines then spikes -- the learning curve
    # zero-leak: no PII value ever entered the shared overlay
    assert not any("hospital" in str(e.get("value")).lower() for e in learn_mod.load_promoted())
    # coverage grows: by E the base holds all earlier generic values
    base = {str(e.get("value")).lower() for e in learn_mod.load_promoted()}
    assert {"cata", "catb", "catc"} <= base

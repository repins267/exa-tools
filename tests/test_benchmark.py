"""Classifier benchmark: safety metrics on the golden corpus + learn-loop proof."""

from __future__ import annotations

from pathlib import Path

from exa.aillm.benchmark import (
    load_golden,
    score_golden,
    simulate_learn_loop,
)

_GOLDEN = Path("tests") / "data" / "classifier_golden.jsonl"


def test_golden_corpus_passes_safety_metrics():
    entries = load_golden(_GOLDEN)
    assert len(entries) >= 30
    r = score_golden(entries)
    # The two non-negotiable safety metrics.
    assert r.pii_withhold_recall == 1.0, "a PII value escaped -> LEAK RISK"
    assert not r.leaks, f"unsafe value auto-promoted: {r.leaks}"
    assert r.auto_promote_precision == 1.0
    # Efficacy: don't wrongly withhold real generic AI values.
    assert r.ai_recall == 1.0


def test_learn_loop_curve_and_zero_leak():
    def _p(v, reason="ai-category"):
        return {"value": v, "field": "category", "table": "t", "reason": reason,
                "redacted": False, "live_values": 1}
    pii = _p('{"pii":"leak@hospital.org"}', "ai-classified")
    customers = [
        [_p("catA"), _p("appA", "ai-classified"), _p("domA", "ai-classified"), pii],
        [_p("catB"), _p("appB", "ai-classified"), _p("catA"), pii],
        [_p("catC"), _p("catA"), _p("catB"), pii],
        [_p("catA"), _p("catB"), _p("catC"), pii],
        [_p("e1"), _p("e2"), _p("e3"), _p("e4"), _p("catA"), pii],
    ]
    loop = simulate_learn_loop(customers)
    assert loop.curve == [3, 2, 1, 0, 4]           # learning curve
    assert loop.coverage_growth[-1] == 10          # knowledge accumulates
    assert loop.leaked == []                        # PII never entered shared base

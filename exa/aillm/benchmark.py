"""Prove the classifier + learn loop with numbers on known data.

Two proofs:

* **Classifier accuracy** over a labelled golden corpus -- per-tier counts plus
  the two safety metrics that matter most: **auto-promote precision** (an
  auto-promoted value must never be PII/customer-specific -> the leak metric,
  target 1.0) and **PII-withhold recall** (every PII value must be local-only,
  target 1.0), plus **AI recall** (don't wrongly withhold real generic AI values).
* **Learn-loop simulation** (A->E) -- new-knowledge-per-customer curve, coverage
  growth, and a hard zero-leak assertion.

The classifier under test is injectable, so the same corpus can be scored against
the deterministic heuristic (default) or an LLM backend (claude/chatgpt/gemini)
for a speed/accuracy/cost leaderboard.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from exa.aillm.calibration import wilson_lower_bound
from exa.aillm.learn import (
    AUTO,
    LOCAL,
    classify,
    extract_learn_candidates,
)

# Golden labels -> whether the value is safe to enter shared knowledge.
_UNSAFE_LABELS = {"pii", "customer-specific"}
_SAFE_LABELS = {"generic-ai"}

# A classifier is (value, reason, redacted) -> (verdict, why).
Classifier = Callable[[str, str, bool], tuple[str, str]]


@dataclass
class GoldenEntry:
    value: str
    reason: str
    label: str
    field: str = ""


@dataclass
class BenchmarkResult:
    model: str
    n: int
    per_verdict: dict[str, int] = field(default_factory=dict)
    auto_promote_precision: float | None = None   # point estimate: 1.0 = no leak
    auto_promote_precision_lb: float | None = None  # Wilson lower bound (rises with N)
    pii_withhold_recall: float | None = None       # 1.0 = every PII value local-only
    ai_recall: float | None = None                 # generic-AI not wrongly withheld
    leaks: list[str] = field(default_factory=list)  # unsafe values that auto-promoted
    seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_golden(path: str | Path) -> list[GoldenEntry]:
    out: list[GoldenEntry] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        out.append(GoldenEntry(
            value=d["value"], reason=d.get("reason", ""),
            label=d.get("label", ""), field=d.get("field", ""),
        ))
    return out


def check_corpus_integrity(
    entries: list[GoldenEntry], *, min_corpus: int = 35, min_pii: int = 3, min_generic: int = 5
) -> list[str]:
    """Structural guards so the gate can't be 'fixed' by weakening the corpus.

    Returns a list of violations (empty == OK). Enforces a minimum size and a
    minimum representation of the safety-critical labels, so a silent deletion of
    PII/generic examples is caught as a hard failure.
    """
    violations: list[str] = []
    if len(entries) < min_corpus:
        violations.append(f"corpus size {len(entries)} < min {min_corpus}")
    labels = Counter(e.label for e in entries)
    if labels.get("pii", 0) < min_pii:
        violations.append(f"pii examples {labels.get('pii', 0)} < min {min_pii}")
    if labels.get("generic-ai", 0) < min_generic:
        violations.append(f"generic-ai examples {labels.get('generic-ai', 0)} < min {min_generic}")
    fields = {e.field for e in entries if e.field}
    for required in ("category", "app", "web_domain", "alert_name"):
        if required not in fields:
            violations.append(f"gate field '{required}' unrepresented")
    return violations


def score_golden(
    entries: list[GoldenEntry], classifier: Classifier = classify, model: str = "heuristic"
) -> BenchmarkResult:
    """Score a classifier over the golden corpus."""
    start = time.perf_counter()
    per_verdict: Counter[str] = Counter()
    auto_total = auto_safe = 0
    pii_total = pii_withheld = 0
    generic_total = generic_kept = 0
    leaks: list[str] = []

    for e in entries:
        verdict, _ = classifier(e.value, e.reason, False)
        per_verdict[verdict] += 1
        promotable = verdict != LOCAL

        if verdict == AUTO:
            auto_total += 1
            if e.label in _UNSAFE_LABELS:
                leaks.append(e.value)
            else:
                auto_safe += 1
        if e.label == "pii":
            pii_total += 1
            if verdict == LOCAL:
                pii_withheld += 1
        if e.label in _SAFE_LABELS:
            generic_total += 1
            if promotable:
                generic_kept += 1

    def _ratio(num: int, den: int) -> float | None:
        return round(num / den, 4) if den else None

    return BenchmarkResult(
        model=model,
        n=len(entries),
        per_verdict=dict(per_verdict),
        auto_promote_precision=_ratio(auto_safe, auto_total) if auto_total else 1.0,
        auto_promote_precision_lb=(
            round(wilson_lower_bound(auto_safe, auto_total), 4) if auto_total else None
        ),
        pii_withhold_recall=_ratio(pii_withheld, pii_total),
        ai_recall=_ratio(generic_kept, generic_total),
        leaks=leaks,
        seconds=round(time.perf_counter() - start, 3),
    )


@dataclass
class LearnLoopResult:
    curve: list[int]              # new generic knowledge per customer
    promoted_total: int
    leaked: list[str]            # PII/customer values that reached the shared base (must be [])
    coverage_growth: list[int]   # cumulative shared-knowledge size after each customer


def simulate_learn_loop(customers: list[list[dict]]) -> LearnLoopResult:
    """Run A->E gap-report `propose` sets through the learn loop in sequence.

    Each ``customers[i]`` is a list of propose-entry dicts. Uses a fresh in-memory
    promoted set (does not touch the real overlay).
    """
    known: set[str] = set()
    promoted: list[dict] = []
    seen = set()
    curve, coverage = [], []
    leaked: list[str] = []

    for propose in customers:
        gap = {"tables": [{"propose": propose}]}
        cands = extract_learn_candidates(gap, known=known)
        curve.append(sum(1 for c in cands if c.verdict != LOCAL))
        for c in cands:
            if c.verdict != LOCAL and c.value.lower() not in seen:
                promoted.append({"value": c.value})
                seen.add(c.value.lower())
            if c.verdict == LOCAL and c.value.lower() in seen:
                leaked.append(c.value)  # would only happen on a bug
        known |= {p["value"].lower() for p in promoted}
        coverage.append(len(promoted))

    return LearnLoopResult(
        curve=curve, promoted_total=len(promoted), leaked=leaked, coverage_growth=coverage
    )


def render_scorecard_html(results: list[BenchmarkResult], loop: LearnLoopResult | None) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{r.model}</td><td class='n'>{r.n}</td>"
        f"<td class='n'>{r.auto_promote_precision}</td>"
        f"<td class='n'>{r.pii_withhold_recall}</td>"
        f"<td class='n'>{r.ai_recall}</td>"
        f"<td class='n'>{r.seconds}s</td>"
        f"<td class='n'>{len(r.leaks)}</td></tr>"
        for r in results
    )
    loop_html = ""
    if loop:
        loop_html = (
            f"<h2>Learn loop (A..)</h2><p>curve (new/customer): {loop.curve} · "
            f"coverage: {loop.coverage_growth} · leaked: {len(loop.leaked)}</p>"
        )
    css = (
        "body{font:15px/1.5 Segoe UI,Arial,sans-serif;background:#15181c;color:#e8eaed;"
        "margin:0;padding:28px}"
        "@media(prefers-color-scheme:light){body{background:#fff;color:#111}}"
        "table{border-collapse:collapse;width:100%}"
        "th,td{padding:7px 10px;border-bottom:1px solid #2a2f36;text-align:left}"
        "td.n{text-align:right;font-variant-numeric:tabular-nums}"
    )
    return (
        f"<!doctype html><html><head><meta charset='utf-8'><title>Classifier Scorecard</title>"
        f"<style>{css}</style></head><body><h1>exa assess — classifier scorecard</h1>"
        f"<table><thead><tr><th>Model</th><th>N</th><th>Auto-promote precision</th>"
        f"<th>PII-withhold recall</th><th>AI recall</th><th>Time</th><th>Leaks</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>{loop_html}</body></html>"
    )

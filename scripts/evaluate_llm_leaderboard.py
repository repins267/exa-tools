#!/usr/bin/env python
"""Nightly, NON-BLOCKING LLM leaderboard evaluation -> historical trend CSV.

Scores the classifier on the golden corpus and appends one row per model to a
trend file (accuracy / speed / cost). It is deliberately kept out of the merge
gate: it is non-deterministic, needs network + API budget, and a vendor timeout
must never block a hotfix.

Today only the deterministic ``heuristic`` backend exists, so that is the row we
record. When ``exa/aillm/llm.py`` lands with claude/chatgpt/gemini backends and
their API keys are present, add them to ``_MODELS`` and this script scores each
on the same corpus for the leaderboard -- no other change needed.
"""

from __future__ import annotations

import argparse
import csv
import os
import time
from pathlib import Path

from exa.aillm.benchmark import load_golden, score_golden

# (model, env var that must be set for a real backend). "heuristic" needs none.
_MODELS: list[tuple[str, str | None]] = [
    ("heuristic", None),
    # ("claude", "ANTHROPIC_API_KEY"),   # enable when exa/aillm/llm.py ships
    # ("chatgpt", "OPENAI_API_KEY"),
    # ("gemini", "GOOGLE_API_KEY"),
]

_HEADER = [
    "timestamp", "model", "n", "auto_promote_precision",
    "auto_promote_precision_lb", "pii_withhold_recall", "ai_recall",
    "seconds", "leaks", "note",
]


def _classifier_for(model: str):
    """Return the (value, reason, redacted) classifier for a model, or None."""
    if model == "heuristic":
        from exa.aillm.learn import classify
        return classify
    try:  # future: exa/aillm/llm.py exposes a backend factory
        from exa.aillm.llm import get_classifier  # type: ignore
        return get_classifier(model)
    except Exception:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description="LLM leaderboard evaluation (non-blocking).")
    ap.add_argument("--golden", default="tests/data/classifier_golden.jsonl")
    ap.add_argument("--out-csv", default="trends/llm_performance.csv")
    args = ap.parse_args()

    entries = load_golden(args.golden)
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    rows = []
    for model, env in _MODELS:
        clf = _classifier_for(model)
        if clf is None or (env and not os.environ.get(env)):
            rows.append({"timestamp": ts, "model": model, "n": len(entries),
                         "note": f"skipped (backend/key missing: {env or 'n/a'})"})
            continue
        r = score_golden(entries, classifier=clf, model=model)
        rows.append({
            "timestamp": ts, "model": model, "n": r.n,
            "auto_promote_precision": r.auto_promote_precision,
            "auto_promote_precision_lb": r.auto_promote_precision_lb,
            "pii_withhold_recall": r.pii_withhold_recall, "ai_recall": r.ai_recall,
            "seconds": r.seconds, "leaks": len(r.leaks),
            "note": "LLM backends pending" if model == "heuristic" else "",
        })

    out = Path(args.out_csv)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_header = not out.exists()
    with out.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=_HEADER)
        if write_header:
            w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in _HEADER})

    for row in rows:
        print(f"{row['model']}: {row.get('note') or 'scored'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

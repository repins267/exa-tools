"""Historical baseline calibration from resolved case outcomes.

Computes per-rule and per-entity false-positive rates from the outcomes
log and cross-references against recently closed Threat Center cases.
Results are written to ~/.exa/cache/ for use by the tune commands.
"""

from __future__ import annotations

import dataclasses
import json
import warnings
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

_CACHE_DIR = Path.home() / ".exa" / "cache"


@dataclasses.dataclass
class CalibrationReport:
    lookback_days_requested: int
    lookback_days_used: int
    lts_retention_days: int | None
    total_closed_cases: int
    outcomes_matched: int
    rule_fp_rates: dict[str, float]
    entity_fp_rates: dict[str, float]
    verdict_accuracy: dict[str, dict[str, Any]]


def run_baseline(
    client: ExaClient,
    *,
    lookback_days: int = 90,
) -> CalibrationReport:
    """Compute calibration report from closed cases and outcomes log.

    Steps:
      1. Query LTS retention to cap the lookback window.
      2. Refresh any unresolved outcome records from Threat Center.
      3. Load all logged outcomes.
      4. Search closed cases in the lookback window.
      5. Cross-reference closed cases with outcomes log.
      6. Compute FP rates and verdict accuracy.
      7. Write cache files.
    """
    from exa.case.cases import search_cases
    from exa.case.outcomes import auto_fill_outcomes, load_outcomes
    from exa.health.consumption import get_lts_consumption

    # Step 1: Determine retention ceiling
    lts_retention_days: int | None = None
    lookback_days_used = lookback_days
    try:
        lts = get_lts_consumption(client)
        # EXA-UNVERIFIED: field name pending live verification
        retention = lts.get("retentionDays")
        if retention is not None:
            lts_retention_days = int(retention)
            if lookback_days > lts_retention_days:
                lookback_days_used = lts_retention_days
    except Exception:
        warnings.warn(
            "LTS consumption endpoint unavailable — proceeding with requested lookback.",
            stacklevel=2,
        )

    # Step 2: Refresh unresolved outcomes
    auto_fill_outcomes(client)

    # Step 3: Load all logged outcome records
    all_outcomes = load_outcomes()

    # Step 4: Search closed cases in the window
    closed_cases = search_cases(
        client,
        filter='stage:"CLOSED"',
        lookback_days=lookback_days_used,
        limit=3000,
    )
    total_closed_cases = len(closed_cases)

    # Step 5: Cross-reference by case_id
    closed_ids = {c.get("caseId") for c in closed_cases}
    matched_outcomes = [r for r in all_outcomes if r.case_id in closed_ids]
    outcomes_matched = len(matched_outcomes)

    # Step 6: Compute rates
    rule_fp_rates, entity_fp_rates = _compute_fp_rates(matched_outcomes)
    verdict_accuracy = _compute_verdict_accuracy(matched_outcomes)

    # Step 7: Write cache
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (_CACHE_DIR / "rule_fp_rates.json").write_text(
        json.dumps(rule_fp_rates, indent=2), encoding="utf-8"
    )
    (_CACHE_DIR / "entity_fp_rates.json").write_text(
        json.dumps(entity_fp_rates, indent=2), encoding="utf-8"
    )

    return CalibrationReport(
        lookback_days_requested=lookback_days,
        lookback_days_used=lookback_days_used,
        lts_retention_days=lts_retention_days,
        total_closed_cases=total_closed_cases,
        outcomes_matched=outcomes_matched,
        rule_fp_rates=rule_fp_rates,
        entity_fp_rates=entity_fp_rates,
        verdict_accuracy=verdict_accuracy,
    )


def _compute_fp_rates(
    records: list,
) -> tuple[dict[str, float], dict[str, float]]:
    """Compute false-positive rates per rule and per entity.

    FP rate = fp_count / total_known where total_known excludes None outcomes.
    """
    rule_counts: dict[str, dict[str, int]] = {}
    entity_counts: dict[str, dict[str, int]] = {}

    for r in records:
        if r.outcome is None:
            continue
        if r.rule_name:
            _tally(rule_counts, r.rule_name, r.outcome)
        if r.entity_name:
            _tally(entity_counts, r.entity_name, r.outcome)

    rule_fp_rates = {
        name: _fp_rate(counts) for name, counts in rule_counts.items()
    }
    entity_fp_rates = {
        name: _fp_rate(counts) for name, counts in entity_counts.items()
    }
    return rule_fp_rates, entity_fp_rates


def _compute_verdict_accuracy(records: list) -> dict[str, dict[str, Any]]:
    """Build per-verdict outcome distribution.

    Structure: {verdict_issued: {tp, fp, noise, duplicate, unknown, total}}
    """
    acc: dict[str, dict[str, Any]] = {}
    for r in records:
        if r.outcome is None:
            continue
        v = r.verdict_issued
        if v not in acc:
            acc[v] = {"tp": 0, "fp": 0, "noise": 0, "duplicate": 0, "unknown": 0, "total": 0}
        bucket = acc[v]
        key = r.outcome if r.outcome in bucket else "unknown"
        bucket[key] += 1
        bucket["total"] += 1
    return acc


def _tally(store: dict[str, dict[str, int]], key: str, outcome: str) -> None:
    if key not in store:
        store[key] = {"tp": 0, "fp": 0, "noise": 0, "duplicate": 0, "unknown": 0}
    bucket = store[key]
    bucket[outcome if outcome in bucket else "unknown"] += 1


def _fp_rate(counts: dict[str, int]) -> float:
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return round(counts.get("fp", 0) / total, 4)

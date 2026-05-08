"""Outcome tracking for case qualification results.

Records every qualified case to ~/.exa/cache/outcomes.jsonl.
Outcomes are filled in later (manually or via auto_fill_outcomes)
once cases are closed in Threat Center.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from exa.client import ExaClient

_CACHE_DIR = Path.home() / ".exa" / "cache"
_OUTCOMES_PATH = _CACHE_DIR / "outcomes.jsonl"

_VALID_OUTCOMES = frozenset({"tp", "fp", "noise", "duplicate", "unknown"})


@dataclasses.dataclass
class OutcomeRecord:
    ts: str
    case_number: str
    case_id: str
    rule_name: str | None
    entity_name: str | None
    entity_type: str | None
    verdict_issued: str
    risk_score: int
    score_trend: str
    closed_reason: str | None
    outcome: str | None


def append_outcome(record: OutcomeRecord) -> None:
    """Append one record to outcomes.jsonl, creating the file if missing."""
    _OUTCOMES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _OUTCOMES_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(dataclasses.asdict(record)) + "\n")


def load_outcomes() -> list[OutcomeRecord]:
    """Read all records from outcomes.jsonl. Returns empty list if file missing."""
    if not _OUTCOMES_PATH.exists():
        return []
    records: list[OutcomeRecord] = []
    with _OUTCOMES_PATH.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(OutcomeRecord(**json.loads(line)))
    return records


def resolve_outcome(
    case_number: str,
    outcome: str,
    closed_reason: str | None = None,
) -> bool:
    """Set the outcome field on a logged record.

    Returns False if no record with case_number exists.
    """
    records = load_outcomes()
    found = False
    for r in records:
        if r.case_number == case_number:
            r.outcome = outcome
            if closed_reason is not None:
                r.closed_reason = closed_reason
            found = True
    if not found:
        return False
    _rewrite(records)
    return True


def auto_fill_outcomes(client: ExaClient) -> int:
    """Check Threat Center for any unresolved records that are now CLOSED.

    Updates outcome and closed_reason in place. Returns count of records filled.
    """
    from exa.case.cases import get_case

    records = load_outcomes()
    updated = 0
    for r in records:
        if r.outcome is not None:
            continue
        try:
            case = get_case(client, r.case_id)
        except Exception:
            continue
        if case.get("stage") != "CLOSED":
            continue
        raw_reason: str | None = case.get("closedReason")
        r.outcome = _normalize_closed_reason(raw_reason)
        r.closed_reason = raw_reason
        updated += 1
    if updated:
        _rewrite(records)
    return updated


def _normalize_closed_reason(reason: str | None) -> str:
    """Map Exabeam closedReason strings to outcome constants.

    Known values observed in Threat Center:
      "False Positive" → "fp"
      "True Positive"  → "tp"
      "Resolved"       → "tp"
      "Duplicate"      → "duplicate"
      "Informational"  → "noise"
      anything else    → "unknown"
    """
    if not reason:
        return "unknown"
    lower = reason.lower().strip()
    if lower.startswith("true positive") or lower == "resolved":
        return "tp"
    if lower.startswith("false positive"):
        return "fp"
    if lower == "duplicate":
        return "duplicate"
    if lower == "informational":
        return "noise"
    return "unknown"


def _rewrite(records: list[OutcomeRecord]) -> None:
    _OUTCOMES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _OUTCOMES_PATH.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(dataclasses.asdict(r)) + "\n")

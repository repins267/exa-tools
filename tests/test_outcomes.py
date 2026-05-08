"""Tests for exa/case/outcomes.py — no HTTP mocking needed."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

import exa.case.outcomes as outcomes_mod
from exa.case.outcomes import (
    OutcomeRecord,
    _normalize_closed_reason,
    append_outcome,
    auto_fill_outcomes,
    load_outcomes,
    resolve_outcome,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(**kwargs) -> OutcomeRecord:
    defaults = dict(
        ts="2026-05-07T10:00:00+00:00",
        case_number="100",
        case_id="uuid-100",
        rule_name="First connection to external IP",
        entity_name="jsmith",
        entity_type="user",
        verdict_issued="SUSPECTED_INCIDENT",
        risk_score=90,
        score_trend="first_appearance",
        closed_reason=None,
        outcome=None,
    )
    defaults.update(kwargs)
    return OutcomeRecord(**defaults)


@pytest.fixture(autouse=True)
def patch_outcomes_path(tmp_path, monkeypatch):
    """Redirect all outcomes file operations to a temp directory."""
    monkeypatch.setattr(outcomes_mod, "_OUTCOMES_PATH", tmp_path / "outcomes.jsonl")


# ---------------------------------------------------------------------------
# append_outcome
# ---------------------------------------------------------------------------


class TestAppendOutcome:
    def test_creates_file_and_appends(self, tmp_path):
        r = _make_record()
        append_outcome(r)
        assert (tmp_path / "outcomes.jsonl").exists()
        lines = (tmp_path / "outcomes.jsonl").read_text().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["case_number"] == "100"

    def test_appends_multiple_records(self, tmp_path):
        append_outcome(_make_record(case_number="1"))
        append_outcome(_make_record(case_number="2"))
        lines = (tmp_path / "outcomes.jsonl").read_text().splitlines()
        assert len(lines) == 2

    def test_all_fields_serialized(self, tmp_path):
        r = _make_record(outcome="tp", closed_reason="True Positive")
        append_outcome(r)
        data = json.loads((tmp_path / "outcomes.jsonl").read_text())
        assert data["outcome"] == "tp"
        assert data["closed_reason"] == "True Positive"
        assert data["ts"] == r.ts


# ---------------------------------------------------------------------------
# load_outcomes
# ---------------------------------------------------------------------------


class TestLoadOutcomes:
    def test_empty_when_file_missing(self):
        result = load_outcomes()
        assert result == []

    def test_round_trips_all_fields(self, tmp_path):
        original = _make_record(outcome="fp", closed_reason="False Positive")
        append_outcome(original)
        loaded = load_outcomes()
        assert len(loaded) == 1
        assert dataclasses.asdict(loaded[0]) == dataclasses.asdict(original)

    def test_multiple_records_loaded_in_order(self):
        append_outcome(_make_record(case_number="1"))
        append_outcome(_make_record(case_number="2"))
        append_outcome(_make_record(case_number="3"))
        loaded = load_outcomes()
        assert [r.case_number for r in loaded] == ["1", "2", "3"]

    def test_none_fields_preserved(self):
        r = _make_record(rule_name=None, entity_name=None, entity_type=None)
        append_outcome(r)
        loaded = load_outcomes()
        assert loaded[0].rule_name is None
        assert loaded[0].entity_name is None


# ---------------------------------------------------------------------------
# resolve_outcome
# ---------------------------------------------------------------------------


class TestResolveOutcome:
    def test_returns_false_for_missing_case(self):
        assert resolve_outcome("9999", "tp") is False

    def test_updates_matching_record(self):
        append_outcome(_make_record(case_number="100"))
        result = resolve_outcome("100", "tp", closed_reason="True Positive")
        assert result is True
        loaded = load_outcomes()
        assert loaded[0].outcome == "tp"
        assert loaded[0].closed_reason == "True Positive"

    def test_other_records_unaffected(self):
        append_outcome(_make_record(case_number="100"))
        append_outcome(_make_record(case_number="200"))
        resolve_outcome("100", "fp")
        loaded = load_outcomes()
        assert loaded[0].outcome == "fp"
        assert loaded[1].outcome is None

    def test_closed_reason_not_overwritten_if_none(self):
        append_outcome(_make_record(case_number="100", closed_reason="original"))
        resolve_outcome("100", "tp", closed_reason=None)
        loaded = load_outcomes()
        assert loaded[0].closed_reason == "original"


# ---------------------------------------------------------------------------
# _normalize_closed_reason
# ---------------------------------------------------------------------------


class TestNormalizeClosedReason:
    def test_none_returns_unknown(self):
        assert _normalize_closed_reason(None) == "unknown"

    def test_empty_string_returns_unknown(self):
        assert _normalize_closed_reason("") == "unknown"

    def test_false_positive(self):
        assert _normalize_closed_reason("False Positive") == "fp"

    def test_true_positive(self):
        assert _normalize_closed_reason("True Positive") == "tp"

    def test_resolved(self):
        assert _normalize_closed_reason("Resolved") == "tp"

    def test_duplicate(self):
        assert _normalize_closed_reason("Duplicate") == "duplicate"

    def test_informational(self):
        assert _normalize_closed_reason("Informational") == "noise"

    def test_case_insensitive(self):
        assert _normalize_closed_reason("FALSE POSITIVE") == "fp"
        assert _normalize_closed_reason("true positive — confirmed") == "tp"

    def test_unknown_reason(self):
        assert _normalize_closed_reason("Expired") == "unknown"
        assert _normalize_closed_reason("some other reason") == "unknown"


# ---------------------------------------------------------------------------
# auto_fill_outcomes (mock ExaClient)
# ---------------------------------------------------------------------------


class TestAutoFillOutcomes:
    # get_case is lazily imported inside auto_fill_outcomes, so patch the source module.

    def test_fills_closed_case(self, monkeypatch):
        append_outcome(_make_record(case_number="100", case_id="uuid-100"))

        monkeypatch.setattr(
            "exa.case.cases.get_case",
            lambda _client, case_id: {"caseId": case_id, "stage": "CLOSED", "closedReason": "True Positive"},
        )

        count = auto_fill_outcomes(object())
        assert count == 1
        loaded = load_outcomes()
        assert loaded[0].outcome == "tp"
        assert loaded[0].closed_reason == "True Positive"

    def test_skips_open_case(self, monkeypatch):
        append_outcome(_make_record(case_number="100", case_id="uuid-100"))

        monkeypatch.setattr(
            "exa.case.cases.get_case",
            lambda _client, case_id: {"stage": "OPEN"},
        )

        count = auto_fill_outcomes(object())
        assert count == 0
        loaded = load_outcomes()
        assert loaded[0].outcome is None

    def test_skips_already_resolved(self, monkeypatch):
        append_outcome(_make_record(case_number="100", outcome="tp"))

        calls: list = []

        def _should_not_be_called(_client, _case_id):
            calls.append(1)
            return {}

        monkeypatch.setattr("exa.case.cases.get_case", _should_not_be_called)

        count = auto_fill_outcomes(object())
        assert count == 0
        assert calls == []

    def test_tolerates_api_error(self, monkeypatch):
        append_outcome(_make_record(case_number="100", case_id="uuid-100"))

        def _raises(_client, _case_id):
            raise RuntimeError("timeout")

        monkeypatch.setattr("exa.case.cases.get_case", _raises)

        count = auto_fill_outcomes(object())
        assert count == 0

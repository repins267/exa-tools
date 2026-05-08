"""Tests for exa/case/baseline.py — HTTP mocked via pytest-httpx."""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import pytest

import exa.case.baseline as baseline_mod
import exa.case.outcomes as outcomes_mod
from exa.case.baseline import (
    CalibrationReport,
    _compute_fp_rates,
    _compute_verdict_accuracy,
    run_baseline,
)
from exa.case.outcomes import OutcomeRecord, append_outcome

BASE_URL = "https://api.us-west.exabeam.cloud"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def patch_paths(tmp_path, monkeypatch):
    """Redirect outcomes file and cache dir to tmp_path."""
    monkeypatch.setattr(outcomes_mod, "_OUTCOMES_PATH", tmp_path / "outcomes.jsonl")
    monkeypatch.setattr(baseline_mod, "_CACHE_DIR", tmp_path)


def _make_outcome(
    *,
    case_number: str = "100",
    case_id: str = "uuid-100",
    rule_name: str = "Test Rule",
    entity_name: str = "jsmith",
    verdict_issued: str = "SUSPECTED_INCIDENT",
    outcome: str | None = None,
) -> OutcomeRecord:
    return OutcomeRecord(
        ts="2026-05-01T10:00:00+00:00",
        case_number=case_number,
        case_id=case_id,
        rule_name=rule_name,
        entity_name=entity_name,
        entity_type="user",
        verdict_issued=verdict_issued,
        risk_score=85,
        score_trend="first_appearance",
        closed_reason=None,
        outcome=outcome,
    )


# ---------------------------------------------------------------------------
# LTS retention capping
# ---------------------------------------------------------------------------


class TestLTSRetention:
    def test_caps_lookback_to_retention_days(self, exa, mock_auth, tmp_path):
        mock_auth.add_response(
            url=f"{BASE_URL}/health-consumption/v1/consumption/lts",
            method="GET",
            json={"retentionDays": 60},
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/cases",
            method="POST",
            json={"rows": []},
        )

        report = run_baseline(exa, lookback_days=90)
        assert report.lookback_days_used == 60
        assert report.lts_retention_days == 60
        assert report.lookback_days_requested == 90

    def test_uses_requested_when_retention_larger(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/health-consumption/v1/consumption/lts",
            method="GET",
            json={"retentionDays": 180},
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/cases",
            method="POST",
            json={"rows": []},
        )

        report = run_baseline(exa, lookback_days=90)
        assert report.lookback_days_used == 90

    def test_lts_endpoint_failure_proceeds(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/health-consumption/v1/consumption/lts",
            method="GET",
            status_code=500,
            json={"error": "server error"},
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/cases",
            method="POST",
            json={"rows": []},
        )

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            report = run_baseline(exa, lookback_days=90)
            assert any("LTS consumption endpoint unavailable" in str(x.message) for x in w)

        assert report.lookback_days_used == 90
        assert report.lts_retention_days is None

    def test_missing_retention_field_proceeds(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/health-consumption/v1/consumption/lts",
            method="GET",
            json={"someOtherField": 42},
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/cases",
            method="POST",
            json={"rows": []},
        )

        report = run_baseline(exa, lookback_days=90)
        assert report.lookback_days_used == 90
        assert report.lts_retention_days is None


# ---------------------------------------------------------------------------
# FP rate computation
# ---------------------------------------------------------------------------


class TestComputeFPRates:
    def test_pure_fp_gives_rate_1(self):
        records = [
            _make_outcome(rule_name="Bad Rule", outcome="fp"),
            _make_outcome(rule_name="Bad Rule", outcome="fp"),
        ]
        rule_rates, _ = _compute_fp_rates(records)
        assert rule_rates["Bad Rule"] == 1.0

    def test_pure_tp_gives_rate_0(self):
        records = [
            _make_outcome(rule_name="Good Rule", outcome="tp"),
            _make_outcome(rule_name="Good Rule", outcome="tp"),
        ]
        rule_rates, _ = _compute_fp_rates(records)
        assert rule_rates["Good Rule"] == 0.0

    def test_mixed_outcomes(self):
        records = [
            _make_outcome(rule_name="Mixed Rule", outcome="tp"),
            _make_outcome(rule_name="Mixed Rule", outcome="fp"),
            _make_outcome(rule_name="Mixed Rule", outcome="fp"),
            _make_outcome(rule_name="Mixed Rule", outcome="tp"),
        ]
        rule_rates, _ = _compute_fp_rates(records)
        assert rule_rates["Mixed Rule"] == pytest.approx(0.5)

    def test_entity_fp_rates_computed(self):
        records = [
            _make_outcome(entity_name="svcaccount", outcome="fp"),
            _make_outcome(entity_name="svcaccount", outcome="fp"),
            _make_outcome(entity_name="svcaccount", outcome="tp"),
        ]
        _, entity_rates = _compute_fp_rates(records)
        assert "svcaccount" in entity_rates
        assert entity_rates["svcaccount"] == pytest.approx(2 / 3, abs=0.001)

    def test_none_outcomes_excluded(self):
        records = [
            _make_outcome(rule_name="Partial Rule", outcome="tp"),
            _make_outcome(rule_name="Partial Rule", outcome=None),
        ]
        rule_rates, _ = _compute_fp_rates(records)
        assert rule_rates["Partial Rule"] == 0.0

    def test_none_rule_name_excluded(self):
        records = [
            OutcomeRecord(
                ts="2026-05-01T00:00:00+00:00",
                case_number="x",
                case_id="y",
                rule_name=None,
                entity_name="user1",
                entity_type="user",
                verdict_issued="NEEDS_INVESTIGATION",
                risk_score=50,
                score_trend="spike",
                closed_reason=None,
                outcome="fp",
            )
        ]
        rule_rates, entity_rates = _compute_fp_rates(records)
        assert len(rule_rates) == 0
        assert "user1" in entity_rates


# ---------------------------------------------------------------------------
# Verdict accuracy
# ---------------------------------------------------------------------------


class TestComputeVerdictAccuracy:
    def test_populates_verdict_buckets(self):
        records = [
            _make_outcome(verdict_issued="SUSPECTED_INCIDENT", outcome="tp"),
            _make_outcome(verdict_issued="SUSPECTED_INCIDENT", outcome="tp"),
            _make_outcome(verdict_issued="SUSPECTED_INCIDENT", outcome="fp"),
            _make_outcome(verdict_issued="LIKELY_FP", outcome="fp"),
        ]
        acc = _compute_verdict_accuracy(records)
        assert acc["SUSPECTED_INCIDENT"]["tp"] == 2
        assert acc["SUSPECTED_INCIDENT"]["fp"] == 1
        assert acc["SUSPECTED_INCIDENT"]["total"] == 3
        assert acc["LIKELY_FP"]["fp"] == 1

    def test_none_outcomes_excluded(self):
        records = [
            _make_outcome(verdict_issued="NEEDS_INVESTIGATION", outcome=None),
        ]
        acc = _compute_verdict_accuracy(records)
        assert acc == {}

    def test_noise_and_duplicate_tracked(self):
        records = [
            _make_outcome(verdict_issued="LEARNING_PHASE_NOISE", outcome="noise"),
            _make_outcome(verdict_issued="LEARNING_PHASE_NOISE", outcome="duplicate"),
        ]
        acc = _compute_verdict_accuracy(records)
        assert acc["LEARNING_PHASE_NOISE"]["noise"] == 1
        assert acc["LEARNING_PHASE_NOISE"]["duplicate"] == 1
        assert acc["LEARNING_PHASE_NOISE"]["total"] == 2


# ---------------------------------------------------------------------------
# run_baseline integration
# ---------------------------------------------------------------------------


class TestRunBaseline:
    def _register_lts_and_cases(self, mock_auth, *, closed_cases=None, lts_retention=60):
        if lts_retention is not None:
            mock_auth.add_response(
                url=f"{BASE_URL}/health-consumption/v1/consumption/lts",
                method="GET",
                json={"retentionDays": lts_retention},
            )
        else:
            mock_auth.add_response(
                url=f"{BASE_URL}/health-consumption/v1/consumption/lts",
                method="GET",
                status_code=500,
                json={},
            )
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/cases",
            method="POST",
            json={"rows": closed_cases if closed_cases is not None else []},
        )

    def test_returns_calibration_report(self, exa, mock_auth):
        self._register_lts_and_cases(mock_auth)
        report = run_baseline(exa, lookback_days=90)
        assert isinstance(report, CalibrationReport)

    def test_outcomes_matched_count(self, exa, mock_auth):
        closed_cases = [
            {"caseId": "uuid-100", "riskScore": 90, "caseCreationTimestamp": "2026-04-01T00:00:00Z"},
            {"caseId": "uuid-200", "riskScore": 80, "caseCreationTimestamp": "2026-04-02T00:00:00Z"},
        ]
        append_outcome(_make_outcome(case_number="100", case_id="uuid-100", outcome="tp"))
        append_outcome(_make_outcome(case_number="200", case_id="uuid-200", outcome="fp"))
        append_outcome(_make_outcome(case_number="300", case_id="uuid-300", outcome="tp"))

        # auto_fill_outcomes needs the get_case endpoint for unresolved records — none here
        # closed cases search returns 2 matching IDs
        self._register_lts_and_cases(mock_auth, closed_cases=closed_cases)

        report = run_baseline(exa, lookback_days=90)
        assert report.total_closed_cases == 2
        assert report.outcomes_matched == 2  # uuid-300 not in closed list

    def test_cache_files_written(self, exa, mock_auth, tmp_path):
        append_outcome(_make_outcome(case_number="100", case_id="uuid-100", outcome="fp"))
        closed = [{"caseId": "uuid-100", "riskScore": 90, "caseCreationTimestamp": "2026-04-01T00:00:00Z"}]
        self._register_lts_and_cases(mock_auth, closed_cases=closed)

        run_baseline(exa, lookback_days=90)

        assert (tmp_path / "rule_fp_rates.json").exists()
        assert (tmp_path / "entity_fp_rates.json").exists()
        rule_rates = json.loads((tmp_path / "rule_fp_rates.json").read_text())
        assert "Test Rule" in rule_rates

    def test_rule_fp_rate_correct_from_outcomes(self, exa, mock_auth):
        # 2 FP + 1 TP for same rule → fp_rate = 2/3
        closed = [
            {"caseId": f"uuid-{i}", "riskScore": 80, "caseCreationTimestamp": "2026-04-01T00:00:00Z"}
            for i in range(3)
        ]
        outcomes_data = [
            _make_outcome(case_number=str(i), case_id=f"uuid-{i}",
                          rule_name="Noisy Rule", outcome="fp" if i < 2 else "tp")
            for i in range(3)
        ]
        for o in outcomes_data:
            append_outcome(o)

        self._register_lts_and_cases(mock_auth, closed_cases=closed)
        report = run_baseline(exa, lookback_days=90)

        assert "Noisy Rule" in report.rule_fp_rates
        assert report.rule_fp_rates["Noisy Rule"] == pytest.approx(2 / 3, abs=0.001)

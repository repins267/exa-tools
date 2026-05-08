"""Tests for case qualification engine: ip_classify, score trend, verdict, run_qualification."""

import re

import pytest

from exa.case.ip_classify import classify_ip, classify_ip_with_label
from exa.case.qualify import (
    QualificationReport,
    _compute_score_trend,
    _determine_verdict,
    _parse_rule_trigger,
    run_qualification,
)

BASE_URL = "https://api.us-west.exabeam.cloud"


# ---------------------------------------------------------------------------
# classify_ip
# ---------------------------------------------------------------------------


class TestClassifyIp:
    def test_private_rfc1918_10(self):
        assert classify_ip("10.0.0.1") == "private"

    def test_private_rfc1918_172(self):
        assert classify_ip("172.16.0.1") == "private"

    def test_private_rfc1918_192(self):
        assert classify_ip("192.168.1.100") == "private"

    def test_loopback(self):
        assert classify_ip("127.0.0.1") == "loopback"

    def test_link_local(self):
        assert classify_ip("169.254.1.1") == "loopback"

    def test_cdn_cloudflare(self):
        assert classify_ip("104.16.0.1") == "cdn"

    def test_cdn_fastly(self):
        assert classify_ip("23.235.32.1") == "cdn"

    def test_residential_comcast(self):
        # 24.x is a Comcast residential range
        assert classify_ip("24.120.18.242") == "residential"

    def test_invalid_ip_returns_unknown(self):
        assert classify_ip("not-an-ip") == "unknown"

    def test_empty_string_returns_unknown(self):
        assert classify_ip("") == "unknown"

    def test_classify_ip_with_label_cdn_includes_provider(self):
        cls, label = classify_ip_with_label("104.16.0.1")
        assert cls == "cdn"
        assert "Cloudflare" in label

    def test_classify_ip_with_label_private(self):
        cls, label = classify_ip_with_label("10.1.2.3")
        assert cls == "private"
        assert label == "private"


# ---------------------------------------------------------------------------
# _compute_score_trend
# ---------------------------------------------------------------------------


class TestScoreTrend:
    def test_first_appearance_no_prior_cases(self):
        is_high, trend, delta = _compute_score_trend(85, [])
        assert trend == "first_appearance"
        assert is_high is True
        assert delta is None

    def test_escalating_trend_detected(self):
        # Scores rising: 60, 70, 80 → current 90
        _, trend, _ = _compute_score_trend(90, [60, 70, 80])
        assert trend == "escalating"

    def test_consistent_trend_small_delta(self):
        # Non-monotonic prior [72, 68, 74] → not escalating; median=72, delta=75-72=3 ≤ 10
        _, trend, delta = _compute_score_trend(75, [72, 68, 74])
        assert trend == "consistent"
        assert delta == 3

    def test_spike_large_delta(self):
        # Current 95, prior all ~50 → delta >> 10
        _, trend, delta = _compute_score_trend(95, [50, 52, 48])
        assert trend == "spike"
        assert delta > 10

    def test_score_is_new_high_true(self):
        is_high, _, _ = _compute_score_trend(100, [80, 85, 90])
        assert is_high is True

    def test_score_is_new_high_false(self):
        is_high, _, _ = _compute_score_trend(70, [80, 85, 90])
        assert is_high is False


# ---------------------------------------------------------------------------
# _parse_rule_trigger
# ---------------------------------------------------------------------------


class TestParseRuleTrigger:
    def test_trigger_on_any_match_is_first_seen(self):
        condition = {"triggerOnAnyMatch": True}
        t, group_by, eql, desc = _parse_rule_trigger(condition, "user:*")
        assert t == "first_seen"
        assert desc is None
        assert eql == "user:*"

    def test_more_than_is_threshold_above(self):
        condition = {
            "triggerOnAnyMatch": False,
            "operator": "more_than",
            "value": "5",
            "time": 10,
            "unit": "m",
            "groupBy": ["src_ip"],
        }
        t, group_by, eql, desc = _parse_rule_trigger(condition, "activity_type:*")
        assert t == "threshold_above"
        assert desc == "> 5 events in 10m"
        assert group_by == ["src_ip"]

    def test_less_than_is_threshold_below(self):
        condition = {
            "triggerOnAnyMatch": False,
            "operator": "less_than",
            "value": "3",
            "time": 1,
            "unit": "h",
            "groupBy": [],
        }
        t, _, _, desc = _parse_rule_trigger(condition, "")
        assert t == "threshold_below"
        assert desc == "< 3 events in 1h"

    def test_unknown_operator(self):
        condition = {"triggerOnAnyMatch": False, "operator": "between"}
        t, _, _, desc = _parse_rule_trigger(condition, "")
        assert t == "unknown"
        assert desc is None


# ---------------------------------------------------------------------------
# _determine_verdict
# ---------------------------------------------------------------------------


def _make_report(**kwargs) -> QualificationReport:
    defaults = dict(
        case_number="100",
        case_id="uuid-100",
        title="Test Rule",
        risk_score=80,
        rule_name="Test Rule",
        rule_trigger_type="first_seen",
        rule_group_by=["user"],
        rule_eql="user:*",
        rule_threshold_desc=None,
        entity_name="jsmith",
        entity_type="user",
        entity_in_context_tables=[],
        prior_cases_30d=0,
        prior_scores=[],
        score_is_new_high=True,
        score_trend="first_appearance",
        score_delta=None,
        nova_summary=None,
        event_context_count=0,
        external_ips=[],
        verdict="",
        verdict_reasons=[],
        recommended_action="",
    )
    defaults.update(kwargs)
    return QualificationReport(**defaults)


class TestVerdictLogic:
    def test_suspected_incident_first_seen_no_context_first_appearance(self):
        report = _make_report(
            rule_trigger_type="first_seen",
            entity_in_context_tables=[],
            score_trend="first_appearance",
            score_is_new_high=True,
        )
        verdict, reasons, action = _determine_verdict(report)
        assert verdict == "SUSPECTED_INCIDENT"
        assert any("First-seen rule" in r for r in reasons)
        assert any("first appearance" in r for r in reasons)
        assert "Escalate" in action

    def test_suspected_incident_first_seen_escalating(self):
        report = _make_report(
            rule_trigger_type="first_seen",
            entity_in_context_tables=[],
            score_trend="escalating",
            prior_scores=[60, 70, 80],
            score_is_new_high=True,
        )
        verdict, reasons, _ = _determine_verdict(report)
        assert verdict == "SUSPECTED_INCIDENT"
        assert any("escalating" in r for r in reasons)

    def test_suspected_incident_includes_nova_when_present(self):
        report = _make_report(
            rule_trigger_type="first_seen",
            entity_in_context_tables=[],
            score_trend="first_appearance",
            nova_summary="Compromised Insider detected",
        )
        verdict, reasons, _ = _determine_verdict(report)
        assert verdict == "SUSPECTED_INCIDENT"
        assert any("Nova" in r for r in reasons)

    def test_likely_fp_entity_in_context_not_new_high(self):
        report = _make_report(
            rule_trigger_type="first_seen",
            entity_in_context_tables=["Compliance - Privileged Users"],
            score_is_new_high=False,
            score_trend="consistent",
            risk_score=75,
            prior_scores=[80, 82, 78],
        )
        verdict, reasons, action = _determine_verdict(report)
        assert verdict == "LIKELY_FP"
        assert any("Compliance - Privileged Users" in r for r in reasons)
        assert any("not a new high" in r for r in reasons)

    def test_likely_fp_threshold_rule_in_context(self):
        report = _make_report(
            rule_trigger_type="threshold_above",
            rule_threshold_desc="> 5 events in 10m",
            entity_in_context_tables=["Compliance - Service Accounts"],
            score_is_new_high=False,
            score_trend="consistent",
            prior_scores=[60, 65, 62],
        )
        verdict, reasons, _ = _determine_verdict(report)
        assert verdict == "LIKELY_FP"
        assert any("Threshold rule" in r for r in reasons)

    def test_learning_phase_noise_threshold_consistent_three_plus_prior(self):
        report = _make_report(
            rule_trigger_type="threshold_above",
            rule_threshold_desc="> 10 events in 1h",
            rule_group_by=["src_ip"],
            entity_in_context_tables=[],
            score_is_new_high=False,
            score_trend="consistent",
            prior_scores=[70, 72, 71, 69],
        )
        verdict, reasons, action = _determine_verdict(report)
        assert verdict == "LEARNING_PHASE_NOISE"
        assert any("consistent" in r for r in reasons)
        assert "Tune threshold" in action

    def test_learning_phase_noise_requires_three_prior(self):
        # Only 2 prior cases — should NOT trigger LEARNING_PHASE_NOISE
        report = _make_report(
            rule_trigger_type="threshold_above",
            rule_threshold_desc="> 10 events in 1h",
            entity_in_context_tables=[],
            score_is_new_high=True,
            score_trend="consistent",
            prior_scores=[70, 72],
        )
        verdict, _, _ = _determine_verdict(report)
        assert verdict == "NEEDS_INVESTIGATION"

    def test_needs_investigation_default(self):
        report = _make_report(
            rule_trigger_type="unknown",
            entity_in_context_tables=[],
            score_trend="spike",
            prior_scores=[50],
            score_delta=30,
            score_is_new_high=True,
        )
        verdict, reasons, _ = _determine_verdict(report)
        assert verdict == "NEEDS_INVESTIGATION"

    def test_ip_classification_not_in_verdict_reasons(self):
        report = _make_report(
            rule_trigger_type="first_seen",
            entity_in_context_tables=[],
            score_trend="first_appearance",
            external_ips=[{"ip": "24.1.2.3", "classification": "residential", "label": "residential", "port_count": 30}],
        )
        _, reasons, _ = _determine_verdict(report)
        # IP info must not appear in verdict reasons
        assert not any("residential" in r for r in reasons)
        assert not any("port" in r for r in reasons)


# ---------------------------------------------------------------------------
# run_qualification (integration, HTTP mocked)
# ---------------------------------------------------------------------------


SEARCH_CASES_RESPONSE = {
    "rows": [{
        "caseId": "case-uuid-221",
        "caseNumber": "221",
        "alertName": "First successful connection to external IP",
        "stage": "OPEN",
        "priority": "CRITICAL",
        "riskScore": 97,
        "users": ["hernibms3353627"],
        "endpoints": [],
        "caseCreationTimestamp": "2026-05-07T10:00:00Z",
        "lastUpdateTimestamp": "2026-05-07T10:05:00Z",
        "tags": [],
        "threatSummary": "Compromised Insider — C2 beacon pattern",
    }],
}

PRIOR_CASES_RESPONSE = {"rows": []}

RULES_RESPONSE = {
    "rules": [{
        "id": "rule-uuid-001",
        "name": "First successful connection to external IP",
        "description": "Detects first external connection",
        "enabled": True,
        "sequencesConfig": {
            "sequences": [{
                "id": "seq-001",
                "query": 'activity_type:"network-session" AND dest_ip:*',
                "condition": {"triggerOnAnyMatch": True},
            }]
        },
    }]
}

TABLES_RESPONSE = []  # no compliance tables

EVENTS_RESPONSE = {"rows": []}


# Regex to match correlation-rules endpoint regardless of query params
_RULES_URL_RE = re.compile(r".*/correlation-rules/v2/rules.*")


def _register_standard_mocks(mock_auth, *, rules_response=None, tables_response=None,
                               prior_cases_response=None, events_response=None,
                               rules_status=200):
    """Register the 5 standard mocks for run_qualification."""
    mock_auth.add_response(
        url=f"{BASE_URL}/threat-center/v1/search/cases",
        method="POST",
        json=SEARCH_CASES_RESPONSE,
    )
    mock_auth.add_response(
        url=_RULES_URL_RE,
        method="GET",
        json=rules_response if rules_response is not None else RULES_RESPONSE,
        status_code=rules_status,
    )
    mock_auth.add_response(
        url=f"{BASE_URL}/context-management/v1/tables",
        method="GET",
        json=tables_response if tables_response is not None else TABLES_RESPONSE,
    )
    mock_auth.add_response(
        url=f"{BASE_URL}/threat-center/v1/search/cases",
        method="POST",
        json=prior_cases_response if prior_cases_response is not None else PRIOR_CASES_RESPONSE,
    )
    mock_auth.add_response(
        url=f"{BASE_URL}/search/v2/events",
        method="POST",
        json=events_response if events_response is not None else EVENTS_RESPONSE,
    )


class TestRunQualification:
    def test_qualify_resolves_case_by_number(self, exa, mock_auth):
        _register_standard_mocks(mock_auth)
        report = run_qualification(exa, "221")
        assert isinstance(report, QualificationReport)
        assert report.case_number == "221"
        assert report.case_id == "case-uuid-221"

    def test_qualify_produces_first_seen_verdict(self, exa, mock_auth):
        _register_standard_mocks(mock_auth)
        report = run_qualification(exa, "221")
        assert report.rule_trigger_type == "first_seen"
        assert report.verdict == "SUSPECTED_INCIDENT"
        assert report.score_trend == "first_appearance"

    def test_qualify_nova_summary_populated(self, exa, mock_auth):
        _register_standard_mocks(mock_auth)
        report = run_qualification(exa, "221")
        assert report.nova_summary == "Compromised Insider — C2 beacon pattern"

    def test_qualify_raises_on_unknown_case(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/cases",
            method="POST",
            json={"rows": []},
        )
        with pytest.raises(ValueError, match="No case found"):
            run_qualification(exa, "9999")

    def test_qualify_degrades_when_rules_api_fails(self, exa, mock_auth):
        _register_standard_mocks(mock_auth, rules_status=500)
        # Should not raise — rule_trigger_type falls back to "unknown"
        report = run_qualification(exa, "221")
        assert report.rule_trigger_type == "unknown"
        assert isinstance(report, QualificationReport)

    def test_qualify_likely_fp_when_entity_in_context(self, exa, mock_auth):
        compliance_tables = [
            {
                "id": "tbl-001",
                "name": "compliance-privileged",
                "displayName": "Compliance - Privileged Users",
                "totalItems": 1,
            }
        ]
        table_records = {
            "records": [{"key": "hernibms3353627", "value": "hernibms3353627"}]
        }
        # Prior scores [98, 100] → max=100 > current=97 → score_is_new_high=False → LIKELY_FP
        prior_cases = {
            "rows": [
                {"caseId": "old-001", "riskScore": 98, "caseCreationTimestamp": "2026-04-01T00:00:00Z"},
                {"caseId": "old-002", "riskScore": 100, "caseCreationTimestamp": "2026-04-15T00:00:00Z"},
            ]
        }

        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/cases",
            method="POST",
            json=SEARCH_CASES_RESPONSE,
        )
        mock_auth.add_response(
            url=_RULES_URL_RE,
            method="GET",
            json=RULES_RESPONSE,
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=compliance_tables,
        )
        mock_auth.add_response(
            url=re.compile(r".*/context-management/v1/tables/tbl-001/records.*"),
            method="GET",
            json=table_records,
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/cases",
            method="POST",
            json=prior_cases,
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            json=EVENTS_RESPONSE,
        )
        report = run_qualification(exa, "221")
        assert report.entity_in_context_tables == ["Compliance - Privileged Users"]
        assert report.verdict == "LIKELY_FP"

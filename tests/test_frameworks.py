"""Tests for compliance framework loading and audit."""

import pytest

from exa.compliance.frameworks import (
    AVAILABLE_FRAMEWORKS,
    Control,
    load_control_queries,
    load_framework,
)

BASE_URL = "https://api.us-west.exabeam.cloud"


class TestLoadFramework:
    @pytest.mark.parametrize("fw_id", AVAILABLE_FRAMEWORKS)
    def test_load_all_frameworks(self, fw_id):
        fw = load_framework(fw_id)
        assert fw.name
        assert fw.framework == fw_id
        assert len(fw.controls) > 0

    def test_nist_csf_structure(self):
        fw = load_framework("NIST_CSF")
        assert fw.name == "NIST CSF v2.0"
        assert len(fw.leaf_controls) > 0
        assert len(fw.testable_controls) > 0
        assert len(fw.manual_controls) > 0
        assert len(fw.header_controls) > 0

    def test_control_is_leaf(self):
        leaf = Control("ID.AM-01", "Identify", "Test", siem_validatable=True)
        header = Control("ID.AM", "Identify", "Test")
        assert leaf.is_leaf is True
        assert header.is_leaf is False

    def test_invalid_framework_raises(self):
        with pytest.raises(Exception):
            load_framework("NONEXISTENT")


class TestLoadControlQueries:
    def test_nist_csf_queries(self):
        queries = load_control_queries("NIST_CSF")
        assert len(queries) > 0
        # Check a known control has queries
        assert "ID.AM-01" in queries
        qg = queries["ID.AM-01"]
        assert qg.name
        assert len(qg.queries) > 0
        assert qg.queries[0].filter

    def test_nonexistent_returns_empty(self):
        queries = load_control_queries("NONEXISTENT_FW")
        assert queries == {}

    def test_shared_query_groups(self):
        queries = load_control_queries("NIST_CSF")
        # Multiple controls should share the same query group
        groups = {qg.shared_query_group for qg in queries.values() if qg.shared_query_group}
        assert len(groups) > 0  # at least some shared groups exist


class TestAuditIntegration:
    @pytest.mark.httpx_mock(can_send_already_matched_responses=True, assert_all_responses_were_requested=False)
    def test_audit_with_mocked_search(self, exa, mock_auth):
        """Test audit runs through with mocked search results."""
        from exa.compliance.audit import run_compliance_audit

        # Mock the search endpoint — catch-all for all POST requests
        mock_auth.add_response(
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            json={"rows": [{"user": "admin", "host": "dc01"}] * 15},
        )

        report = run_compliance_audit(
            exa, "NIST_CSF", lookback_days=30, minimum_evidence=10
        )
        assert report.framework == "NIST_CSF"
        assert report.siem_testable_count > 0
        assert report.controls_pass > 0
        assert report.coverage_pct > 0


class TestSearchEvents:
    def test_search_events(self, exa, mock_auth):
        from exa.search.events import search_events

        mock_auth.add_response(
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            json={
                "rows": [
                    {"user": "admin", "host": "dc01", "approxLogTime": 1711929600000000},
                    {"user": "user1", "host": "ws01", "approxLogTime": 1711929700000000},
                ]
            },
        )
        results = search_events(
            exa,
            'activity_type:"authentication"',
            lookback_days=7,
        )
        assert len(results) == 2
        assert results[0]["user"] == "admin"
        assert "timestamp" in results[0]

    def test_search_events_raw(self, exa, mock_auth):
        from exa.search.events import search_events

        # EXA-UNVERIFIED — "metadata" field not confirmed in CLAUDE.md
        mock_auth.add_response(
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            json={"rows": [], "metadata": {"total": 0}},
        )
        result = search_events(
            exa, 'test:"query"', lookback_hours=1, raw=True
        )
        assert "metadata" in result

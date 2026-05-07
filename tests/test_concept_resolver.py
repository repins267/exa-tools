"""Tests for compliance concept resolution system."""

from __future__ import annotations

import pytest

from exa.compliance.concepts import (
    ALL_CONCEPTS,
    CONCEPT_ACTIVITY_MAP,
    PHYSICAL_ACCESS,
)
from exa.compliance.query_builder import ComplianceQueryBuilder
from exa.compliance.resolver import ConceptResolver

BASE_URL = "https://api.us-west.exabeam.cloud"


# ── Concept map ───────────────────────────────────────────────────────────────


class TestConceptMap:
    def test_all_18_concepts_in_all_concepts_set(self):
        assert len(ALL_CONCEPTS) == 18

    def test_every_concept_has_at_least_one_activity_type(self):
        for concept in ALL_CONCEPTS:
            types = CONCEPT_ACTIVITY_MAP.get(concept, [])
            assert types, f"{concept} has no activity_type mapping"

    def test_physical_access_maps_to_physical_location_access(self):
        assert "physical_location-access" in CONCEPT_ACTIVITY_MAP[PHYSICAL_ACCESS]

    def test_all_mapped_concepts_are_in_all_concepts(self):
        for concept in CONCEPT_ACTIVITY_MAP:
            assert concept in ALL_CONCEPTS, f"{concept} in map but not ALL_CONCEPTS"

    def test_no_empty_activity_type_strings(self):
        for concept, types in CONCEPT_ACTIVITY_MAP.items():
            for t in types:
                assert t.strip(), f"{concept} has an empty activity_type"


# ── ConceptResolver ───────────────────────────────────────────────────────────


class TestConceptResolver:
    def test_resolve_known_concept_returns_activity_types(self):
        r = ConceptResolver()
        types = r.resolve(["GROUP_MANAGEMENT"])
        assert "group-modify" in types

    def test_resolve_unknown_concept_returns_empty(self):
        r = ConceptResolver()
        types = r.resolve(["NONEXISTENT_CONCEPT"])
        assert types == []

    def test_resolve_empty_concepts_returns_empty(self):
        r = ConceptResolver()
        assert r.resolve([]) == []

    def test_resolve_no_active_types_returns_full_list(self):
        r = ConceptResolver()
        types = r.resolve(["NETWORK_TRAFFIC"], active_types=None)
        assert len(types) >= 3  # network-session, http-session, http-traffic, ...

    def test_resolve_with_active_types_filters(self):
        r = ConceptResolver()
        # Only network-session is "active" in the tenant
        types = r.resolve(["NETWORK_TRAFFIC"], active_types={"network-session"})
        assert "network-session" in types
        assert "http-session" not in types

    def test_resolve_physical_access_not_filtered_by_active_types(self):
        r = ConceptResolver()
        # Even with an empty active_types set, physical_location-access must appear
        types = r.resolve([PHYSICAL_ACCESS], active_types=set())
        assert "physical_location-access" in types

    def test_resolve_deduplicates_across_concepts(self):
        r = ConceptResolver()
        # AUTH_SUCCESS and PRIVILEGED_ACCESS both map to authentication
        types = r.resolve(["AUTH_SUCCESS", "PRIVILEGED_ACCESS"])
        count = types.count("authentication")
        assert count == 1

    def test_resolve_returns_sorted_list(self):
        r = ConceptResolver()
        types = r.resolve(["NETWORK_TRAFFIC"])
        assert types == sorted(types)

    def test_resolve_multiple_concepts_combines_types(self):
        r = ConceptResolver()
        types = r.resolve(["GROUP_MANAGEMENT", "AUDIT_LOG"])
        assert "group-modify" in types
        assert "audit_policy-modify" in types

    def test_oracle_version_no_cache(self, tmp_path, monkeypatch):
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        r = ConceptResolver()
        assert r.oracle_version() == "no-cache"

    def test_active_activity_types_returns_set(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            json={"rows": [
                {"activity_type": "authentication"},
                {"activity_type": "group-modify"},
                {"activity_type": "authentication"},  # duplicate — must be deduplicated
            ]},
        )
        r = ConceptResolver()
        result = r.active_activity_types(exa, lookback_days=30)
        assert isinstance(result, set)
        assert "authentication" in result
        assert "group-modify" in result
        assert len(result) == 2

    def test_active_activity_types_fails_gracefully(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            status_code=500,
        )
        r = ConceptResolver()
        result = r.active_activity_types(exa, lookback_days=30)
        assert result == set()

    def test_active_activity_types_skips_missing_field(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            json={"rows": [{"no_activity_type_here": "foo"}]},
        )
        r = ConceptResolver()
        result = r.active_activity_types(exa, lookback_days=30)
        assert result == set()


# ── ComplianceQueryBuilder ────────────────────────────────────────────────────


class TestComplianceQueryBuilder:
    def _builder(self) -> ComplianceQueryBuilder:
        return ComplianceQueryBuilder(ConceptResolver())

    def test_build_single_concept(self):
        b = self._builder()
        result = b.build(["GROUP_MANAGEMENT"])
        assert 'activity_type:"group-modify"' in result

    def test_build_uses_or_separator(self):
        b = self._builder()
        result = b.build(["NETWORK_TRAFFIC"])
        assert " OR " in result

    def test_build_deduplicates_across_concepts(self):
        b = self._builder()
        result = b.build(["AUTH_SUCCESS", "PRIVILEGED_ACCESS"])
        # authentication should appear only once
        assert result.count('"authentication"') == 1

    def test_build_empty_concepts_returns_fallback(self):
        b = self._builder()
        result = b.build([], fallback_filter='activity_type:"foo"')
        assert result == 'activity_type:"foo"'

    def test_build_empty_concepts_no_fallback_returns_empty(self):
        b = self._builder()
        result = b.build([])
        assert result == ""

    def test_build_filtered_excludes_inactive_types(self):
        b = self._builder()
        result = b.build(
            ["NETWORK_TRAFFIC"],
            active_types={"network-session"},
        )
        assert 'activity_type:"network-session"' in result
        assert "http-session" not in result

    def test_build_uses_fallback_when_all_filtered(self):
        b = self._builder()
        # Active types has nothing that NETWORK_TRAFFIC maps to
        result = b.build(
            ["NETWORK_TRAFFIC"],
            fallback_filter='activity_type:"network-traffic"',
            active_types={"authentication"},
        )
        assert result == 'activity_type:"network-traffic"'

    def test_build_physical_access_survives_empty_active_types(self):
        b = self._builder()
        result = b.build([PHYSICAL_ACCESS], active_types=set())
        assert 'activity_type:"physical_location-access"' in result

    def test_eql_values_are_double_quoted(self):
        b = self._builder()
        result = b.build(["GROUP_MANAGEMENT"])
        assert 'activity_type:"group-modify"' in result
        assert "activity_type:'group-modify'" not in result


# ── Audit integration ─────────────────────────────────────────────────────────


class TestAuditWithConcepts:
    @pytest.mark.httpx_mock(
        can_send_already_matched_responses=True,
        assert_all_responses_were_requested=False,
    )
    def test_audit_tenant_aware_queries_active_types(self, exa, mock_auth):
        from exa.compliance.audit import run_compliance_audit

        # First call: active_activity_types discovery
        mock_auth.add_response(
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            json={"rows": [{"activity_type": "authentication"}]},
        )
        # Subsequent calls: per-control evidence queries
        mock_auth.add_response(
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            json={"rows": [{"user": "admin"}] * 15},
        )
        report = run_compliance_audit(
            exa, "NIST_CSF", lookback_days=7, minimum_evidence=10, tenant_aware=True
        )
        assert report.query_mode in ("tenant-aware", "static-fallback")

    @pytest.mark.httpx_mock(
        can_send_already_matched_responses=True,
        assert_all_responses_were_requested=False,
    )
    def test_audit_no_tenant_aware_uses_static(self, exa, mock_auth):
        from exa.compliance.audit import run_compliance_audit

        mock_auth.add_response(
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            json={"rows": [{"user": "admin"}] * 15},
        )
        report = run_compliance_audit(
            exa, "NIST_CSF", lookback_days=7, minimum_evidence=10, tenant_aware=False
        )
        assert report.query_mode == "static"
        assert report.active_activity_types == []

    @pytest.mark.httpx_mock(
        can_send_already_matched_responses=True,
        assert_all_responses_were_requested=False,
    )
    def test_audit_report_has_query_mode_field(self, exa, mock_auth):
        from exa.compliance.audit import run_compliance_audit

        mock_auth.add_response(
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            json={"rows": []},
        )
        report = run_compliance_audit(
            exa, "NIST_CSF", lookback_days=7, tenant_aware=False
        )
        assert hasattr(report, "query_mode")
        assert hasattr(report, "oracle_version")
        assert hasattr(report, "active_activity_types")

    def test_concepts_loaded_from_nist_csf_json(self):
        from exa.compliance.frameworks import load_control_queries

        queries = load_control_queries("NIST_CSF")
        # PR.AA-05 should have concept annotations after migration
        assert "PR.AA-05" in queries
        qg = queries["PR.AA-05"]
        assert "GROUP_MANAGEMENT" in qg.concepts

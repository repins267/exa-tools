"""Tests for AI/LLM reference data, merge, and sync."""

import json
from pathlib import Path

import pytest

from exa.aillm.reference import ReferenceData, load_reference_data
from exa.aillm.merge import merge_aillm_data, MergedData

BASE_URL = "https://api.us-west.exabeam.cloud"


class TestLoadReferenceData:
    def test_loads_all_tables(self):
        ref = load_reference_data()
        assert len(ref.public_domains) > 0
        assert len(ref.web_domains) > 0
        assert len(ref.applications) > 0
        assert len(ref.dlp_rulesets) > 0
        assert len(ref.proxy_categories) > 0
        assert len(ref.web_categories) > 0

    def test_domains_have_key_and_risk(self):
        ref = load_reference_data()
        for d in ref.public_domains:
            assert "key" in d
            assert "risk" in d

    def test_web_domains_key_only(self):
        ref = load_reference_data()
        for d in ref.web_domains:
            assert "key" in d
            assert "risk" not in d

    def test_proxy_categories_deduplicated(self):
        ref = load_reference_data()
        keys = [c["key"].lower() for c in ref.proxy_categories]
        assert len(keys) == len(set(keys))

    def test_ipv4_domains_excluded(self):
        ref = load_reference_data()
        for d in ref.public_domains:
            parts = d["key"].split(".")
            # Should not be a pure IPv4 address
            assert not (len(parts) == 4 and all(p.isdigit() for p in parts))

    def test_malicious_domains_excluded(self):
        ref = load_reference_data()
        domain_keys = {d["key"] for d in ref.public_domains}
        assert "zeroclaw.org" not in domain_keys
        assert "zeroclaw.net" not in domain_keys


class TestMergeAILLMData:
    @pytest.fixture()
    def ref(self):
        return load_reference_data()

    def test_merge_no_discovery(self, ref):
        merged = merge_aillm_data(ref)
        assert isinstance(merged, MergedData)
        assert len(merged.public_domains) == len(ref.public_domains)
        assert merged.merge_stats.discovered_new == 0

    def test_merge_with_discovered_domains(self, ref):
        merged = merge_aillm_data(
            ref,
            discovered_domains=["brand-new-ai.example.com", "chatgpt.com"],
        )
        # chatgpt.com is already in reference, so only 1 new
        assert merged.merge_stats.discovered_new == 1
        assert merged.merge_stats.discovered_total == 2
        domain_keys = {d["key"] for d in merged.public_domains}
        assert "brand-new-ai.example.com" in domain_keys

    def test_discovered_domain_gets_medium_risk(self, ref):
        merged = merge_aillm_data(
            ref,
            discovered_domains=["newdomain.example.com"],
        )
        new_entry = next(d for d in merged.public_domains if d["key"] == "newdomain.example.com")
        assert new_entry["risk"] == "medium"

    def test_merge_with_discovered_apps(self, ref):
        merged = merge_aillm_data(
            ref,
            discovered_apps=["BrandNewAIApp", "ChatGPT"],
        )
        # ChatGPT already in reference
        assert merged.merge_stats.discovered_apps_new == 1
        app_keys = {a["key"] for a in merged.applications}
        assert "BrandNewAIApp" in app_keys

    def test_risk_override_file(self, ref, tmp_path):
        override_file = tmp_path / "overrides.json"
        override_file.write_text(json.dumps({"chatgpt.com": "critical"}))
        merged = merge_aillm_data(ref, risk_override_path=override_file)
        chatgpt = next(d for d in merged.public_domains if d["key"] == "chatgpt.com")
        assert chatgpt["risk"] == "critical"

    def test_dedup_case_insensitive(self, ref):
        merged = merge_aillm_data(
            ref,
            discovered_domains=["ChatGPT.COM"],
        )
        # Should not be added as new since chatgpt.com is already in reference
        assert merged.merge_stats.discovered_new == 0


class TestSyncIntegration:
    """Integration test that mocks the Exabeam API for a full sync."""

    def test_sync_single_table(self, exa, mock_auth):
        # Mock list tables
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=[{"name": "AI/LLM Applications", "id": "apps-123"}],
        )
        # Mock get attributes
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/attributes/Other",
            method="GET",
            json={"attributes": []},
        )
        # Mock add records
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/apps-123/addRecords",
            method="POST",
            json={"status": "ok"},
        )

        from exa.aillm.sync import sync_aillm_context_tables

        results = sync_aillm_context_tables(exa, buckets=["applications"])
        assert len(results) == 1
        assert results[0].upserted > 0
        assert results[0].errors == 0

    def test_dry_run_returns_empty_no_api_writes(self, exa, mock_auth):
        """Dry run must not call any write endpoints."""
        from exa.aillm.sync import sync_aillm_context_tables

        results = sync_aillm_context_tables(exa, dry_run=True)
        # Dry run returns empty list
        assert results == []
        # No write requests should have been made
        requests = mock_auth.get_requests()
        write_requests = [r for r in requests if r.method in ("POST", "PUT", "PATCH", "DELETE")]
        assert write_requests == [], f"Unexpected write requests: {write_requests}"

    def test_dry_run_with_discovered_domains_no_writes(self, exa, mock_auth):
        """Dry run with discovered domains still makes no API writes."""
        from exa.aillm.sync import sync_aillm_context_tables

        results = sync_aillm_context_tables(
            exa,
            dry_run=True,
            discovered_domains=["new-ai-tool.example.com"],
        )
        assert results == []
        requests = mock_auth.get_requests()
        write_requests = [r for r in requests if r.method in ("POST", "PUT", "PATCH", "DELETE")]
        assert write_requests == []


class TestGetAILLMTableStatus:
    """Tests for get_aillm_table_status()."""

    def _tables_response(self):
        """Minimal mock for all 6 AI/LLM tables with totalItems and lastUpdated."""
        return [
            {
                "id": "dlp-001",
                "name": "AI/LLM DLP Rulesets",
                "displayName": "AI/LLM DLP Rulesets",
                "totalItems": 46,
                "lastUpdated": 1744214400000,  # milliseconds
            },
            {
                "id": "proxy-001",
                "name": "AI/LLM Proxy Categories",
                "displayName": "AI/LLM Proxy Categories",
                "totalItems": 9,
                "lastUpdated": 1744214400000,
            },
            {
                "id": "pub-001",
                "name": "Public AI Domains and Risk",
                "displayName": "Public AI Domains and Risk",
                "totalItems": 221,
                "lastUpdated": 1744214400000,
            },
            {
                "id": "web-001",
                "name": "AI/LLM Web Domains",
                "displayName": "AI/LLM Web Domains",
                "totalItems": 221,
                "lastUpdated": 1744214400000,
            },
            {
                "id": "webcat-001",
                "name": "AI/LLM Web Categories",
                "displayName": "AI/LLM Web Categories",
                "totalItems": 9,
                "lastUpdated": 1744214400000,
            },
            {
                "id": "apps-001",
                "name": "AI/LLM Applications",
                "displayName": "AI/LLM Applications",
                "totalItems": 90,
                "lastUpdated": 1744214400000,
            },
        ]

    def test_returns_six_statuses(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=self._tables_response(),
        )
        from exa.aillm.status import get_aillm_table_status

        statuses = get_aillm_table_status(exa)
        assert len(statuses) == 6

    def test_record_counts_from_total_items(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=self._tables_response(),
        )
        from exa.aillm.status import get_aillm_table_status

        statuses = get_aillm_table_status(exa)
        counts = {s.table_name: s.record_count for s in statuses}
        assert counts["AI/LLM DLP Rulesets"] == 46
        assert counts["AI/LLM Applications"] == 90
        assert counts["Public AI Domains and Risk"] == 221

    def test_missing_table_shows_not_found(self, exa, mock_auth):
        """Tables not present in tenant should be marked found=False."""
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=[],  # Empty tenant
        )
        from exa.aillm.status import get_aillm_table_status

        statuses = get_aillm_table_status(exa)
        assert all(not s.found for s in statuses)
        assert all(s.record_count == 0 for s in statuses)
        assert all(s.last_updated == "Never" for s in statuses)

    def test_last_updated_parses_millisecond_timestamp(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=self._tables_response(),
        )
        from exa.aillm.status import get_aillm_table_status

        statuses = get_aillm_table_status(exa)
        populated = [s for s in statuses if s.found and s.record_count > 0]
        for s in populated:
            assert s.last_updated != "Never"
            assert s.last_updated != "Unknown"
            assert "UTC" in s.last_updated


class TestSearchLogsForAIDomains:
    """Tests for search_logs_for_ai_domains()."""

    def test_returns_distinct_domains(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            json={
                "rows": [
                    {"web_domain": "chatgpt.com", "approxLogTime": "1744214400000000"},
                    {"web_domain": "claude.ai", "approxLogTime": "1744214400000000"},
                    {"web_domain": "chatgpt.com", "approxLogTime": "1744214400000000"},  # dup
                ]
            },
        )
        from exa.aillm.discover import search_logs_for_ai_domains

        domains = search_logs_for_ai_domains(exa, lookback_days=30)
        assert "chatgpt.com" in domains
        assert "claude.ai" in domains
        # Deduplication: chatgpt.com appears once
        assert domains.count("chatgpt.com") == 1

    def test_empty_logs_returns_empty_list(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            json={"rows": []},
        )
        from exa.aillm.discover import search_logs_for_ai_domains

        domains = search_logs_for_ai_domains(exa, lookback_days=30)
        assert domains == []

    def test_domains_are_sorted(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            json={
                "rows": [
                    {"web_domain": "z-ai.com", "approxLogTime": "1744214400000000"},
                    {"web_domain": "a-ai.com", "approxLogTime": "1744214400000000"},
                    {"web_domain": "m-ai.com", "approxLogTime": "1744214400000000"},
                ]
            },
        )
        from exa.aillm.discover import search_logs_for_ai_domains

        domains = search_logs_for_ai_domains(exa, lookback_days=7)
        assert domains == sorted(domains)

    def test_discover_and_merge_adds_new_domains(self, exa, mock_auth):
        """End-to-end: discovered domains flow into merge correctly."""
        from exa.aillm.discover import search_logs_for_ai_domains
        from exa.aillm.merge import merge_aillm_data
        from exa.aillm.reference import load_reference_data

        mock_auth.add_response(
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            json={
                "rows": [
                    {"web_domain": "brand-new-llm.example.com", "approxLogTime": "1744214400000000"},
                    {"web_domain": "chatgpt.com", "approxLogTime": "1744214400000000"},
                ]
            },
        )

        ref = load_reference_data()
        discovered = search_logs_for_ai_domains(exa, lookback_days=30)
        merged = merge_aillm_data(ref, discovered_domains=discovered)

        # 1 genuinely new domain added
        assert merged.merge_stats.discovered_new == 1
        domain_keys = {d["key"] for d in merged.public_domains}
        assert "brand-new-llm.example.com" in domain_keys

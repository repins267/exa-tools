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

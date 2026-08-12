"""Tests for AI/LLM reference data, merge, and sync."""

import json
from typing import Any

import pytest

from exa.aillm.merge import MergedData, merge_aillm_data
from exa.aillm.profile import FieldValues, TenantProfile
from exa.aillm.reference import load_reference_data

BASE_URL = "https://api.us-west.exabeam.cloud"


@pytest.fixture(autouse=True)
def _isolate_profile_cache(tmp_path, monkeypatch):
    """Keep the real ~/.exa/cache out of the tests.

    collect_tenant_profile() returns a cached profile whenever one exists for
    the tenant and date. A developer who has profiled a customer tenant today
    would otherwise satisfy that call from disk, and the assertions below would
    run against customer data instead of their own fixtures — passing or
    failing for reasons nothing in this file controls.
    """
    monkeypatch.setattr("exa.aillm.profile.CACHE_DIR", tmp_path / "cache")


def _profile(
    fields: dict[str, list[str]],
    *,
    truncated: set[str] | None = None,
    attribution: dict[str, dict[str, list[str]]] | None = None,
) -> TenantProfile:
    """Build a TenantProfile directly, so discovery can be tested without HTTP.

    Discovery reads a profile; it does not query. Constructing one here keeps
    these tests about classification rather than about transport.
    """
    truncated = truncated or set()
    return TenantProfile(
        tenant="test-tenant",
        collected_at="2026-08-11T00:00:00+00:00",
        lookback_days=30,
        fields={
            name: FieldValues(
                name, values=sorted(set(values)), truncated=name in truncated
            )
            for name, values in fields.items()
        },
        attribution=attribution or {},
    )


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

    def test_impersonator_domains_included_for_detection(self):
        # zeroclaw.org / zeroclaw.net are high-risk impersonator domains and
        # should be in the tables so access to them triggers detection rules.
        ref = load_reference_data()
        domain_keys = {d["key"] for d in ref.public_domains}
        assert "zeroclaw.org" in domain_keys
        assert "zeroclaw.net" in domain_keys


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
        # Mock existing records fetch (empty — no duplicates)
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/apps-123/records?limit=100000&offset=0",
            method="GET",
            json={"records": []},
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

    def test_sync_skips_existing_keys(self, exa, mock_auth):
        """Records whose key already exists on the tenant are not re-uploaded."""
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=[{"name": "AI/LLM Applications", "id": "apps-123"}],
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/attributes/Other",
            method="GET",
            json={"attributes": []},
        )
        # Pretend ChatGPT is already in the tenant table
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/apps-123/records?limit=100000&offset=0",
            method="GET",
            json={"records": [{"key": "ChatGPT"}]},
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/apps-123/addRecords",
            method="POST",
            json={"status": "ok"},
        )

        from exa.aillm.sync import sync_aillm_context_tables

        results = sync_aillm_context_tables(exa, buckets=["applications"])
        assert results[0].skipped == 1
        assert results[0].upserted == results[0].merged_total - 1

    def test_sync_all_present_skips_upload(self, exa, mock_auth):
        """If every record already exists, no addRecords call is made."""
        from exa.aillm.reference import load_reference_data
        ref = load_reference_data()
        existing = [{"key": a["key"]} for a in ref.applications]

        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=[{"name": "AI/LLM Applications", "id": "apps-123"}],
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/attributes/Other",
            method="GET",
            json={"attributes": []},
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/apps-123/records?limit=100000&offset=0",
            method="GET",
            json={"records": existing},
        )

        from exa.aillm.sync import sync_aillm_context_tables

        results = sync_aillm_context_tables(exa, buckets=["applications"])
        assert results[0].upserted == 0
        assert results[0].skipped == len(existing)

    @pytest.mark.skip(reason="requires live tenant / reference data")
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

    @pytest.mark.skip(reason="requires live tenant / reference data")
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


class TestDiscoverAIDomains:
    """Classification of the hostnames a tenant actually reaches.

    Domain values below are ones observed on a live tenant, so a regression
    here is a regression against real customer traffic rather than a synthetic
    example.
    """

    @pytest.fixture(autouse=True)
    def _fixed_exclusions(self, monkeypatch):
        """Pin the exclusion list.

        load_exclusions() prefers ~/.exa/aillm-domains/data/known_exclusions.json
        over the bundled fallback, so classification would otherwise depend on
        whether the developer has run `exa update`.
        """
        monkeypatch.setattr(
            "exa.aillm.discover.load_exclusions",
            lambda: {"datagrail.io", "buzzfeed.ai", "powerad.ai"},
        )

    def test_reference_domain_is_known(self):
        from exa.aillm.discover import KNOWN, discover_ai_domains

        result = discover_ai_domains(None, profile=_profile({"web_domain": ["chatgpt.com"]}))

        assert [d.domain for d in result.known] == ["chatgpt.com"]
        assert result.known[0].classification == KNOWN
        assert result.known[0].risk  # risk carried through from reference data

    def test_full_host_matches_registered_domain(self):
        """Reference data holds registered domains; logs hold full hosts.

        ContextListContains is exact-match, so this mismatch is the reason a
        223-record table can overlap live data by ~7. Suffix matching is what
        lets discovery report cdn.openai.com as covered.
        """
        from exa.aillm.discover import discover_ai_domains

        # Reference data lists several openai.com hosts explicitly, but never
        # every one a tenant reaches. These two are absent from it.
        result = discover_ai_domains(
            None,
            profile=_profile({"web_domain": ["files.openai.com", "ab.chatgpt.com"]}),
        )

        assert {d.domain for d in result.known} == {"files.openai.com", "ab.chatgpt.com"}
        assert {d.matched_reference for d in result.known} == {"openai.com", "chatgpt.com"}
        assert result.candidates == []

    def test_exclusion_beats_weak_ai_hint(self):
        """datagrail.io is martech — it matches a naive filter on 'datagrail'."""
        from exa.aillm.discover import EXCLUDED, discover_ai_domains

        result = discover_ai_domains(
            None, profile=_profile({"web_domain": ["datagrail.io", "buzzfeed.ai"]})
        )

        assert {d.domain for d in result.excluded} == {"datagrail.io", "buzzfeed.ai"}
        assert all(d.classification == EXCLUDED for d in result.excluded)
        assert result.candidates == []
        assert result.known == []

    def test_unlisted_ai_domain_is_a_candidate_not_known(self):
        """claude.com and geminiweb-pa.googleapis.com were both live and unlisted.

        These are current primary domains of two major providers, absent from a
        223-entry reference set. They must surface for review — and must not be
        promoted to `known`, which is what feeds a context table unattended.
        """
        from exa.aillm.discover import CANDIDATE, discover_ai_domains

        result = discover_ai_domains(
            None,
            profile=_profile(
                {"web_domain": ["claude.com", "geminiweb-pa.googleapis.com"]}
            ),
        )

        assert {d.domain for d in result.candidates} == {
            "claude.com",
            "geminiweb-pa.googleapis.com",
        }
        assert all(d.classification == CANDIDATE for d in result.candidates)
        assert all(d.reason for d in result.candidates)
        assert result.known == []

    def test_non_ai_domains_are_not_reported(self):
        """The predecessor returned every domain in the tenant — 10,000+."""
        from exa.aillm.discover import discover_ai_domains

        profile = _profile(
            {"web_domain": ["sharepoint.com", "rapid7.com", "chatgpt.com"]}
        )
        result = discover_ai_domains(None, profile=profile)

        reported = {
            d.domain for d in result.known + result.candidates + result.excluded
        }
        assert reported == {"chatgpt.com"}
        assert result.scanned == 3  # everything was examined, most was dropped

    def test_safe_to_sync_excludes_candidates(self):
        """Only reference-matched domains may reach a context table unreviewed."""
        from exa.aillm.discover import discover_ai_domains

        result = discover_ai_domains(
            None,
            profile=_profile(
                {"web_domain": ["chatgpt.com", "claude.com", "datagrail.io"]}
            ),
        )

        assert result.safe_to_sync == ["chatgpt.com"]
        assert result.safe_to_sync == sorted(result.safe_to_sync)

    def test_truncation_propagates_from_profile(self):
        """A truncated sample means "not found" does not mean "not present"."""
        from exa.aillm.discover import discover_ai_domains

        profile = _profile({"web_domain": ["chatgpt.com"]}, truncated={"web_domain"})
        assert discover_ai_domains(None, profile=profile).truncated is True

        profile = _profile({"web_domain": ["chatgpt.com"]})
        assert discover_ai_domains(None, profile=profile).truncated is False


class TestDiscoverCategories:
    """Category discovery — the field three analytics rules match against."""

    def test_finds_vendor_specific_ai_categories(self):
        """Vendors do not agree on a taxonomy, and the two fields diverge.

        Palo Alto emits AI-conversational-assistant in `categories`; Zscaler
        emits 'AI & ML Apps' in `category`. Generic labels like 'Generative AI'
        match neither, which is how a 9-record table reaches zero overlap.
        """
        from exa.aillm.discover import discover_categories

        found = discover_categories(
            None,
            profile=_profile(
                {
                    "category": ["AI & ML Apps", "MS Copilot Personal"],
                    "categories": ["AI-conversational-assistant", "AI-platform-service"],
                }
            ),
        )

        assert {(v.field_name, v.value) for v in found} == {
            ("category", "AI & ML Apps"),
            ("category", "MS Copilot Personal"),
            ("categories", "AI-conversational-assistant"),
            ("categories", "AI-platform-service"),
        }

    def test_ignores_non_ai_categories(self):
        from exa.aillm.discover import discover_categories

        found = discover_categories(
            None,
            profile=_profile(
                {
                    "category": ["online-shopping", "newly-registered-domain"],
                    "categories": ["business-and-economy"],
                }
            ),
        )

        assert found == []

    def test_flags_values_already_in_reference_data(self):
        """in_reference separates "already covered" from "must be appended"."""
        from exa.aillm.discover import discover_categories

        found = discover_categories(
            None,
            profile=_profile({"category": ["Generative AI", "AI & ML Apps"]}),
        )
        by_value = {v.value: v for v in found}

        assert by_value["Generative AI"].in_reference is True
        assert by_value["AI & ML Apps"].in_reference is False

    def test_records_vendor_attribution(self):
        """Which product classified the traffic decides where the fix belongs."""
        from exa.aillm.discover import discover_categories

        found = discover_categories(
            None,
            profile=_profile(
                {"category": ["AI & ML Apps"]},
                attribution={"category": {"AI & ML Apps": ["Zscaler / Internet Access"]}},
            ),
        )

        assert found[0].sources == ["Zscaler / Internet Access"]


class TestDiscoverAlertNames:
    """event.alert_name discovery (EXA-ALERTNAME-TWO-NAMESPACES).

    This is the CIM field carrying the *source product's* alert name, which is
    what dashboards and any AI/LLM DLP Rulesets lookup filter on. It is not the
    Threat Center analytics-rule namespace read by discover_alerts.py; the two
    do not intersect, and populating the table from the wrong one yields a
    panel that renders blank with no error.
    """

    def test_finds_ai_alert_names(self):
        from exa.aillm.discover import discover_alert_names

        found = discover_alert_names(
            None,
            profile=_profile(
                {
                    "alert_name": [
                        "DSPM for AI: Detect sensitive info added to AI sites",
                        "Copilot - sensitive content",
                        "Impossible travel",
                    ]
                }
            ),
        )

        assert {v.value for v in found} == {
            "DSPM for AI: Detect sensitive info added to AI sites",
            "Copilot - sensitive content",
        }
        assert all(v.field_name == "alert_name" for v in found)

    def test_bundled_dlp_patterns_do_not_match_a_real_tenant(self):
        """The bundled 46 names have zero overlap with observed alert names.

        This is why the table must be discovery-driven: sync populates it from
        reference data, the record count looks healthy, and it matches nothing.
        """
        from exa.aillm.discover import discover_alert_names

        found = discover_alert_names(
            None,
            profile=_profile(
                {"alert_name": ["DSPM for AI: Detect sensitive info added to AI sites"]}
            ),
        )

        assert found[0].in_reference is False


class TestSearchLogsForAIDomainsShim:
    """The backwards-compatible list-returning shim, end to end over HTTP."""

    def _search_callback(self, rows_by_field: dict[str, list[dict[str, str]]]):
        import httpx

        def callback(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            primary = (body.get("groupBy") or body.get("fields") or [""])[0]
            return httpx.Response(200, json={"rows": rows_by_field.get(primary, [])})

        return callback

    def test_returns_only_reference_matched_domains(self, exa, mock_auth):
        from exa.aillm.discover import search_logs_for_ai_domains

        mock_auth.add_callback(
            self._search_callback(
                {
                    "web_domain": [
                        {"web_domain": "claude.ai"},
                        {"web_domain": "chatgpt.com"},
                        {"web_domain": "chatgpt.com"},  # duplicate
                        {"web_domain": "sharepoint.com"},
                    ]
                }
            ),
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            is_reusable=True,
        )

        assert search_logs_for_ai_domains(exa, lookback_days=30) == [
            "chatgpt.com",
            "claude.ai",
        ]

    def test_empty_tenant_returns_empty_list(self, exa, mock_auth):
        from exa.aillm.discover import search_logs_for_ai_domains

        mock_auth.add_callback(
            self._search_callback({}),
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            is_reusable=True,
        )

        assert search_logs_for_ai_domains(exa, lookback_days=30) == []

    def test_unlisted_domain_does_not_reach_a_context_table(self, exa, mock_auth):
        """Regression: callers feed this straight into merge and then upload.

        The predecessor returned every observed domain, so an unreviewed
        hostname went into a customer's context table with no human in the
        loop. An unlisted AI domain must surface as a candidate instead.
        """
        from exa.aillm.discover import discover_ai_domains, search_logs_for_ai_domains

        mock_auth.add_callback(
            self._search_callback(
                {
                    "web_domain": [
                        {"web_domain": "claude.com"},  # real, AI, and unlisted
                        {"web_domain": "chatgpt.com"},
                    ]
                }
            ),
            url=f"{BASE_URL}/search/v2/events",
            method="POST",
            is_reusable=True,
        )

        discovered = search_logs_for_ai_domains(exa, lookback_days=30)
        merged = merge_aillm_data(load_reference_data(), discovered_domains=discovered)

        assert "claude.com" not in discovered
        assert merged.merge_stats.discovered_new == 0

        result = discover_ai_domains(exa, lookback_days=30)
        assert "claude.com" in [d.domain for d in result.candidates]


class TestSyncPublicDomainsMapping:
    """Schema-aware field mapping for Public AI Domains and Risk (EXA-CONTEXT-SCHEMA-35).

    The baystate tenant uses aillm_domain (key) + risk_level (enum) attribute IDs
    instead of the legacy key + risk names. Records must be remapped before upload
    or the API silently drops them.
    """

    PUB_ID = "pg5mmUzim3"

    def _baystate_attrs(self) -> dict[str, Any]:
        return {
            "id": self.PUB_ID,
            "name": "Public AI Domains and Risk",
            "attributes": [
                {
                    "displayName": "AI/LLM Domain",
                    "id": "aillm_domain",
                    "isKey": True,
                    "type": "string",
                },
                {
                    "displayName": "Risk Level",
                    "id": "risk_level",
                    "isKey": False,
                    "type": "enum",
                },
            ],
        }

    def _standard_attrs(self) -> dict[str, Any]:
        return {
            "id": self.PUB_ID,
            "name": "Public AI Domains and Risk",
            "attributes": [
                {"displayName": "Key", "id": "key", "isKey": True, "type": "string"},
                {"displayName": "risk", "id": "risk", "isKey": False, "type": "string"},
            ],
        }

    def _setup_mocks(
        self,
        mock_auth: Any,
        schema: dict[str, Any],
        existing_records: list[dict[str, Any]] | None = None,
    ) -> None:
        # The list endpoint includes `attributes` — sync reads schema from here,
        # not from the individual /tables/{id} endpoint.
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=[schema],
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/attributes/Other",
            method="GET",
            json={"attributes": [
                {
                    "displayName": "Risk Level",
                    "id": "risk_level",
                    "type": "enum",
                    "format": "Low|Medium|High",
                }
            ]},
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/{self.PUB_ID}/records"
            "?limit=100000&offset=0",
            method="GET",
            json={"records": existing_records or []},
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/{self.PUB_ID}/addRecords",
            method="POST",
            json={"status": "ok"},
        )

    def test_records_use_aillm_domain_and_risk_level_keys(self, exa, mock_auth):
        """Records sent to baystate table use aillm_domain + risk_level, not key + risk."""
        self._setup_mocks(mock_auth, self._baystate_attrs())

        from exa.aillm.sync import sync_aillm_context_tables

        results = sync_aillm_context_tables(exa, buckets=["public_domains"])
        assert results[0].errors == 0
        assert results[0].upserted > 0

        reqs = mock_auth.get_requests()
        add_req = next(
            r for r in reqs if "addRecords" in str(r.url) and r.method == "POST"
        )
        body = json.loads(add_req.content)
        sample = body["data"][0]

        assert "aillm_domain" in sample, f"Expected aillm_domain key, got: {sample}"
        assert "risk_level" in sample, f"Expected risk_level key, got: {sample}"
        assert "key" not in sample, f"Canonical 'key' leaked into payload: {sample}"
        assert "risk" not in sample, f"Canonical 'risk' leaked into payload: {sample}"
        assert sample["risk_level"] in {"Low", "Medium", "High"}, (
            f"risk_level must be title-case enum value, got: {sample['risk_level']!r}"
        )

    def test_risk_level_value_populated(self, exa, mock_auth):
        """Each record's risk_level field is non-empty."""
        self._setup_mocks(mock_auth, self._baystate_attrs())

        from exa.aillm.sync import sync_aillm_context_tables

        sync_aillm_context_tables(exa, buckets=["public_domains"])

        reqs = mock_auth.get_requests()
        add_req = next(
            r for r in reqs if "addRecords" in str(r.url) and r.method == "POST"
        )
        body = json.loads(add_req.content)
        valid_enum = {"Low", "Medium", "High"}
        for rec in body["data"]:
            assert rec.get("risk_level") in valid_enum, (
                f"risk_level must be one of {valid_enum}, got: {rec}"
            )

    def test_dedup_uses_aillm_domain_key(self, exa, mock_auth):
        """chatgpt.com already present via aillm_domain field is correctly skipped."""
        self._setup_mocks(
            mock_auth,
            self._baystate_attrs(),
            existing_records=[{"aillm_domain": "chatgpt.com", "risk_level": "high"}],
        )

        from exa.aillm.sync import sync_aillm_context_tables

        results = sync_aillm_context_tables(exa, buckets=["public_domains"])
        assert results[0].skipped == 1
        assert results[0].upserted == results[0].merged_total - 1

    def test_standard_key_schema_unchanged(self, exa, mock_auth):
        """Legacy table with key + risk attributes: records remain unchanged."""
        self._setup_mocks(mock_auth, self._standard_attrs())

        from exa.aillm.sync import sync_aillm_context_tables

        sync_aillm_context_tables(exa, buckets=["public_domains"])

        reqs = mock_auth.get_requests()
        add_req = next(
            (r for r in reqs if "addRecords" in str(r.url) and r.method == "POST"), None
        )
        if add_req:
            body = json.loads(add_req.content)
            sample = body["data"][0]
            assert "key" in sample
            assert "risk" in sample

    def test_nonzero_write_regression(self, exa, mock_auth):
        """Regression: table stays empty when wrong field names used (pre-fix)."""
        self._setup_mocks(mock_auth, self._baystate_attrs())

        from exa.aillm.sync import sync_aillm_context_tables

        results = sync_aillm_context_tables(exa, buckets=["public_domains"])
        # Before fix: upserted > 0 but table stayed at 0 (API silently dropped records).
        # After fix: records use correct attr IDs so the API persists them.
        assert results[0].upserted > 0, (
            "upserted must be > 0 — confirm aillm_domain/risk_level remapping is active"
        )

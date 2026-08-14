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

    # These two were @pytest.mark.skip("requires live tenant / reference data") and so
    # never ran. That is why nothing caught the dry run reaching the table-CREATE path
    # when it stopped returning early. A skipped safety test is not a safety test.
    def _mock_tenant_with_table(self, mock_auth, *, existing_keys: list[str]) -> None:
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
            json={"records": [{"key": k} for k in existing_keys]},
        )

    @staticmethod
    def _writes(mock_auth) -> list:
        """Requests that would CHANGE tenant state. Reads are expected on a dry run."""
        return [
            r for r in mock_auth.get_requests()
            if r.method in ("PUT", "PATCH", "DELETE")
            or (r.method == "POST" and "/auth/" not in str(r.url))
        ]

    def test_dry_run_makes_no_writes(self, exa, mock_auth):
        """A dry run reads the tenant but must never write to it."""
        self._mock_tenant_with_table(mock_auth, existing_keys=[])

        from exa.aillm.sync import sync_aillm_context_tables

        results = sync_aillm_context_tables(exa, buckets=["applications"], dry_run=True)

        assert self._writes(mock_auth) == [], "dry run issued a write request"
        # It must still report a real, non-empty preview -- the old behavior
        # returned [] and never queried the tenant at all.
        assert len(results) == 1
        assert results[0].upserted > 0

    def test_dry_run_reports_delta_not_reference_size(self, exa, mock_auth):
        """The preview counts NEW records, not the whole reference set.

        The old dry run returned at phase [2/4] and printed the reference-data
        size, so a table where every key was already present still read as
        'N records would be written'.
        """
        from exa.aillm.reference import load_reference_data

        all_keys = [r["key"] for r in load_reference_data().applications]
        self._mock_tenant_with_table(mock_auth, existing_keys=all_keys)

        from exa.aillm.sync import sync_aillm_context_tables

        results = sync_aillm_context_tables(exa, buckets=["applications"], dry_run=True)

        assert self._writes(mock_auth) == []
        assert results[0].upserted == 0, "everything already present -- nothing to add"
        assert results[0].skipped == len(all_keys)

    def test_dry_run_does_not_create_a_missing_table(self, exa, mock_auth):
        """Table creation is a write. A preview must not perform it."""
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=[],  # target table absent -- a real sync would CREATE it
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/attributes/Other",
            method="GET",
            json={"attributes": []},
        )

        from exa.aillm.sync import sync_aillm_context_tables

        results = sync_aillm_context_tables(exa, buckets=["applications"], dry_run=True)

        assert self._writes(mock_auth) == [], "dry run created a table"
        assert results[0].upserted > 0  # reported as "would create, then upload"


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


class TestGapAnalysis:
    """`exa aillm gaps` — live values a table lacks, classified.

    Every value below was observed on a live healthcare tenant (baystate.use1,
    2026-08-12), so a regression here is a regression against real customer
    data. The alert-name figures from that tenant, over 30 days:

        27,777 distinct alert_name values
        19,134 Microsoft Purview per-email strings -> 2 real policy names
         7,276 Check Point machine-generated tokens
             8 genuine AI alert names

    Adding the diff unclassified would have written 27,000 records, most of them
    unmatchable and some carrying patient names.
    """

    @pytest.fixture(autouse=True)
    def _bundled_data_only(self, tmp_path, monkeypatch):
        """Pin every data source to the bundled copies.

        vendors, reference and discover all prefer ~/.exa/aillm-domains/data
        over the bundle, so classification would otherwise depend on whether the
        developer has run `exa update` — and on a TAM's machine that directory
        holds customer-derived data.
        """
        monkeypatch.setattr(
            "exa.aillm.vendors._EXTERNAL_DATA_DIR", tmp_path / "absent"
        )
        monkeypatch.setattr(
            "exa.aillm.reference._EXTERNAL_DATA_DIR", tmp_path / "absent"
        )
        monkeypatch.setattr(
            "exa.aillm.discover.load_exclusions", lambda: {"datagrail.io"}
        )

    def _validation(
        self,
        table: str,
        fields: list[str],
        missing: list[str],
        *,
        entries: list[str] | None = None,
        truncated: bool = False,
    ):
        from exa.aillm.validate import TableValidation

        return TableValidation(
            table_name=table,
            table_id="tbl-1",
            fields=fields,
            live_field=", ".join(fields),
            missing=missing,
            entries=entries or [],
            truncated_sample=truncated,
            status="DEAD",
        )

    def _report(self, validation, profile, **kwargs):
        from exa.aillm.gaps import build_gap_report

        return build_gap_report([validation], profile, **kwargs)

    # -- Purview normalisation ------------------------------------------------

    PURVIEW = "Microsoft / Microsoft Purview"

    def _purview_raw(self, policy: str, subject: str) -> str:
        return f"DLP policy ({policy}) matched for email with subject ({subject})"

    def test_purview_per_email_values_collapse_to_policy_names(self):
        """3,323 distinct values, 2 real policies. Diffing raw compares noise."""
        internal = "U.S. Health Insurance Act (HIPAA) Enhanced - Internal"
        external = "U.S. Health Insurance Act (HIPAA) Enhanced - External"
        raws = [
            self._purview_raw(internal, "RE: Patient chart"),
            self._purview_raw(internal, "FW: Lab results"),
            self._purview_raw(external, "Referral"),
        ]
        profile = _profile(
            {"alert_name": raws},
            attribution={"alert_name": {r: [self.PURVIEW] for r in raws}},
        )
        v = self._validation("AI/LLM DLP Rulesets", ["alert_name"], raws)

        table = self._report(v, profile).tables[0]

        assert table.propose == []
        assert table.by_reason() == {"high-cardinality-per-record": 3}
        assert {g.value for g in table.withhold} == {internal, external}
        # Two entries covering three live values — the collapse, in the output.
        assert table.withheld_distinct == 2
        assert table.withheld_values == 3

    def test_email_subjects_never_reach_disk(self):
        """The raw string carries the message subject. It must not be written."""
        import json as _json

        from exa.aillm.gaps import gap_report_to_dict

        raw = self._purview_raw(
            "U.S. Health Insurance Act (HIPAA) Enhanced - Internal",
            "RE: Cuevas discharge summary",
        )
        profile = _profile(
            {"alert_name": [raw]},
            attribution={"alert_name": {raw: [self.PURVIEW]}},
        )
        v = self._validation("AI/LLM DLP Rulesets", ["alert_name"], [raw])

        text = _json.dumps(gap_report_to_dict(self._report(v, profile)))

        assert "Cuevas" not in text
        assert "matched for email with subject" not in text
        assert "U.S. Health Insurance Act (HIPAA) Enhanced - Internal" in text

    def test_ai_policy_inside_a_wrapper_is_proposed_by_name_only(self):
        """The policy name is addable; the per-email string never is."""
        policy = "Default DLP policy - Protect sensitive M365 Copilot interactions"
        raw = self._purview_raw(policy, "Q3 planning")
        profile = _profile(
            {"alert_name": [raw]},
            attribution={"alert_name": {raw: [self.PURVIEW]}},
        )
        v = self._validation("AI/LLM DLP Rulesets", ["alert_name"], [raw])

        table = self._report(v, profile).tables[0]

        assert [g.value for g in table.propose] == [policy]
        assert table.propose[0].normalised is True

    # -- the classifier misses ------------------------------------------------

    def test_ai_enterprise_interactions_exported_is_proposed(self):
        """There is no word boundary between "AI" and "Enterprise".

        `\\bAI\\b` therefore skipped this Microsoft 365 audit operation on a live
        tenant, and it was one of only eight genuine AI alert names that tenant
        emitted in 30 days. The fix must not open the gate to every word
        containing "ai".
        """
        from exa.aillm.discover import is_ai_alert_name

        assert is_ai_alert_name("AIEnterpriseInteractionsExported")
        assert not is_ai_alert_name("Airport badge access denied")
        assert not is_ai_alert_name("AIRPORT")
        assert not is_ai_alert_name("Email messages removed after delivery")

        names = ["AIEnterpriseInteractionsExported", "TeamCopilotMsgInteraction"]
        profile = _profile(
            {"alert_name": names},
            attribution={"alert_name": {n: ["Microsoft / Microsoft 365"] for n in names}},
        )
        v = self._validation("AI/LLM DLP Rulesets", ["alert_name"], names)

        table = self._report(v, profile).tables[0]

        assert sorted(g.value for g in table.propose) == sorted(names)

    def test_vendor_template_is_proposed(self):
        """Asimily is not a traditional security feed and is easy to miss."""
        name = "Use of AI chatbot detected"
        profile = _profile(
            {"alert_name": [name]},
            attribution={"alert_name": {name: ["Asimily / Asimily"]}},
        )
        v = self._validation("AI/LLM DLP Rulesets", ["alert_name"], [name])

        table = self._report(v, profile).tables[0]

        assert [g.value for g in table.propose] == [name]

    # -- machine-generated noise ----------------------------------------------

    def test_check_point_tokens_are_withheld_as_machine_generated(self):
        """973 in a truncated sample, 7,276 over the full 30 days. Never data."""
        tokens = ["dga-Cai8Z.TC.893fEDbW", "Malware.TC.0059VopB"]
        profile = _profile(
            {"alert_name": tokens},
            attribution={"alert_name": {t: ["Check Point / SmartDefense"] for t in tokens}},
        )
        v = self._validation("AI/LLM DLP Rulesets", ["alert_name"], tokens)

        table = self._report(v, profile).tables[0]

        assert table.propose == []
        assert table.by_reason() == {"machine-generated": 2}

    def test_sibling_pack_supplies_the_noise_pattern(self):
        """Check Point emits the same tokens under two products.

        Only the SmartDefense pack documents them. Without the vendor-sibling
        fallback the NGFW-attributed ones were reported as "unrelated" — true,
        but it hides that they are generated rather than merely uninteresting.
        """
        token = "dga-4oe6S.TC.5658JNJy"
        profile = _profile(
            {"alert_name": [token]},
            attribution={"alert_name": {token: ["Check Point / Check Point NGFW"]}},
        )
        v = self._validation("AI/LLM DLP Rulesets", ["alert_name"], [token])

        table = self._report(v, profile).tables[0]

        assert table.withhold[0].reason == "machine-generated"

    def test_random_token_containing_llm_is_not_proposed(self):
        """`dga-6WsNw.TC.c5b8LLMs` is base62, not an LLM alert.

        The shared AI classifier matches "LLM" anywhere, which is right for
        prose and wrong for random tokens. Overriding a vendor noise pattern
        requires a word-boundary match.
        """
        token = "dga-6WsNw.TC.c5b8LLMs"
        profile = _profile(
            {"alert_name": [token]},
            attribution={"alert_name": {token: ["Check Point / SmartDefense"]}},
        )
        v = self._validation("AI/LLM DLP Rulesets", ["alert_name"], [token])

        table = self._report(v, profile).tables[0]

        assert table.propose == []
        assert table.withhold[0].reason == "machine-generated"

    def test_ai_domain_verdict_survives_the_noise_pattern(self):
        """Palo Alto's Parked:/Grayware: prefixes are noise — except when the
        domain being flagged is AI-branded, which is the shadow-AI signal."""
        names = ["Parked:broadstreet.ai", "Parked:iionads.com"]
        profile = _profile(
            {"alert_name": names},
            attribution={
                "alert_name": {n: ["Palo Alto Networks / Palo Alto NGFW"] for n in names}
            },
        )
        v = self._validation("AI/LLM DLP Rulesets", ["alert_name"], names)

        table = self._report(v, profile).tables[0]

        assert [g.value for g in table.propose] == ["Parked:broadstreet.ai"]
        assert [g.value for g in table.withhold] == ["Parked:iionads.com"]

    # -- accounting -----------------------------------------------------------

    def test_no_value_is_ever_dropped_silently(self):
        """Examined must equal accounted for, in every bucket, always."""
        raws = [
            self._purview_raw("HIPAA Enhanced - Internal", "RE: chart"),
            "dga-Cai8Z.TC.893fEDbW",
            "Use of AI chatbot detected",
            "Impossible travel",
            "Password Spray",
        ]
        profile = _profile(
            {"alert_name": raws},
            attribution={
                "alert_name": {
                    raws[0]: [self.PURVIEW],
                    raws[1]: ["Check Point / SmartDefense"],
                    raws[2]: ["Asimily / Asimily"],
                }
            },
        )
        v = self._validation("AI/LLM DLP Rulesets", ["alert_name"], raws)

        report = self._report(v, profile)
        table = report.tables[0]

        assert table.examined == len(raws)
        assert table.accounted == len(raws)
        assert table.balanced is True
        assert report.balanced is True
        assert all(g.reason for g in table.propose + table.withhold)

    def test_withheld_alert_text_is_redacted_unless_requested(self):
        profile = _profile({"alert_name": ["Impossible travel"]})
        v = self._validation(
            "AI/LLM DLP Rulesets", ["alert_name"], ["Impossible travel"]
        )

        default = self._report(v, profile).tables[0]
        assert default.withhold[0].value is None
        assert default.withhold[0].redacted is True

        opted_in = self._report(v, profile, include_withheld_values=True).tables[0]
        assert opted_in.withhold[0].value == "Impossible travel"

    def test_value_already_in_the_table_is_not_reproposed(self):
        name = "Use of AI chatbot detected"
        profile = _profile(
            {"alert_name": [name]},
            attribution={"alert_name": {name: ["Asimily / Asimily"]}},
        )
        v = self._validation(
            "AI/LLM DLP Rulesets", ["alert_name"], [name], entries=[name.lower()]
        )

        table = self._report(v, profile).tables[0]

        assert table.propose == []
        assert table.withhold[0].reason == "covered-after-normalisation"

    # -- truncation -----------------------------------------------------------

    def test_counts_are_labelled_lower_bounds_when_truncated(self):
        """A truncated sample means "not found" is not "not present"."""
        from exa.aillm.gaps import gap_report_to_dict

        profile = _profile(
            {"alert_name": ["Impossible travel"]}, truncated={"alert_name"}
        )
        v = self._validation(
            "AI/LLM DLP Rulesets", ["alert_name"], ["Impossible travel"], truncated=True
        )

        report = self._report(v, profile)
        payload = gap_report_to_dict(report)

        assert report.lower_bound is True
        assert payload["counts_are_lower_bound"] is True
        assert "alert_name" in payload["truncated_fields"]
        assert payload["tables"][0]["counts_are_lower_bound"] is True

    def test_complete_sample_is_not_labelled_a_lower_bound(self):
        profile = _profile({"alert_name": ["Impossible travel"]})
        v = self._validation(
            "AI/LLM DLP Rulesets", ["alert_name"], ["Impossible travel"]
        )

        assert self._report(v, profile).lower_bound is False

    # -- the other tables -----------------------------------------------------

    def test_domain_buckets_follow_discovery(self):
        """Gaps must not re-derive what discovery already decided."""
        hosts = ["chatgpt.com", "claude.com", "datagrail.io", "sharepoint.com"]
        profile = _profile({"web_domain": hosts})
        v = self._validation("AI/LLM Web Domains", ["web_domain"], hosts)

        table = self._report(v, profile).tables[0]
        by_value = {g.value: g.reason for g in table.withhold}

        assert [g.value for g in table.propose] == ["chatgpt.com"]
        assert by_value["claude.com"] == "needs-review"
        assert by_value["datagrail.io"] == "excluded-martech"
        assert by_value["sharepoint.com"] == "not-ai-related"

    def test_ai_categories_proposed_and_others_withheld(self):
        values = ["AI-conversational-assistant", "online-shopping"]
        profile = _profile({"category": values})
        v = self._validation("AI/LLM Web Categories", ["category"], values)

        table = self._report(v, profile).tables[0]

        assert [g.value for g in table.propose] == ["AI-conversational-assistant"]
        assert [g.value for g in table.withhold] == ["online-shopping"]

    def test_interpreters_need_review_and_model_runtimes_are_proposed(self):
        """python.exe runs the AI frameworks — and everything else.

        Six rules read each process-name table. Auto-adding an interpreter fires
        all of them on the whole estate.
        """
        values = ["ollama.exe", "python.exe", "EXCEL.EXE"]
        profile = _profile({"process_name": values})
        v = self._validation(
            "AI Agent Process Names", ["process_name", "parent_process_name"], values
        )

        table = self._report(v, profile).tables[0]
        by_value = {g.value: g.reason for g in table.withhold}

        assert [g.value for g in table.propose] == ["ollama.exe"]
        assert by_value["python.exe"] == "needs-review"
        assert by_value["EXCEL.EXE"] == "not-ai-related"

    def test_app_values_use_reference_data_then_provider_tokens(self):
        values = ["ChatGPT", "Copilot.M365.Teams", "Workday"]
        profile = _profile({"app": values})
        v = self._validation("AI/LLM Applications", ["app"], values)

        table = self._report(v, profile).tables[0]

        assert sorted(g.value for g in table.propose) == [
            "ChatGPT",
            "Copilot.M365.Teams",
        ]
        assert [g.value for g in table.withhold] == ["Workday"]

    def test_a_misparsed_domain_carrying_an_identity_is_redacted(self):
        """Field type is not a safety guarantee.

        A parser artefact put `<creds><USR>firstname.lastname@<customer>.org<`
        into `web_domain` on a live tenant — a structured taxonomy field holding
        a raw log fragment naming a person. The content test has to run on every
        field, not only the ones known to be free text.
        """
        import json as _json

        from exa.aillm.gaps import gap_report_to_dict

        leak = "<creds><USR>Brandon.Andrews@baystatehealth.org<"
        profile = _profile({"web_domain": [leak, "chatgpt.com"]})
        v = self._validation("AI/LLM Web Domains", ["web_domain"], [leak, "chatgpt.com"])

        report = self._report(v, profile)
        table = report.tables[0]
        text = _json.dumps(gap_report_to_dict(report))

        assert "baystatehealth.org" not in text
        assert "Brandon" not in text
        assert any(g.redacted for g in table.withhold)
        assert table.balanced is True

    def test_listing_is_capped_but_counts_stay_complete(self):
        """43,461 withheld domains produced a 43 MB file nobody would open.

        Capping the LISTING is fine; losing the count is not. The elision has to
        be stated in the file rather than inferred from its absence.
        """
        from exa.aillm.gaps import gap_report_to_dict

        hosts = [f"host{i}.example.com" for i in range(50)]
        profile = _profile({"web_domain": hosts})
        v = self._validation("AI/LLM Web Domains", ["web_domain"], hosts)

        payload = gap_report_to_dict(
            self._report(v, profile), max_listed_per_reason=10
        )
        table = payload["tables"][0]

        assert table["withheld_values"] == 50
        assert table["withheld_by_reason"] == {"not-ai-related": 50}
        assert len(table["withhold"]) == 10
        assert table["withhold_listing"] == {
            "max_listed_per_reason": 10,
            "listed": 10,
            "not_listed": 40,
        }
        assert table["balanced"] is True

    def test_per_record_shapes_are_never_proposed(self):
        """No pack to normalise with, so nothing can rescue these."""
        from exa.aillm.gaps import is_per_record

        assert is_per_record("Copilot alert for user jane.doe@example.org")
        assert is_per_record("AI policy " + "x" * 200)
        assert not is_per_record("Use of AI chatbot detected")

        raw = "GenAI upload alert for jane.doe@example.org"
        profile = _profile({"alert_name": [raw]})
        v = self._validation("AI/LLM DLP Rulesets", ["alert_name"], [raw])

        table = self._report(v, profile).tables[0]

        assert table.propose == []
        assert table.withhold[0].reason == "high-cardinality-per-record"
        assert table.withhold[0].value is None  # raw text stays off disk


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


class TestGapsApply:
    """apply_gaps -- the only write path in the aillm module.

    Every test here guards a failure the API reports as success: a write under
    the wrong key attribute, a duplicate from a stale report, or a withheld
    value promoted by accident.
    """

    TABLE_ID = "tbl-dlp"
    TABLES_URL = f"{BASE_URL}/context-management/v1/tables"

    def _report(self, tmp_path, propose, withhold=None):
        import json as _json

        payload = {
            "tenant": "t",
            "tables": [
                {
                    "table": "AI/LLM DLP Rulesets",
                    "table_id": self.TABLE_ID,
                    "key_attr": "key",
                    "propose": [
                        {"value": v, "reason": "ai-related", "redacted": False}
                        for v in propose
                    ],
                    "withhold": withhold or [],
                }
            ],
        }
        path = tmp_path / "gaps.json"
        path.write_text(_json.dumps(payload), encoding="utf-8")
        return path

    def _mock_reads(self, mock_auth, *, key_attr="alert_name", existing=()):
        # get_tables() returns `attributes` inline, so resolve_table_schema()
        # needs no second call. Mirror that -- a fixture that omits them would
        # pass while hiding an extra round trip per table on the real API.
        mock_auth.add_response(
            url=self.TABLES_URL,
            method="GET",
            json=[
                {
                    "id": self.TABLE_ID,
                    "name": "AI/LLM DLP Rulesets",
                    "displayName": "AI/LLM DLP Rulesets",
                    "attributes": [{"id": key_attr, "isKey": True}],
                }
            ],
        )
        mock_auth.add_response(
            url=f"{self.TABLES_URL}/{self.TABLE_ID}/records?limit=100000&offset=0",
            method="GET",
            json={"records": [{key_attr: v} for v in existing]},
        )

    def test_dry_run_issues_no_write(self, exa, mock_auth, tmp_path):
        """Dry run is the default and must stay read-only. The whole point of
        the reviewable report is defeated if reviewing it writes."""
        from exa.aillm.gaps import apply_gaps

        self._mock_reads(mock_auth)
        report = self._report(tmp_path, ["DSPM for AI: Detect sensitive info"])

        results = apply_gaps(exa, report)

        assert results[0].written == 1, "dry run still reports what it would write"
        assert results[0].status == "DryRun"
        assert not [
            r for r in mock_auth.get_requests() if r.method == "POST" and "addRecords" in str(r.url)
        ], "dry run must not POST"

    def test_write_uses_the_resolved_key_attribute(self, exa, mock_auth, tmp_path):
        """EXA-TABLE-KEY-ATTR: the key is not always 'key'. Writing under the
        wrong one is accepted with HTTP 200 and lands nothing."""
        import json as _json

        from exa.aillm.gaps import apply_gaps

        self._mock_reads(mock_auth, key_attr="alert_name")
        mock_auth.add_response(
            url=f"{self.TABLES_URL}/{self.TABLE_ID}/addRecords",
            method="POST",
            json={"trackerId": "trk-1", "jsonEntries": 1},
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/uploadStatus/trk-1",
            method="GET",
            json={"status": "Completed", "totalUploaded": 1, "totalErrors": 0},
        )
        report = self._report(tmp_path, ["AIEnterpriseInteractionsExported"])

        results = apply_gaps(exa, report, dry_run=False)

        add = next(
            r for r in mock_auth.get_requests() if "addRecords" in str(r.url)
        )
        record = _json.loads(add.content)["data"][0]
        assert record == {"alert_name": "AIEnterpriseInteractionsExported"}, (
            f"wrote under the report's key_attr instead of the live one: {record}"
        )
        assert results[0].key_attr == "alert_name"
        assert results[0].written == 1

    def test_value_already_present_is_not_rewritten(self, exa, mock_auth, tmp_path):
        """addRecords is additive. A report older than the table would otherwise
        duplicate anything that arrived in between."""
        from exa.aillm.gaps import apply_gaps

        self._mock_reads(mock_auth, existing=["Already There"])
        report = self._report(tmp_path, ["Already There"])

        results = apply_gaps(exa, report, dry_run=False)

        assert results[0].already_present == 1
        assert results[0].written == 0
        assert results[0].skipped_reason == "all proposals already present"
        assert not [
            r for r in mock_auth.get_requests() if "addRecords" in str(r.url)
        ], "nothing new to write, so nothing should be POSTed"

    def test_withheld_values_are_never_written(self, exa, mock_auth, tmp_path):
        """No flag on this command can promote a withheld value. Purview's
        withheld strings carry message subjects, i.e. patient names."""
        from exa.aillm.gaps import apply_gaps

        self._mock_reads(mock_auth)
        report = self._report(
            tmp_path,
            ["Genuine Policy"],
            withhold=[
                {
                    "value": "DLP policy matched for email w/ subject: <redacted>",
                    "reason": "high-cardinality-per-record",
                    "redacted": True,
                }
            ],
        )

        results = apply_gaps(exa, report)

        assert results[0].proposed == 1, "only the propose bucket is considered"
        assert results[0].written == 1

    def test_table_absent_from_tenant_is_reported_not_created(
        self, exa, mock_auth, tmp_path
    ):
        """A missing table means the tenant is on different content, not that
        we should invent one -- creating it would look like success and match
        nothing."""
        from exa.aillm.gaps import apply_gaps

        mock_auth.add_response(url=self.TABLES_URL, method="GET", json=[])
        report = self._report(tmp_path, ["Genuine Policy"])

        results = apply_gaps(exa, report, dry_run=False)

        assert results[0].skipped_reason == "table not present on tenant"
        assert results[0].written == 0
        assert not results[0].ok

    def test_table_filter_restricts_the_write(self, exa, mock_auth, tmp_path):
        from exa.aillm.gaps import apply_gaps

        mock_auth.add_response(url=self.TABLES_URL, method="GET", json=[])
        report = self._report(tmp_path, ["Genuine Policy"])

        results = apply_gaps(exa, report, tables=["AI/LLM Web Domains"])

        assert results == [], "a table not named in --table is not touched at all"

    def test_upload_errors_surface_as_not_ok(self, exa, mock_auth, tmp_path):
        """A partial upload must not read as success -- the POST already
        returned 200 before any of this was known."""
        from exa.aillm.gaps import apply_gaps

        self._mock_reads(mock_auth)
        mock_auth.add_response(
            url=f"{self.TABLES_URL}/{self.TABLE_ID}/addRecords",
            method="POST",
            json={"trackerId": "trk-9", "jsonEntries": 2},
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/uploadStatus/trk-9",
            method="GET",
            json={"status": "Completed", "totalUploaded": 1, "totalErrors": 1},
        )
        report = self._report(tmp_path, ["Policy A", "Policy B"])

        results = apply_gaps(exa, report, dry_run=False)

        assert results[0].errors == 1
        assert not results[0].ok


class TestUniversalDashboard:
    """build_dashboard -- CP4: two tenants, one config.

    The hand-built Landscapes these replace carried hardcoded domains, one
    tenant's action vocabulary, and pasted category strings. Point either at
    another customer and panels go blank silently, because a filter matching
    nothing renders as an empty chart rather than an error. These tests pin the
    properties that prevent that from creeping back.
    """

    TABLES_URL = f"{BASE_URL}/context-management/v1/tables"

    ALL_TABLES = (
        "AI/LLM Web Domains",
        "Public AI Domains and Risk",
        "AI/LLM Proxy Categories",
        "AI/LLM Applications",
        "AI/LLM DLP Rulesets",
    )

    def _mock_tables(self, mock_auth, ids, *, use_display_name=True):
        rows = []
        for name, tid in ids.items():
            row = {"id": tid, "name": name}
            row["displayName"] = name if use_display_name else None
            rows.append(row)
        mock_auth.add_response(url=self.TABLES_URL, method="GET", json=rows)

    def _ids(self, prefix):
        return {name: f"{prefix}-{i}" for i, name in enumerate(self.ALL_TABLES)}

    def test_two_tenants_differ_only_in_table_ids(self, exa, mock_auth):
        """CP4. Opaque 10-char IDs hide differences from the naked eye, so the
        comparison has to be mechanical."""
        from exa.aillm.dashboard import build_dashboard, portable_form

        self._mock_tables(mock_auth, self._ids("aaa"))
        first = build_dashboard(exa).config

        self._mock_tables(mock_auth, self._ids("zzz"))
        second = build_dashboard(exa).config

        assert first != second, "table IDs should differ between tenants"
        assert portable_form(first) == portable_form(second), (
            "configs differ by something other than resolved table IDs"
        )

    def test_no_panel_hardcodes_a_tenant_value(self, exa, mock_auth):
        """The specific values that made the hand-built versions unportable."""
        import json as _json

        from exa.aillm.dashboard import build_dashboard

        self._mock_tables(mock_auth, self._ids("t"))
        blob = _json.dumps(build_dashboard(exa).config).lower()

        for banned in (
            "deepseek.ai",
            "stablediffusionweb",
            "openai.com",
            "character.ai",
            "check point",
            "zscaler",
            "purview",
            "generative ai and ml applications",
        ):
            assert banned not in blob, f"tenant-specific value leaked in: {banned}"

    def test_outcome_is_pivoted_never_filtered(self, exa, mock_auth):
        """action vocabulary is vendor-specific -- Accept/Prevent at Check Point,
        Allowed/Blocked at Zscaler. Filtering on it is what broke portability."""
        from exa.aillm.dashboard import build_dashboard

        self._mock_tables(mock_auth, self._ids("t"))
        config = build_dashboard(exa).config

        for element in config["dashboardElements"]:
            filters = element.get("filters") or {}
            assert "event.action" not in filters, (
                f"panel {element.get('title')!r} filters on action"
            )
            assert "event.result" not in filters, (
                f"panel {element.get('title')!r} filters on result, which no "
                "Microsoft-sourced agent telemetry populates"
            )

        pivoted = [
            e
            for e in config["dashboardElements"]
            if "event.action" in (e.get("pivots") or [])
        ]
        assert pivoted, "no panel pivots on action"

    def test_every_vis_panel_is_scoped(self, exa, mock_auth):
        """An unfiltered panel renders every event on the tenant and looks like
        a working AI panel -- how one OOTB dashboard came to report ~200M/day
        beside a pie reporting 551."""
        from exa.aillm.dashboard import build_dashboard

        self._mock_tables(mock_auth, self._ids("t"))
        config = build_dashboard(exa).config

        for element in config["dashboardElements"]:
            if element.get("type") != "vis":
                continue
            filters = element.get("filters") or {}
            scoping = set(filters) - {"event.approx_log_time"}
            assert scoping, (
                f"panel {element.get('title')!r} has only a time filter -- it "
                "would plot total tenant ingest"
            )

    def test_context_panels_set_apply_context_rule(self, exa, mock_auth):
        """context_rule without apply_context_rule=Yes is ignored silently."""
        from exa.aillm.dashboard import build_dashboard

        self._mock_tables(mock_auth, self._ids("t"))
        config = build_dashboard(exa).config

        for element in config["dashboardElements"]:
            filters = element.get("filters") or {}
            if "event.context_rule" in filters:
                assert filters.get("event.apply_context_rule") == "Yes", (
                    f"panel {element.get('title')!r} binds a table but never "
                    "applies it"
                )

    def test_missing_table_skips_the_panel(self, exa, mock_auth):
        """Never emit the panel unfiltered as a fallback."""
        from exa.aillm.dashboard import build_dashboard

        ids = self._ids("t")
        del ids["AI/LLM DLP Rulesets"]
        self._mock_tables(mock_auth, ids)

        build = build_dashboard(exa)

        assert any("DLP Rulesets" in s for s in build.skipped)
        titles = [e.get("title", "") for e in build.config["dashboardElements"]]
        assert not any("DLP Alerts" in t for t in titles)

    def test_tenant_with_null_display_names_still_resolves(self, exa, mock_auth):
        """displayName is null on entire tenants (EXA-DISPLAYNAME-UNDOCUMENTED).
        Falling back to name is what keeps every panel from being skipped."""
        from exa.aillm.dashboard import build_dashboard

        self._mock_tables(mock_auth, self._ids("t"), use_display_name=False)

        build = build_dashboard(exa)

        assert not build.skipped, f"skipped on null-displayName tenant: {build.skipped}"
        assert len(build.resolved) == len(self.ALL_TABLES)

    def test_category_binds_to_proxy_categories_not_web_categories(
        self, exa, mock_auth
    ):
        """CP0. Web Categories feeds analytics rules; the dashboards read Proxy
        Categories for event.category. One hand-built Landscape bound this to
        the rules table and rendered a plausible but wrong slice."""
        from exa.aillm.dashboard import build_dashboard

        ids = self._ids("t")
        ids["AI/LLM Web Categories"] = "wrong-table"
        self._mock_tables(mock_auth, ids)

        build = build_dashboard(exa)

        assert build.resolved["AI/LLM Proxy Categories"]
        assert "AI/LLM Web Categories" not in build.resolved

    def test_context_rule_encoding(self):
        from exa.aillm.dashboard import build_context_rule

        assert build_context_rule("web_domain", "JfPvofJzKB") == (
            "web_domainContextRuleSeparatorinContextRuleSeparatorcustom"
            "ContextRuleSeparatorraw_entity_other_customContextRuleSeparator"
            "JfPvofJzKB"
        )

    def test_header_tile_carries_no_markup(self, exa, mock_auth):
        """The text tile renders neither HTML nor markdown -- proven in a live
        tenant. Markup ships as literal characters."""
        from exa.aillm.dashboard import build_dashboard

        self._mock_tables(mock_auth, self._ids("t"))
        config = build_dashboard(exa).config

        body = config["dashboardElements"][0]["body_text"]
        for markup in ("<b>", "<br", "<div", "**", "##", "|---"):
            assert markup not in body, f"markup in text tile: {markup}"


class TestAILLMReport:
    """state / changes / drift.

    The failure this guards is a report that reads as reassuring because it was
    built on an absent baseline, a stale reference set, or a truncated sample.
    All three produce a clean-looking page and none of them raise.
    """

    TABLES_URL = f"{BASE_URL}/context-management/v1/tables"

    def _state(self, name, records, table_id="t1"):
        from exa.aillm.report import TableState

        return TableState(
            name=name, table_id=table_id, key_attr="key", records=records
        )

    def _mock_tables(self, mock_auth, rows):
        # get_tables() returns `attributes` inline, so resolve_table_schema()
        # needs no follow-up call. A fixture omitting them passes while hiding
        # one extra round trip per table against the real API.
        for row in rows:
            row.setdefault("attributes", [{"id": "key", "isKey": True}])
        mock_auth.add_response(url=self.TABLES_URL, method="GET", json=rows)

    def test_no_baseline_is_not_no_change(self, exa, mock_auth, tmp_path, monkeypatch):
        """An empty change list on a first run must not render as 'nothing
        moved' -- that is the difference between 'we checked' and 'we can't'."""
        from exa.aillm import report as report_mod

        monkeypatch.setattr(report_mod, "SNAPSHOT_DIR", tmp_path)
        self._mock_tables(
            mock_auth,
            [{"id": "a", "name": "AI/LLM Applications", "totalItems": 5}],
        )

        rep = report_mod.build_report(exa, "acme", include_drift=False)

        assert not rep.has_baseline
        assert rep.changes == []
        html = report_mod.generate_html_report(rep)
        assert "No previous snapshot" in html
        assert "nothing to compare" in html.lower()

    def test_baseline_round_trip_reports_movement(
        self, exa, mock_auth, tmp_path, monkeypatch
    ):
        from exa.aillm import report as report_mod

        monkeypatch.setattr(report_mod, "SNAPSHOT_DIR", tmp_path)
        rows = [{"id": "a", "name": "AI/LLM Applications", "totalItems": 5}]
        self._mock_tables(mock_auth, rows)
        first = report_mod.build_report(exa, "acme", include_drift=False)
        report_mod.save_baseline(first)

        rows[0]["totalItems"] = 9
        self._mock_tables(mock_auth, rows)
        second = report_mod.build_report(exa, "acme", include_drift=False)

        assert second.has_baseline
        moved = [c for c in second.changes if c.moved]
        assert len(moved) == 1
        assert moved[0].before == 5
        assert moved[0].after == 9
        assert moved[0].delta == 4

    def test_corrupt_baseline_does_not_read_as_unchanged(
        self, exa, mock_auth, tmp_path, monkeypatch
    ):
        """A truncated snapshot file must degrade to 'no baseline', never to an
        empty diff that implies stability."""
        from exa.aillm import report as report_mod

        monkeypatch.setattr(report_mod, "SNAPSHOT_DIR", tmp_path)
        snap = tmp_path / "acme" / "state.json"
        snap.parent.mkdir(parents=True)
        snap.write_text("{not json", encoding="utf-8")

        self._mock_tables(
            mock_auth, [{"id": "a", "name": "AI/LLM Applications", "totalItems": 5}]
        )
        rep = report_mod.build_report(exa, "acme", include_drift=False)

        assert not rep.has_baseline

    def test_uses_total_items_not_num_records(self, exa, mock_auth, tmp_path, monkeypatch):
        """numRecords does not exist. Reading it yields 0 for every table and
        reports a fully populated tenant as empty."""
        from exa.aillm import report as report_mod

        monkeypatch.setattr(report_mod, "SNAPSHOT_DIR", tmp_path)
        self._mock_tables(
            mock_auth,
            [
                {
                    "id": "a",
                    "name": "AI/LLM Applications",
                    "totalItems": 162,
                    "numRecords": 0,
                }
            ],
        )

        rep = report_mod.build_report(exa, "acme", include_drift=False)

        state = next(t for t in rep.tables if t.name == "AI/LLM Applications")
        assert state.records == 162

    def test_absent_table_is_reported_not_silently_zero(
        self, exa, mock_auth, tmp_path, monkeypatch
    ):
        from exa.aillm import report as report_mod

        monkeypatch.setattr(report_mod, "SNAPSHOT_DIR", tmp_path)
        self._mock_tables(mock_auth, [])

        rep = report_mod.build_report(exa, "acme", include_drift=False)

        assert rep.missing_tables, "every table absent but none reported missing"
        html = report_mod.generate_html_report(rep)
        assert "absent from this tenant" in html

    def test_truncation_marks_every_count_a_lower_bound(self):
        """A drift list presented as complete retires a question still open."""
        from exa.aillm.report import AILLMReport, DriftItem, generate_html_report

        rep = AILLMReport(
            tenant="acme",
            collected_at="2026-08-13T00:00:00+00:00",
            lookback_days=30,
            drift=[DriftItem(field_name="web_domain", value="new-ai.example")],
            truncated_fields=["web_domain"],
        )

        assert rep.counts_are_lower_bound
        html = generate_html_report(rep)
        assert "lower bound" in html.lower()
        assert "1+" in html, "drift count not marked as bounded"

    def test_stale_reference_is_stated_next_to_drift(self):
        """Drift is measured against the reference data, so its age qualifies
        the result. A clean drift list off stale data looks like good news."""
        from exa.aillm.report import AILLMReport, generate_html_report

        rep = AILLMReport(
            tenant="acme",
            collected_at="2026-08-13T00:00:00+00:00",
            lookback_days=30,
            reference_summary="bundled snapshot (frozen at release)",
            reference_stale=True,
        )

        html = generate_html_report(rep)
        assert "Reference data is stale" in html

    def test_html_escapes_values(self):
        """Drift values are free text from the source product."""
        from exa.aillm.report import AILLMReport, DriftItem, generate_html_report

        rep = AILLMReport(
            tenant="acme",
            collected_at="2026-08-13T00:00:00+00:00",
            lookback_days=30,
            drift=[
                DriftItem(field_name="alert_name", value="<script>alert(1)</script>")
            ],
        )

        html = generate_html_report(rep)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_html_defines_colors_outside_media_query(self):
        """A color defined only inside prefers-color-scheme renders one theme's
        text on the other theme's ground for viewers on the default setting."""
        from exa.aillm.report import AILLMReport, generate_html_report

        html = generate_html_report(
            AILLMReport(
                tenant="acme",
                collected_at="2026-08-13T00:00:00+00:00",
                lookback_days=30,
            )
        )
        base = html.split("@media")[0]
        for token in ("--bg:", "--fg:", "--muted:", "--line:", "--panel:"):
            assert token in base, f"{token} only defined inside a media query"

    def test_default_report_path_shape(self):
        from exa.aillm.report import default_report_path

        path = default_report_path("baystate", "2026-08-13")
        assert path.name == "baystate-aillm-2026-08-13.html"
        assert path.parent.name == "reports"


class TestReferenceFreshness:
    def test_bundled_is_always_stale(self, monkeypatch, tmp_path):
        """The bundled snapshot is frozen at release, so it can never be
        current -- saying otherwise invites trusting it."""
        from exa.aillm import reference

        monkeypatch.setattr(reference, "_EXTERNAL_DATA_DIR", tmp_path / "nope")

        fresh = reference.reference_freshness()

        assert fresh.source == "bundled"
        assert fresh.stale
        assert "exa update" in fresh.summary

    def test_fresh_external_is_not_stale(self, monkeypatch, tmp_path):
        from exa.aillm import reference

        (tmp_path / "known_ai_domains.json").write_text("[]", encoding="utf-8")
        monkeypatch.setattr(reference, "_EXTERNAL_DATA_DIR", tmp_path)

        fresh = reference.reference_freshness()

        assert fresh.source == "external"
        assert not fresh.stale

    def test_old_external_is_stale(self, monkeypatch, tmp_path):
        import os
        import time

        from exa.aillm import reference

        old = tmp_path / "known_ai_domains.json"
        old.write_text("[]", encoding="utf-8")
        stamp = time.time() - (reference.STALE_AFTER_DAYS + 5) * 86400
        os.utime(old, (stamp, stamp))
        monkeypatch.setattr(reference, "_EXTERNAL_DATA_DIR", tmp_path)

        fresh = reference.reference_freshness()

        assert fresh.stale
        assert "exa update" in fresh.summary


class TestAILLMWatch:
    """watch -- one pass over every tenant.

    Each test guards a way this could under-report while looking complete: a run
    that stops early, a first run that reads as reassuring, or a floor presented
    as a total.
    """

    def _reports(self, monkeypatch, mapping):
        """Stub build_report per tenant. mapping: name -> report or Exception."""
        from exa.aillm import report as report_mod

        def fake_client(name=None):
            class _C:
                def close(self):
                    return None

            return _C()

        def fake_build(client, tenant, **kw):
            outcome = mapping[tenant]
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        # watch_tenants imports these inside the function body, so patching the
        # source modules is what takes effect at call time.
        monkeypatch.setattr("exa.cli.app._make_client", fake_client)
        monkeypatch.setattr(report_mod, "build_report", fake_build)
        monkeypatch.setattr(report_mod, "save_baseline", lambda r: None)
        monkeypatch.setattr(report_mod, "save_html_report", lambda r, p: None)

    def _report(self, tenant, *, baseline=True, moved=0, truncated=False, missing=()):
        from exa.aillm.report import AILLMReport, TableChange

        changes = [
            TableChange(name=f"t{i}", before=1, after=2) for i in range(moved)
        ]
        return AILLMReport(
            tenant=tenant,
            collected_at="2026-08-13T00:00:00+00:00",
            lookback_days=30,
            changes=changes,
            baseline_at="2026-08-01T00:00:00+00:00" if baseline else None,
            truncated_fields=["web_domain"] if truncated else [],
            tables=[],
        )

    def test_one_tenant_failing_does_not_abort_the_run(
        self, monkeypatch, tmp_path
    ):
        """A watch that stops on tenant 2 of 4 reports on 1 and looks complete."""
        from exa.aillm.watch import FAILED, watch_tenants

        self._reports(
            monkeypatch,
            {
                "a": self._report("a"),
                "b": RuntimeError("auth failed"),
                "c": self._report("c", moved=2),
                "d": self._report("d", baseline=False),
            },
        )

        run = watch_tenants(["a", "b", "c", "d"], out_dir=tmp_path)

        assert run.attempted == 4, "a failure ended the run early"
        assert [t.tenant for t in run.by_state(FAILED)] == ["b"]
        assert "auth failed" in run.by_state(FAILED)[0].error

    def test_failed_tenant_appears_in_the_index(self, monkeypatch, tmp_path):
        """A tenant that could not be reached must be visible, not absent --
        absence reads as 'nothing to say about it'."""
        from exa.aillm.watch import generate_index_html, watch_tenants

        self._reports(
            monkeypatch, {"a": self._report("a"), "b": RuntimeError("boom")}
        )
        run = watch_tenants(["a", "b"], out_dir=tmp_path)

        html = generate_index_html(run)
        assert "b" in html
        assert "failed" in html.lower()
        assert "boom" in html

    def test_no_baseline_is_its_own_state_not_quiet(self, monkeypatch, tmp_path):
        """Folding 'cannot compare' into 'nothing changed' turns an open
        question into a reassurance."""
        from exa.aillm.watch import NO_BASELINE, QUIET, watch_tenants

        self._reports(
            monkeypatch,
            {"fresh": self._report("fresh", baseline=False), "old": self._report("old")},
        )

        run = watch_tenants(["fresh", "old"], out_dir=tmp_path)

        assert [t.tenant for t in run.by_state(NO_BASELINE)] == ["fresh"]
        assert [t.tenant for t in run.by_state(QUIET)] == ["old"]

    def test_moved_and_failed_sort_before_quiet(self, monkeypatch, tmp_path):
        """Reading order, not run order -- the point is which accounts need you."""
        from exa.aillm.watch import watch_tenants

        self._reports(
            monkeypatch,
            {
                "quiet1": self._report("quiet1"),
                "moved1": self._report("moved1", moved=1),
                "bad1": RuntimeError("x"),
            },
        )

        run = watch_tenants(["quiet1", "moved1", "bad1"], out_dir=tmp_path)

        assert [t.tenant for t in run.ordered][:2] == ["bad1", "moved1"]
        assert run.ordered[-1].tenant == "quiet1"

    def test_lower_bounds_are_marked_and_not_summed(self, monkeypatch, tmp_path):
        """A cross-tenant total built from floors is a floor, and printing it as
        a figure reads as exact."""
        from exa.aillm.watch import generate_index_html, watch_tenants

        self._reports(
            monkeypatch,
            {"a": self._report("a", truncated=True), "b": self._report("b")},
        )

        run = watch_tenants(["a", "b"], out_dir=tmp_path)

        assert run.any_lower_bound
        html = generate_index_html(run)
        assert "lower bound" in html.lower()
        assert "not summed" in html.lower()

    def test_missing_tables_flag_attention_even_when_quiet(
        self, monkeypatch, tmp_path
    ):
        """A tenant whose tables are absent has nothing to move, so 'quiet' would
        be the most misleading possible label."""
        from exa.aillm.watch import watch_tenants

        rep = self._report("a")
        rep.tables = []
        self._reports(monkeypatch, {"a": rep})
        run = watch_tenants(["a"], out_dir=tmp_path)
        run.tenants[0].missing_tables = ["AI/LLM DLP Rulesets"]

        assert run.tenants[0].needs_attention

    def test_index_is_written_and_self_contained(self, monkeypatch, tmp_path):
        from exa.aillm.watch import save_index, watch_tenants

        self._reports(monkeypatch, {"a": self._report("a")})
        run = watch_tenants(["a"], out_dir=tmp_path)
        path = save_index(run, tmp_path)

        html = path.read_text(encoding="utf-8")
        assert path.name == "index.html"
        assert "http://" not in html and "https://" not in html
        assert "<script" not in html

    def test_configured_tenants_reads_the_same_source_as_config_tenants(
        self, monkeypatch
    ):
        """A divergence here silently skips accounts the user believes covered."""
        from exa.aillm import watch as watch_mod

        monkeypatch.setattr(
            "exa.config._read_config_file",
            lambda: {"tenants": {"zeta": {}, "alpha": {}}},
        )

        assert watch_mod.configured_tenants() == ["alpha", "zeta"]

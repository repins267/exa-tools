"""Tests for search_events (POST /search/v2/events)."""

import json

from exa.search import search_events

BASE_URL = "https://api.us-west.exabeam.cloud"
SEARCH_URL = f"{BASE_URL}/search/v2/events"

EQL_FILTER = 'activity_type:"authentication"'

APPROX_LOG_TIME = 1_746_000_000_000_000  # 2025-04-30T04:00:00Z in microseconds

EVENT_ROW = {
    "user": "jsmith",
    "host": "WORKSTATION-01",
    "src_ip": "10.0.0.1",
    "dest_ip": "10.0.0.254",
    "activity_type": "authentication",
    "outcome": "success",
    "approxLogTime": APPROX_LOG_TIME,
}

SEARCH_RESPONSE = {"rows": [EVENT_ROW]}


class TestSearchEventsBodyKey:
    def test_uses_query_key_not_filter(self, exa, mock_auth):
        mock_auth.add_response(url=SEARCH_URL, method="POST", json=SEARCH_RESPONSE)
        search_events(exa, EQL_FILTER, lookback_hours=1, limit=3)
        request = mock_auth.get_request(url=SEARCH_URL)
        body = json.loads(request.content)
        assert "query" in body, "EQL string must go in 'query' key"

    def test_mandatory_filter_key_present(self, exa, mock_auth):
        """EXA-SEARCH-FILTER-400: 'filter' key must always be present."""
        mock_auth.add_response(url=SEARCH_URL, method="POST", json=SEARCH_RESPONSE)
        search_events(exa, EQL_FILTER, lookback_hours=1, limit=3)
        request = mock_auth.get_request(url=SEARCH_URL)
        body = json.loads(request.content)
        assert "filter" in body, "body must include 'filter' key (EXA-SEARCH-FILTER-400)"

    def test_eql_sent_in_both_query_and_filter(self, exa, mock_auth):
        """The EQL must reach BOTH keys, because tenants disagree about which they honour.

        This assertion previously demanded `filter == ""`, encoding the belief that
        `query` carried the EQL. Measured 2026-08-12 against baystate.use1 (US-East)
        and csnsafusion (SA), that is wrong on both: sending EQL only in `query`
        returns the UNFILTERED result set -- on csnsafusion, byte-identical to
        sending no filter at all (72 rows / 71 distinct activity types either way).
        No error is raised, so every caller silently got every event.

        Sending it in both is deliberate. If a tenant honours `query` it filters, if
        it honours `filter` it filters, and if it ANDs them the same EQL twice is the
        same result -- verified to return the correct single-value result on both.
        """
        mock_auth.add_response(url=SEARCH_URL, method="POST", json=SEARCH_RESPONSE)
        search_events(exa, EQL_FILTER, lookback_hours=1, limit=3)
        body = json.loads(mock_auth.get_request(url=SEARCH_URL).content)
        assert body["query"] == EQL_FILTER
        assert body["filter"] == EQL_FILTER

    def test_empty_eql_leaves_both_keys_empty(self, exa, mock_auth):
        """A catch-all search must not accidentally send a filter to either key."""
        mock_auth.add_response(url=SEARCH_URL, method="POST", json=SEARCH_RESPONSE)
        search_events(exa, "", lookback_hours=1, limit=3)
        body = json.loads(mock_auth.get_request(url=SEARCH_URL).content)
        assert body["query"] == ""
        assert body["filter"] == ""

    def test_eql_string_reaches_api_unchanged(self, exa, mock_auth):
        mock_auth.add_response(url=SEARCH_URL, method="POST", json=SEARCH_RESPONSE)
        search_events(exa, EQL_FILTER, lookback_hours=1, limit=3)
        request = mock_auth.get_request(url=SEARCH_URL)
        body = json.loads(request.content)
        assert body["query"] == EQL_FILTER


class TestSearchEventsGroupBy:
    def test_group_by_excludes_approx_log_time(self, exa, mock_auth):
        """GROUP BY queries reject fields not in group_by — approxLogTime must be omitted."""
        mock_auth.add_response(url=SEARCH_URL, method="POST", json={"rows": []})
        search_events(exa, EQL_FILTER, fields=["web_domain"], group_by=["web_domain"])
        request = mock_auth.get_request(url=SEARCH_URL)
        body = json.loads(request.content)
        assert "approxLogTime" not in body["fields"]
        assert body["groupBy"] == ["web_domain"]

    def test_non_group_by_includes_approx_log_time(self, exa, mock_auth):
        mock_auth.add_response(url=SEARCH_URL, method="POST", json={"rows": []})
        search_events(exa, EQL_FILTER, fields=["web_domain"])
        request = mock_auth.get_request(url=SEARCH_URL)
        body = json.loads(request.content)
        assert "approxLogTime" in body["fields"]


class TestSearchEventsResults:
    def test_returns_rows(self, exa, mock_auth):
        mock_auth.add_response(url=SEARCH_URL, method="POST", json=SEARCH_RESPONSE)
        result = search_events(exa, EQL_FILTER, lookback_hours=1, limit=3)
        assert len(result) == 1
        assert result[0]["user"] == "jsmith"
        assert result[0]["activity_type"] == "authentication"

    def test_approx_log_time_converted_to_timestamp(self, exa, mock_auth):
        mock_auth.add_response(url=SEARCH_URL, method="POST", json=SEARCH_RESPONSE)
        result = search_events(exa, EQL_FILTER, lookback_hours=1)
        assert "timestamp" in result[0]
        # approxLogTime microseconds → epoch seconds → ISO string
        assert result[0]["timestamp"].startswith("2025-04-")

    def test_empty_result(self, exa, mock_auth):
        mock_auth.add_response(url=SEARCH_URL, method="POST", json={"rows": []})
        result = search_events(exa, EQL_FILTER)
        assert result == []

    def test_raw_mode_returns_full_response(self, exa, mock_auth):
        mock_auth.add_response(url=SEARCH_URL, method="POST", json=SEARCH_RESPONSE)
        result = search_events(exa, EQL_FILTER, raw=True)
        assert isinstance(result, dict)
        assert "rows" in result

    def test_limit_sent_in_body(self, exa, mock_auth):
        mock_auth.add_response(url=SEARCH_URL, method="POST", json={"rows": []})
        search_events(exa, EQL_FILTER, limit=42)
        request = mock_auth.get_request(url=SEARCH_URL)
        body = json.loads(request.content)
        assert body["limit"] == 42


class TestFieldRequestContract:
    """The API returns ONLY requested fields, so absent reads as null.

    Measured 2026-08-13 on a live tenant: 50,000 dns-response events read with
    the default field set showed dns_domain "0% populated", which supported a
    conclusion that the vendor's parser was dropping the queried domain.
    Requesting the field returned it on 99.2% of the SAME events. The parser was
    fine; the default hid the data. These tests pin the guard.
    """

    def test_filtered_fields_are_returned(self, exa, mock_auth):
        """Filtering on a field and not getting it back is the sharp edge."""
        import json as _json

        mock_auth.add_response(
            url=f"{BASE_URL}/search/v2/events", method="POST", json={"rows": []}
        )
        from exa.search.events import search_events

        search_events(exa, 'activity_type:"dns-response" dns_domain:RGXi("chatgpt")')

        body = _json.loads(
            next(r for r in mock_auth.get_requests() if "search/v2/events" in str(r.url)).content
        )
        assert "dns_domain" in body["fields"], (
            f"filtered on dns_domain but did not request it back: {body['fields']}"
        )
        assert "activity_type" in body["fields"]

    def test_explicit_fields_still_win(self, exa, mock_auth):
        import json as _json

        mock_auth.add_response(
            url=f"{BASE_URL}/search/v2/events", method="POST", json={"rows": []}
        )
        from exa.search.events import search_events

        search_events(exa, 'categories:RGXi("Generative AI")', fields=["dns_query"])

        body = _json.loads(
            next(r for r in mock_auth.get_requests() if "search/v2/events" in str(r.url)).content
        )
        assert "dns_query" in body["fields"]
        assert "categories" in body["fields"], "filter field not added to explicit list"
        assert "user" not in body["fields"], "default set leaked in over an explicit list"

    def test_eql_operators_are_not_mistaken_for_fields(self):
        from exa.search.events import _fields_in_filter

        found = _fields_in_filter(
            'activity_type:"x" AND NOT dns_domain:RGXi("y") OR host:WLDi("*z*")'
        )
        assert found == ["activity_type", "dns_domain", "host"], found

    def test_empty_filter_adds_nothing(self):
        from exa.search.events import _fields_in_filter

        assert _fields_in_filter("") == []

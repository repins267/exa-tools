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
        assert "query" in body, "body must use 'query' key, not 'filter'"
        assert "filter" not in body, "'filter' key must not appear in body"

    def test_eql_string_reaches_api_unchanged(self, exa, mock_auth):
        mock_auth.add_response(url=SEARCH_URL, method="POST", json=SEARCH_RESPONSE)
        search_events(exa, EQL_FILTER, lookback_hours=1, limit=3)
        request = mock_auth.get_request(url=SEARCH_URL)
        body = json.loads(request.content)
        assert body["query"] == EQL_FILTER


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

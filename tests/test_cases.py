"""Tests for Threat Center case and alert operations."""

from datetime import UTC, datetime

from exa.case import (
    create_case,
    get_alert,
    get_case,
    search_alerts,
    search_cases,
    update_alert,
    update_case,
)

BASE_URL = "https://api.us-west.exabeam.cloud"

# ---------------------------------------------------------------------------
# Fixtures / shared data
# ---------------------------------------------------------------------------

CASE_ROW = {
    "caseId": "case-uuid-001",
    "caseNumber": "C-1001",
    "alertName": "Suspicious PowerShell Activity",
    "stage": "IN PROGRESS",
    "priority": "HIGH",
    "riskScore": 87,
    "queue": "Tier-1",
    "assignee": "analyst@corp.com",
    "caseCreationTimestamp": "2026-05-01T12:00:00Z",
    "lastUpdateTimestamp": "2026-05-02T08:00:00Z",
    "tags": ["malware", "powershell"],
    "users": ["jsmith"],
    "endpoints": ["WORKSTATION-01"],
    "threatSummary": "High-risk PowerShell encoded command detected.",
}

ALERT_ROW = {
    "alertId": "alert-uuid-001",
    "alertName": "Code42 High Severity Alert",
    "priority": "HIGH",
    "riskScore": 72,
    "caseId": "case-uuid-001",
    "alertCreationTimestamp": "2026-05-01T11:00:00Z",
    "lastUpdateTimestamp": "2026-05-01T11:30:00Z",
    "tags": ["dlp"],
    "users": ["jsmith"],
}

SEARCH_CASES_RESPONSE = {
    "startTime": "2026-04-01T00:00:00Z",
    "endTime": "2026-05-01T00:00:00Z",
    "rows": [CASE_ROW],
    "totalRows": 1,
}

SEARCH_ALERTS_RESPONSE = {
    "startTime": "2026-04-01T00:00:00Z",
    "endTime": "2026-05-01T00:00:00Z",
    "rows": [ALERT_ROW],
    "totalRows": 1,
}


# ---------------------------------------------------------------------------
# search_cases
# ---------------------------------------------------------------------------

class TestSearchCases:
    def test_returns_rows(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/cases",
            method="POST",
            json=SEARCH_CASES_RESPONSE,
        )
        result = search_cases(exa, lookback_days=30)
        assert len(result) == 1
        assert result[0]["caseId"] == "case-uuid-001"
        assert result[0]["caseNumber"] == "C-1001"

    def test_with_filter(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/cases",
            method="POST",
            json=SEARCH_CASES_RESPONSE,
        )
        result = search_cases(exa, filter='NOT stage:"CLOSED"', lookback_days=7)
        assert len(result) == 1

    def test_raw_mode(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/cases",
            method="POST",
            json=SEARCH_CASES_RESPONSE,
        )
        result = search_cases(exa, raw=True)
        assert "rows" in result
        assert "totalRows" in result
        assert result["totalRows"] == 1

    def test_empty_rows(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/cases",
            method="POST",
            json={"rows": [], "totalRows": 0},
        )
        result = search_cases(exa)
        assert result == []

    def test_request_body_contains_fields(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/cases",
            method="POST",
            json=SEARCH_CASES_RESPONSE,
        )
        search_cases(exa, fields=["caseId", "stage"], limit=100, lookback_days=7)
        import json
        request = mock_auth.get_request(url=f"{BASE_URL}/threat-center/v1/search/cases")
        body = json.loads(request.content)
        assert body["fields"] == ["caseId", "stage"]
        assert body["limit"] == 100

    def test_default_fields_is_star(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/cases",
            method="POST",
            json=SEARCH_CASES_RESPONSE,
        )
        search_cases(exa)
        import json
        request = mock_auth.get_request(url=f"{BASE_URL}/threat-center/v1/search/cases")
        body = json.loads(request.content)
        assert body["fields"] == ["*"]

    def test_absolute_time_range(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/cases",
            method="POST",
            json=SEARCH_CASES_RESPONSE,
        )
        start = datetime(2026, 4, 1, tzinfo=UTC)
        end = datetime(2026, 5, 1, tzinfo=UTC)
        search_cases(exa, start_time=start, end_time=end)
        import json
        request = mock_auth.get_request(url=f"{BASE_URL}/threat-center/v1/search/cases")
        body = json.loads(request.content)
        assert body["startTime"] == "2026-04-01T00:00:00Z"
        assert body["endTime"] == "2026-05-01T00:00:00Z"


# ---------------------------------------------------------------------------
# get_case
# ---------------------------------------------------------------------------

class TestGetCase:
    def test_returns_case(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/cases/case-uuid-001",
            method="GET",
            json=CASE_ROW,
        )
        result = get_case(exa, "case-uuid-001")
        assert result["caseId"] == "case-uuid-001"
        assert result["stage"] == "IN PROGRESS"
        assert result["priority"] == "HIGH"

    def test_correct_endpoint(self, exa, mock_auth):
        case_id = "abc-123"
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/cases/{case_id}",
            method="GET",
            json={"caseId": case_id},
        )
        result = get_case(exa, case_id)
        assert result["caseId"] == case_id


# ---------------------------------------------------------------------------
# update_case
# ---------------------------------------------------------------------------

class TestUpdateCase:
    def test_update_stage(self, exa, mock_auth):
        updated = {**CASE_ROW, "stage": "CLOSED", "closedReason": "False Positive"}
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/cases/case-uuid-001",
            method="POST",
            json=updated,
        )
        result = update_case(
            exa, "case-uuid-001",
            stage="CLOSED",
            closed_reason="False Positive",
        )
        assert result["stage"] == "CLOSED"

    def test_update_priority_and_assignee(self, exa, mock_auth):
        updated = {**CASE_ROW, "priority": "CRITICAL", "assignee": "senior@corp.com"}
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/cases/case-uuid-001",
            method="POST",
            json=updated,
        )
        result = update_case(
            exa, "case-uuid-001",
            priority="CRITICAL",
            assignee="senior@corp.com",
        )
        assert result["priority"] == "CRITICAL"
        assert result["assignee"] == "senior@corp.com"

    def test_only_provided_fields_sent(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/cases/case-uuid-001",
            method="POST",
            json=CASE_ROW,
        )
        update_case(exa, "case-uuid-001", tags=["reviewed"])
        import json
        request = mock_auth.get_request(url=f"{BASE_URL}/threat-center/v1/cases/case-uuid-001")
        body = json.loads(request.content)
        assert body == {"tags": ["reviewed"]}

    def test_update_name_uses_alert_name_key(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/cases/case-uuid-001",
            method="POST",
            json=CASE_ROW,
        )
        update_case(exa, "case-uuid-001", name="New Case Name")
        import json
        request = mock_auth.get_request(url=f"{BASE_URL}/threat-center/v1/cases/case-uuid-001")
        body = json.loads(request.content)
        assert "alertName" in body
        assert body["alertName"] == "New Case Name"


# ---------------------------------------------------------------------------
# create_case
# ---------------------------------------------------------------------------

class TestCreateCase:
    def test_create_minimal(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/cases",
            method="POST",
            json={**CASE_ROW, "caseId": "new-case-uuid"},
        )
        result = create_case(exa, "alert-uuid-001")
        assert result["caseId"] == "new-case-uuid"

    def test_create_with_options(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/cases",
            method="POST",
            json={**CASE_ROW, "caseId": "new-case-uuid"},
        )
        create_case(
            exa, "alert-uuid-001",
            stage="IN PROGRESS",
            priority="HIGH",
            queue="Tier-1",
        )
        import json
        request = mock_auth.get_request(url=f"{BASE_URL}/threat-center/v1/cases")
        body = json.loads(request.content)
        assert body["alertId"] == "alert-uuid-001"
        assert body["stage"] == "IN PROGRESS"
        assert body["priority"] == "HIGH"
        assert body["queue"] == "Tier-1"

    def test_request_body_contains_alert_id(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/cases",
            method="POST",
            json=CASE_ROW,
        )
        create_case(exa, "my-alert-id")
        import json
        request = mock_auth.get_request(url=f"{BASE_URL}/threat-center/v1/cases")
        body = json.loads(request.content)
        assert body["alertId"] == "my-alert-id"


# ---------------------------------------------------------------------------
# search_alerts
# ---------------------------------------------------------------------------

class TestSearchAlerts:
    def test_returns_rows(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/alerts",
            method="POST",
            json=SEARCH_ALERTS_RESPONSE,
        )
        result = search_alerts(exa, lookback_days=30)
        assert len(result) == 1
        assert result[0]["alertId"] == "alert-uuid-001"

    def test_with_filter(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/alerts",
            method="POST",
            json=SEARCH_ALERTS_RESPONSE,
        )
        result = search_alerts(exa, filter='priority:"HIGH"')
        assert len(result) == 1

    def test_raw_mode(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/alerts",
            method="POST",
            json=SEARCH_ALERTS_RESPONSE,
        )
        result = search_alerts(exa, raw=True)
        assert "totalRows" in result
        assert result["totalRows"] == 1

    def test_empty_response(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/alerts",
            method="POST",
            json={"rows": [], "totalRows": 0},
        )
        result = search_alerts(exa)
        assert result == []

    def test_default_order_by_risk_score(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/search/alerts",
            method="POST",
            json=SEARCH_ALERTS_RESPONSE,
        )
        search_alerts(exa)
        import json
        request = mock_auth.get_request(url=f"{BASE_URL}/threat-center/v1/search/alerts")
        body = json.loads(request.content)
        assert body["orderBy"] == ["riskScore DESC"]


# ---------------------------------------------------------------------------
# get_alert
# ---------------------------------------------------------------------------

class TestGetAlert:
    def test_returns_alert(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/alerts/alert-uuid-001",
            method="GET",
            json=ALERT_ROW,
        )
        result = get_alert(exa, "alert-uuid-001")
        assert result["alertId"] == "alert-uuid-001"
        assert result["priority"] == "HIGH"

    def test_correct_endpoint(self, exa, mock_auth):
        alert_id = "xyz-456"
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/alerts/{alert_id}",
            method="GET",
            json={"alertId": alert_id},
        )
        result = get_alert(exa, alert_id)
        assert result["alertId"] == alert_id


# ---------------------------------------------------------------------------
# update_alert
# ---------------------------------------------------------------------------

class TestUpdateAlert:
    def test_update_priority(self, exa, mock_auth):
        updated = {**ALERT_ROW, "priority": "CRITICAL"}
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/alerts/alert-uuid-001",
            method="POST",
            json=updated,
        )
        result = update_alert(exa, "alert-uuid-001", priority="CRITICAL")
        assert result["priority"] == "CRITICAL"

    def test_update_tags(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/alerts/alert-uuid-001",
            method="POST",
            json=ALERT_ROW,
        )
        update_alert(exa, "alert-uuid-001", tags=["reviewed", "dlp"])
        import json
        request = mock_auth.get_request(url=f"{BASE_URL}/threat-center/v1/alerts/alert-uuid-001")
        body = json.loads(request.content)
        assert body == {"tags": ["reviewed", "dlp"]}

    def test_only_provided_fields_sent(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/alerts/alert-uuid-001",
            method="POST",
            json=ALERT_ROW,
        )
        update_alert(exa, "alert-uuid-001", name="Renamed Alert")
        import json
        request = mock_auth.get_request(url=f"{BASE_URL}/threat-center/v1/alerts/alert-uuid-001")
        body = json.loads(request.content)
        assert list(body.keys()) == ["alertName"]
        assert body["alertName"] == "Renamed Alert"

    def test_update_name_uses_alert_name_key(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/threat-center/v1/alerts/alert-uuid-001",
            method="POST",
            json=ALERT_ROW,
        )
        update_alert(exa, "alert-uuid-001", name="New Name")
        import json
        request = mock_auth.get_request(url=f"{BASE_URL}/threat-center/v1/alerts/alert-uuid-001")
        body = json.loads(request.content)
        assert "alertName" in body
        assert "name" not in body

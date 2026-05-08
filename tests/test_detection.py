"""Tests for Detection (analytics) rule management."""

import json

import pytest

from exa.detection import (
    diff_rules,
    export_rules,
    get_detection_rule,
    get_detection_rules,
    import_rules,
    set_detection_rule_state,
)

BASE_URL = "https://api.us-west.exabeam.cloud"
_BASE = "/detection-management/v1/analytics-rules"

# ---------------------------------------------------------------------------
# Fixtures / shared data
# ---------------------------------------------------------------------------

RULE_A = {
    "id": "rule-uuid-001",
    "name": "Suspicious PowerShell Execution",
    "isEnabled": True,
    "state": "Active",
    "severity": "High",
    "description": "Detects encoded PowerShell commands",
}

RULE_B = {
    "id": "rule-uuid-002",
    "name": "Brute Force Login Attempt",
    "isEnabled": False,
    "state": "Active",
    "severity": "Medium",
    "description": "Detects rapid failed authentication",
}

RULES_LIST_RESPONSE = {"rules": [RULE_A, RULE_B], "total": 2}

EXPORT_BUNDLE = {"rules": [RULE_A, RULE_B], "version": "1.0"}

IMPORT_RESULT = {"imported": 2, "skipped": 0, "errors": []}


# ---------------------------------------------------------------------------
# get_detection_rules
# ---------------------------------------------------------------------------

class TestGetDetectionRules:
    def test_returns_rules_list(self, exa, mock_auth):
        # No url= — GET params are appended as query string, so exact URL won't match
        mock_auth.add_response(method="GET", json=RULES_LIST_RESPONSE)
        result = get_detection_rules(exa)
        assert len(result) == 2
        assert result[0]["id"] == "rule-uuid-001"

    def test_filter_by_name_client_side(self, exa, mock_auth):
        # API always returns all rules; name filter is applied client-side
        mock_auth.add_response(method="GET", json=RULES_LIST_RESPONSE)
        result = get_detection_rules(exa, name="PowerShell")
        assert len(result) == 1
        assert result[0]["id"] == "rule-uuid-001"

    def test_filter_by_name_case_insensitive(self, exa, mock_auth):
        mock_auth.add_response(method="GET", json=RULES_LIST_RESPONSE)
        result = get_detection_rules(exa, name="powershell")
        assert len(result) == 1

    def test_filter_by_status_enabled(self, exa, mock_auth):
        mock_auth.add_response(method="GET", json=RULES_LIST_RESPONSE)
        result = get_detection_rules(exa, status="enabled")
        assert len(result) == 1
        assert result[0]["isEnabled"] is True

    def test_filter_by_status_disabled(self, exa, mock_auth):
        mock_auth.add_response(method="GET", json=RULES_LIST_RESPONSE)
        result = get_detection_rules(exa, status="disabled")
        assert len(result) == 1
        assert result[0]["isEnabled"] is False

    def test_limit_applied_client_side(self, exa, mock_auth):
        mock_auth.add_response(method="GET", json=RULES_LIST_RESPONSE)
        result = get_detection_rules(exa, limit=1)
        assert len(result) == 1

    def test_no_query_params_sent_to_api(self, exa, mock_auth):
        mock_auth.add_response(method="GET", json=RULES_LIST_RESPONSE)
        get_detection_rules(exa, name="PowerShell", status="enabled", limit=1)
        request = mock_auth.get_request(url=f"{BASE_URL}{_BASE}")
        assert "?" not in str(request.url)

    def test_empty_response(self, exa, mock_auth):
        mock_auth.add_response(method="GET", json={"rules": []})
        result = get_detection_rules(exa)
        assert result == []

    def test_raw_list_response(self, exa, mock_auth):
        mock_auth.add_response(method="GET", json=[RULE_A, RULE_B])
        result = get_detection_rules(exa)
        assert isinstance(result, list)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# get_detection_rule
# ---------------------------------------------------------------------------

class TestGetDetectionRule:
    def test_returns_rule_by_id(self, exa, mock_auth):
        # Per-ID endpoint returns 404 on sademodev22; implementation fetches all and filters.
        mock_auth.add_response(method="GET", json=RULES_LIST_RESPONSE)
        result = get_detection_rule(exa, "rule-uuid-001")
        assert result["id"] == "rule-uuid-001"
        assert result["name"] == "Suspicious PowerShell Execution"

    def test_raises_for_missing_id(self, exa, mock_auth):
        mock_auth.add_response(method="GET", json=RULES_LIST_RESPONSE)
        with pytest.raises(KeyError, match="not found"):
            get_detection_rule(exa, "does-not-exist")


# ---------------------------------------------------------------------------
# set_detection_rule_state
# ---------------------------------------------------------------------------

class TestSetDetectionRuleState:
    def test_enable_rule(self, exa, mock_auth):
        updated = {**RULE_A, "enabled": True}
        mock_auth.add_response(
            url=f"{BASE_URL}{_BASE}/rule-uuid-001",
            method="PUT",
            json=updated,
        )
        result = set_detection_rule_state(exa, "rule-uuid-001", enabled=True)
        assert result["enabled"] is True

    def test_disable_rule(self, exa, mock_auth):
        updated = {**RULE_B, "enabled": False}
        mock_auth.add_response(
            url=f"{BASE_URL}{_BASE}/rule-uuid-002",
            method="PUT",
            json=updated,
        )
        result = set_detection_rule_state(exa, "rule-uuid-002", enabled=False)
        assert result["enabled"] is False

    def test_request_body_contains_enabled_flag(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}{_BASE}/rule-uuid-001",
            method="PUT",
            json=RULE_A,
        )
        set_detection_rule_state(exa, "rule-uuid-001", enabled=True)
        request = mock_auth.get_request(url=f"{BASE_URL}{_BASE}/rule-uuid-001")
        body = json.loads(request.content)
        assert body == {"enabled": True}


# ---------------------------------------------------------------------------
# export_rules
# ---------------------------------------------------------------------------

class TestExportRules:
    def test_export_all_rules(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}{_BASE}/export",
            method="POST",
            json=EXPORT_BUNDLE,
        )
        result = export_rules(exa)
        assert "rules" in result
        assert len(result["rules"]) == 2

    def test_export_specific_rules(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}{_BASE}/export",
            method="POST",
            json={"rules": [RULE_A]},
        )
        result = export_rules(exa, rule_ids=["rule-uuid-001"])
        assert len(result["rules"]) == 1

    def test_export_sends_rule_ids_in_body(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}{_BASE}/export",
            method="POST",
            json=EXPORT_BUNDLE,
        )
        export_rules(exa, rule_ids=["rule-uuid-001", "rule-uuid-002"])
        request = mock_auth.get_request(url=f"{BASE_URL}{_BASE}/export")
        body = json.loads(request.content)
        assert body["ruleIds"] == ["rule-uuid-001", "rule-uuid-002"]

    def test_export_all_sends_empty_body(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}{_BASE}/export",
            method="POST",
            json=EXPORT_BUNDLE,
        )
        export_rules(exa)
        request = mock_auth.get_request(url=f"{BASE_URL}{_BASE}/export")
        body = json.loads(request.content)
        assert "ruleIds" not in body


# ---------------------------------------------------------------------------
# import_rules
# ---------------------------------------------------------------------------

class TestImportRules:
    def test_import_returns_result(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}{_BASE}/import",
            method="POST",
            json=IMPORT_RESULT,
        )
        result = import_rules(exa, EXPORT_BUNDLE)
        assert result["imported"] == 2
        assert result["skipped"] == 0

    def test_import_overwrite_flag_sent(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}{_BASE}/import",
            method="POST",
            json=IMPORT_RESULT,
        )
        import_rules(exa, EXPORT_BUNDLE, overwrite=True)
        request = mock_auth.get_request(url=f"{BASE_URL}{_BASE}/import")
        body = json.loads(request.content)
        assert body["overwrite"] is True

    def test_import_no_overwrite_by_default(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}{_BASE}/import",
            method="POST",
            json=IMPORT_RESULT,
        )
        import_rules(exa, EXPORT_BUNDLE)
        request = mock_auth.get_request(url=f"{BASE_URL}{_BASE}/import")
        body = json.loads(request.content)
        assert body["overwrite"] is False

    def test_import_bundle_fields_forwarded(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}{_BASE}/import",
            method="POST",
            json=IMPORT_RESULT,
        )
        import_rules(exa, EXPORT_BUNDLE)
        request = mock_auth.get_request(url=f"{BASE_URL}{_BASE}/import")
        body = json.loads(request.content)
        assert "rules" in body
        assert "version" in body


# ---------------------------------------------------------------------------
# diff_rules (pure — no HTTP)
# ---------------------------------------------------------------------------

class TestDiffRules:
    def test_no_changes(self):
        rules = [RULE_A, RULE_B]
        result = diff_rules(rules, rules)
        assert result["added"] == []
        assert result["removed"] == []
        assert result["changed"] == []
        assert result["unchanged"] == 2

    def test_added_rule(self):
        rule_c = {**RULE_A, "id": "rule-uuid-003", "name": "New Rule"}
        result = diff_rules([RULE_A], [RULE_A, rule_c])
        assert len(result["added"]) == 1
        assert result["added"][0]["id"] == "rule-uuid-003"
        assert result["removed"] == []
        assert result["unchanged"] == 1

    def test_removed_rule(self):
        result = diff_rules([RULE_A, RULE_B], [RULE_A])
        assert len(result["removed"]) == 1
        assert result["removed"][0]["id"] == "rule-uuid-002"
        assert result["added"] == []

    def test_changed_rule_field(self):
        rule_a_disabled = {**RULE_A, "isEnabled": False}
        result = diff_rules([RULE_A], [rule_a_disabled])
        assert len(result["changed"]) == 1
        entry = result["changed"][0]
        assert entry["id"] == "rule-uuid-001"
        assert "isEnabled" in entry["changes"]
        assert entry["changes"]["isEnabled"]["before"] is True
        assert entry["changes"]["isEnabled"]["after"] is False

    def test_custom_key_field(self):
        rules_a = [{"name": "Rule Alpha", "status": "enabled"}]
        rules_b = [{"name": "Rule Alpha", "status": "disabled"}]
        result = diff_rules(rules_a, rules_b, key="name")
        assert len(result["changed"]) == 1
        assert result["changed"][0]["name"] == "Rule Alpha"

    def test_empty_lists(self):
        result = diff_rules([], [])
        assert result["added"] == []
        assert result["removed"] == []
        assert result["changed"] == []
        assert result["unchanged"] == 0

    def test_missing_key_field_skipped(self):
        rules_a = [{"id": "a", "name": "Rule A"}, {"name": "No ID"}]
        rules_b = [{"id": "a", "name": "Rule A"}]
        result = diff_rules(rules_a, rules_b)
        assert result["unchanged"] == 1

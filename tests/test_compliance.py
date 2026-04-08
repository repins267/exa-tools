"""Tests for compliance identity mapping and sync."""

from exa.compliance.mapping import (
    ClassificationResult,
    DiscoverySuggestion,
    classify_records,
    discover_source_mappings,
    extract_keys,
)

BASE_URL = "https://api.us-west.exabeam.cloud"


class TestExtractKeys:
    def test_key_column(self):
        records = [{"key": "admin@test.com"}, {"key": "user@test.com"}]
        assert extract_keys(records) == ["admin@test.com", "user@test.com"]

    def test_u_account_priority(self):
        records = [{"u_account": "jdoe", "key": "fallback", "username": "other"}]
        assert extract_keys(records) == ["jdoe"]

    def test_u_user_before_username(self):
        records = [{"u_user": "jdoe", "username": "john.doe"}]
        assert extract_keys(records) == ["jdoe"]

    def test_hostname_for_device_tables(self):
        records = [{"hostname": "DC-01", "ip": "10.0.0.1"}]
        assert extract_keys(records) == ["DC-01"]

    def test_ip_fallback(self):
        records = [{"ip": "10.0.0.1"}]
        assert extract_keys(records) == ["10.0.0.1"]

    def test_last_resort_first_string(self):
        records = [{"custom_field": "some_value", "number": 42}]
        assert extract_keys(records) == ["some_value"]

    def test_empty_values_skipped(self):
        records = [{"key": ""}, {"key": "valid"}]
        assert extract_keys(records) == ["valid"]


class TestClassifyRecords:
    def test_service_account_by_pattern(self):
        records = [{"key": "svc-backup"}, {"key": "sa-monitor"}, {"key": "regular-user"}]
        result = classify_records(records)
        assert "svc-backup" in result.service_accounts
        assert "sa-monitor" in result.service_accounts

    def test_service_account_by_type(self):
        records = [{"key": "myapp", "accountType": "service"}]
        result = classify_records(records)
        assert "myapp" in result.service_accounts

    def test_privileged_by_flag(self):
        records = [{"key": "admin1", "isPrivileged": "true"}]
        result = classify_records(records)
        assert "admin1" in result.privileged_users

    def test_privileged_by_admin_count(self):
        records = [{"key": "admin2", "adminCount": "1"}]
        result = classify_records(records)
        assert "admin2" in result.privileged_users

    def test_privileged_by_group_membership(self):
        records = [{"key": "admin3", "memberOf": "CN=Domain Admins,OU=Groups"}]
        result = classify_records(records)
        assert "admin3" in result.privileged_users

    def test_shared_by_pattern(self):
        records = [{"key": "shared-mailbox"}]
        result = classify_records(records)
        assert "shared-mailbox" in result.shared_accounts

    def test_shared_by_type(self):
        records = [{"key": "genericbox", "accountType": "shared"}]
        result = classify_records(records)
        assert "genericbox" in result.shared_accounts

    def test_third_party_by_user_type(self):
        records = [{"key": "vendor@ext.com", "userType": "guest"}]
        result = classify_records(records)
        assert "vendor@ext.com" in result.third_party_users

    def test_third_party_by_employee_type(self):
        records = [{"key": "contractor1", "employeeType": "contractor"}]
        result = classify_records(records)
        assert "contractor1" in result.third_party_users

    def test_third_party_by_external_email(self):
        records = [{"key": "ext@partner.com", "email": "ext@partner.com"}]
        result = classify_records(records, internal_domains=["contoso.com"])
        assert "ext@partner.com" in result.third_party_users

    def test_internal_email_not_third_party(self):
        records = [{"key": "int@contoso.com", "email": "int@contoso.com"}]
        result = classify_records(records, internal_domains=["contoso.com"])
        assert "int@contoso.com" not in result.third_party_users

    def test_classification_priority(self):
        """Service account pattern takes priority over privileged flag."""
        records = [{"key": "svc-admin", "isPrivileged": "true"}]
        result = classify_records(records)
        assert "svc-admin" in result.service_accounts
        assert "svc-admin" not in result.privileged_users

    def test_unclassified_count(self):
        records = [{"key": "normal_user"}]
        result = classify_records(records)
        assert result.unclassified == 1

    def test_missing_key_unclassified(self):
        records = [{"other": "no_key_field"}]
        result = classify_records(records)
        assert result.unclassified == 1


class TestDiscoverSourceMappings:
    def test_high_confidence_match(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=[
                {"name": "Privileged Users", "id": "t1", "numRecords": 50},
                {"name": "Service Accounts", "id": "t2", "numRecords": 30},
            ],
        )
        suggestions = discover_source_mappings(exa)
        priv = next(s for s in suggestions if s.compliance_target == "privileged_users")
        assert priv.suggested_source == "Privileged Users"
        assert priv.confidence == "High"

    def test_skips_compliance_tables(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=[
                {"name": "Compliance - Privileged Users", "id": "t1", "numRecords": 10},
                {"name": "AD Privileged Users", "id": "t2", "numRecords": 25},
            ],
        )
        suggestions = discover_source_mappings(exa)
        priv = next(s for s in suggestions if s.compliance_target == "privileged_users")
        assert priv.suggested_source == "AD Privileged Users"

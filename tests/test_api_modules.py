"""Tests for correlation, detection, and platform API modules."""

BASE_URL = "https://api.us-west.exabeam.cloud"


class TestCorrelationRules:
    def test_get_rules(self, exa, mock_auth):
        from exa.correlation import get_rules

        mock_auth.add_response(
            url=f"{BASE_URL}/correlation-rules/v2/rules",
            method="GET",
            json=[{"id": "r1", "name": "Brute Force"}],
        )
        rules = get_rules(exa)
        assert len(rules) == 1
        assert rules[0]["name"] == "Brute Force"

    def test_get_rules_name_filter(self, exa, mock_auth):
        from exa.correlation import get_rules

        mock_auth.add_response(
            url=f"{BASE_URL}/correlation-rules/v2/rules?nameContains=brute",
            method="GET",
            json=[{"id": "r1", "name": "Brute Force Login"}],
        )
        rules = get_rules(exa, name="brute")
        assert len(rules) == 1

    def test_get_rule(self, exa, mock_auth):
        from exa.correlation import get_rule

        mock_auth.add_response(
            url=f"{BASE_URL}/correlation-rules/v2/rules/r1",
            method="GET",
            json={"id": "r1", "name": "Brute Force", "enabled": True},
        )
        rule = get_rule(exa, "r1")
        assert rule["id"] == "r1"

    def test_create_rule(self, exa, mock_auth):
        from exa.correlation import create_rule

        mock_auth.add_response(
            url=f"{BASE_URL}/correlation-rules/v2/rules",
            method="POST",
            json={"id": "new-1"},
        )
        result = create_rule(exa, {"name": "New Rule", "filter": "test"})
        assert result["id"] == "new-1"

    def test_delete_rule(self, exa, mock_auth):
        from exa.correlation import delete_rule

        mock_auth.add_response(
            url=f"{BASE_URL}/correlation-rules/v2/rules/r1",
            method="DELETE",
            text="",
            status_code=204,
        )
        delete_rule(exa, "r1")  # should not raise

    def test_set_rule_state(self, exa, mock_auth):
        from exa.correlation import set_rule_state

        mock_auth.add_response(
            url=f"{BASE_URL}/correlation-rules/v2/rules/r1",
            method="PUT",
            json={"id": "r1", "enabled": False},
        )
        result = set_rule_state(exa, "r1", enabled=False)
        assert result["enabled"] is False


class TestDetectionRules:
    def test_get_detection_rules(self, exa, mock_auth):
        from exa.detection import get_detection_rules

        mock_auth.add_response(
            url=f"{BASE_URL}/detection-management/v1/analytics-rules?limit=100",
            method="GET",
            json={"rules": [{"id": "d1", "name": "Anomaly"}]},
        )
        rules = get_detection_rules(exa)
        assert len(rules) == 1
        assert rules[0]["name"] == "Anomaly"

    def test_get_detection_rule(self, exa, mock_auth):
        from exa.detection import get_detection_rule

        mock_auth.add_response(
            url=f"{BASE_URL}/detection-management/v1/analytics-rules/d1",
            method="GET",
            json={"id": "d1", "name": "Anomaly", "enabled": True},
        )
        rule = get_detection_rule(exa, "d1")
        assert rule["id"] == "d1"

    def test_set_detection_rule_state(self, exa, mock_auth):
        from exa.detection import set_detection_rule_state

        mock_auth.add_response(
            url=f"{BASE_URL}/detection-management/v1/analytics-rules/d1",
            method="PUT",
            json={"id": "d1", "enabled": True},
        )
        result = set_detection_rule_state(exa, "d1", enabled=True)
        assert result["enabled"] is True


class TestPlatform:
    def test_get_tenant_info(self, exa, mock_auth):
        from exa.platform import get_tenant_info

        mock_auth.add_response(
            url=f"{BASE_URL}/platform/v1/tenant",
            method="GET",
            json={"tenantId": "t1", "region": "us-west"},
        )
        info = get_tenant_info(exa)
        assert info["tenantId"] == "t1"

    def test_get_api_keys(self, exa, mock_auth):
        from exa.platform import get_api_keys

        mock_auth.add_response(
            url=f"{BASE_URL}/access-control/v1/apikeys",
            method="GET",
            json=[{"id": "k1", "ownerEmail": "admin@test.com"}],
        )
        keys = get_api_keys(exa)
        assert len(keys) == 1

    def test_get_roles(self, exa, mock_auth):
        from exa.platform import get_roles

        mock_auth.add_response(
            url=f"{BASE_URL}/access-control/v1/roles",
            method="GET",
            json=[{"id": "admin", "name": "Administrator"}],
        )
        roles = get_roles(exa)
        assert roles[0]["name"] == "Administrator"

    def test_get_users(self, exa, mock_auth):
        from exa.platform import get_users

        mock_auth.add_response(
            url=f"{BASE_URL}/access-control/v1/users",
            method="GET",
            json=[{"id": "u1", "email": "admin@test.com"}],
        )
        users = get_users(exa)
        assert len(users) == 1

    def test_get_user(self, exa, mock_auth):
        from exa.platform import get_user

        mock_auth.add_response(
            url=f"{BASE_URL}/access-control/v1/users/u1",
            method="GET",
            json={"id": "u1", "email": "admin@test.com"},
        )
        user = get_user(exa, "u1")
        assert user["email"] == "admin@test.com"

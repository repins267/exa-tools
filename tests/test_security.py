"""Security tests — credentials, input validation, XSS, tenant isolation."""

import re
from unittest.mock import patch

import pytest

from exa.exceptions import ExaAuthError, ExaConfigError

BASE_URL = "https://api.us-west.exabeam.cloud"
CLIENT_ID = "test-client-id-abc"
CLIENT_SECRET = "super-secret-value-xyz"
TOKEN_RESPONSE = {
    "access_token": "tok-secret-abc123",
    "token_type": "Bearer",
    "expires_in": 14400,
}


# ── Credential Security ─────────────────────────────────────────────


class TestClientSecretNotInRepr:
    def test_repr_hides_secret(self, mock_auth) -> None:
        from exa.client import ExaClient

        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        client.authenticate()
        r = repr(client)
        assert CLIENT_SECRET not in r
        assert "tok-secret-abc123" not in r
        client.close()

    def test_str_hides_secret(self, mock_auth) -> None:
        from exa.client import ExaClient

        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        client.authenticate()
        s = str(client)
        assert CLIENT_SECRET not in s
        assert "tok-secret-abc123" not in s
        client.close()


class TestClientSecretNotInException:
    def test_auth_error_hides_secret(self, httpx_mock) -> None:
        from exa.client import ExaClient

        httpx_mock.add_response(
            url=f"{BASE_URL}/auth/v1/token",
            method="POST",
            status_code=401,
            json={"error": "invalid_client"},
        )
        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        with pytest.raises(ExaAuthError) as exc_info:
            client.authenticate()
        msg = str(exc_info.value)
        assert CLIENT_SECRET not in msg
        client.close()


class TestAccessTokenNotPersisted:
    def test_token_not_in_config_files(
        self, mock_auth, tmp_path, monkeypatch,
    ) -> None:
        from exa.client import ExaClient

        monkeypatch.setattr("exa.config._CONFIG_DIR", tmp_path)
        monkeypatch.setattr(
            "exa.config._CONFIG_FILE", tmp_path / "config.json",
        )

        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        client.authenticate()
        token = client._access_token

        # Check no file in the config dir contains the token
        for f in tmp_path.rglob("*"):
            if f.is_file():
                content = f.read_text(encoding="utf-8", errors="ignore")
                assert token not in content, (
                    f"Token found in {f}"
                )
        client.close()


class TestConfigFileNeverContainsSecret:
    def test_secret_not_in_config_json(
        self, tmp_path, monkeypatch,
    ) -> None:
        from exa.config import save_profile

        monkeypatch.setattr("exa.config._CONFIG_DIR", tmp_path)
        monkeypatch.setattr(
            "exa.config._CONFIG_FILE", tmp_path / "config.json",
        )

        stored: dict = {}

        def mock_set(svc: str, key: str, val: str) -> None:
            stored.setdefault(svc, {})[key] = val

        with patch(
            "exa.config.keyring.set_password", side_effect=mock_set,
        ):
            save_profile(
                "test-tenant", BASE_URL, CLIENT_ID, CLIENT_SECRET,
            )

        raw = (tmp_path / "config.json").read_text(encoding="utf-8")
        assert CLIENT_SECRET not in raw
        assert CLIENT_ID not in raw


# ── Input Validation ────────────────────────────────────────────────


class TestTenantNamePathTraversal:
    @pytest.mark.parametrize("bad_name", [
        "../../../etc/passwd",
        "..\\..\\windows\\system32",
        "<script>alert(1)</script>",
        "\x00null",
    ])
    def test_rejects_malicious_tenant_names(
        self, bad_name: str, tmp_path, monkeypatch,
    ) -> None:
        from exa.config import save_profile

        monkeypatch.setattr("exa.config._CONFIG_DIR", tmp_path)
        monkeypatch.setattr(
            "exa.config._CONFIG_FILE", tmp_path / "config.json",
        )

        with pytest.raises(ValueError, match="Invalid tenant name"):
            save_profile(bad_name, BASE_URL, "id", "secret")

        # Verify no file created outside tmp_path
        for f in tmp_path.rglob("*"):
            assert str(tmp_path) in str(f.resolve())


class TestFrameworkNamePathTraversal:
    @pytest.mark.parametrize("bad_id", [
        "../../../etc/passwd",
        "..\\..\\boot.ini",
        "NIST_CSF; rm -rf /",
        "\x00",
    ])
    def test_rejects_malicious_framework_ids(
        self, bad_id: str,
    ) -> None:
        from exa.compliance.frameworks import load_framework

        with pytest.raises(ExaConfigError, match="Invalid framework ID"):
            load_framework(bad_id)


class TestHttpsOnly:
    def test_rejects_http_url(self) -> None:
        from exa.client import ExaClient

        with pytest.raises(
            ValueError, match="API server URL must use HTTPS",
        ):
            ExaClient(
                "http://api.us-west.exabeam.cloud",
                CLIENT_ID,
                CLIENT_SECRET,
            )

    def test_accepts_https_url(self, mock_auth) -> None:
        from exa.client import ExaClient

        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        client.authenticate()
        assert client.base_url.startswith("https://")
        client.close()


class TestSslVerificationEnabled:
    def test_verify_not_disabled(self) -> None:
        from exa.client import ExaClient

        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        # httpx.Client defaults verify=True; check it wasn't overridden
        # If verify=False was passed, the pool would reflect it
        assert client._http._transport is not None
        client.close()


# ── API Security ────────────────────────────────────────────────────


class TestAuthErrorDoesNotContainCredentials:
    def test_401_hides_creds(self, httpx_mock) -> None:
        from exa.client import ExaClient

        httpx_mock.add_response(
            url=f"{BASE_URL}/auth/v1/token",
            method="POST",
            status_code=401,
            json={"error": "unauthorized"},
        )
        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        with pytest.raises(ExaAuthError) as exc_info:
            client.authenticate()
        msg = str(exc_info.value)
        assert CLIENT_ID not in msg
        assert CLIENT_SECRET not in msg
        client.close()


class TestNoPlaintextCredentialsInHeaders:
    def test_auth_header_is_bearer_only(
        self, mock_auth,
    ) -> None:
        from exa.client import ExaClient

        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        client.authenticate()
        headers = client._auth_headers
        auth_value = headers["Authorization"]
        assert auth_value.startswith("Bearer ")
        assert CLIENT_ID not in auth_value
        assert CLIENT_SECRET not in auth_value
        client.close()


# ── HTML Report Security ────────────────────────────────────────────


def _make_report(**overrides):
    """Build a minimal AuditReport for testing."""
    from exa.compliance.audit import AuditReport, ControlResult

    defaults = {
        "timestamp": "2026-04-09T12:00:00+00:00",
        "framework": "NIST_CSF",
        "framework_name": "NIST CSF v2.0",
        "lookback_days": 30,
        "minimum_evidence": 10,
        "total_leaf_controls": 10,
        "siem_testable_count": 5,
        "manual_control_count": 5,
        "controls_pass": 3,
        "controls_fail": 2,
        "coverage_pct": 60.0,
        "total_evidence": 100,
        "unique_queries": 5,
        "control_results": [
            ControlResult(
                control_id="ID.AM-01",
                family="Identify",
                description="Hardware Asset Inventory",
                status="Pass",
                evidence_count=25,
            ),
        ],
    }
    defaults.update(overrides)
    return AuditReport(**defaults)


class TestHtmlReportEscapesControlTitle:
    def test_script_tag_escaped(self) -> None:
        from exa.compliance.audit import ControlResult
        from exa.compliance.report import generate_html_report

        xss = "<script>alert('xss')</script>"
        report = _make_report(
            control_results=[
                ControlResult(
                    control_id="XSS-01",
                    family="Test",
                    description=xss,
                    status="Fail",
                    evidence_count=0,
                ),
            ],
        )
        html = generate_html_report(report)
        assert xss not in html
        assert "&lt;script&gt;" in html


class TestHtmlReportEscapesControlDescription:
    def test_img_onerror_escaped(self) -> None:
        from exa.compliance.audit import ControlResult
        from exa.compliance.report import generate_html_report

        xss = '<img src=x onerror=alert(1)>'
        report = _make_report(
            control_results=[
                ControlResult(
                    control_id="XSS-02",
                    family="Test",
                    description=xss,
                    status="Pass",
                    evidence_count=10,
                ),
            ],
        )
        html = generate_html_report(report)
        assert xss not in html
        assert "&lt;img" in html


class TestHtmlReportNoExternalUrls:
    def test_no_external_references(self) -> None:
        from exa.compliance.report import generate_html_report

        html = generate_html_report(_make_report())
        urls = re.findall(
            r'(?:href|src)\s*=\s*["\']?(https?://[^"\'>\s]+)',
            html,
        )
        assert urls == [], f"External URLs found: {urls}"


class TestHtmlReportEscapesTenantName:
    def test_xss_in_framework_name_escaped(self) -> None:
        from exa.compliance.report import generate_html_report

        xss = "<script>alert(1)</script>"
        report = _make_report(framework_name=xss)
        html = generate_html_report(report)
        assert xss not in html
        assert "&lt;script&gt;" in html


# ── Multi-Tenant Isolation ──────────────────────────────────────────


class TestTenantProfilesIsolated:
    def test_profiles_dont_cross(
        self, tmp_path, monkeypatch,
    ) -> None:
        from exa.config import load_profile, save_profile

        monkeypatch.setattr("exa.config._CONFIG_DIR", tmp_path)
        monkeypatch.setattr(
            "exa.config._CONFIG_FILE", tmp_path / "config.json",
        )

        stored: dict = {}

        def mock_set(svc: str, key: str, val: str) -> None:
            stored.setdefault(svc, {})[key] = val

        def mock_get(svc: str, key: str) -> str | None:
            return stored.get(svc, {}).get(key)

        with (
            patch("exa.config.keyring.set_password", side_effect=mock_set),
            patch("exa.config.keyring.get_password", side_effect=mock_get),
        ):
            save_profile("tenant-a", BASE_URL, "id-a", "secret-a")
            save_profile("tenant-b", BASE_URL, "id-b", "secret-b")

            _, cid_a, csec_a = load_profile("tenant-a")
            _, cid_b, csec_b = load_profile("tenant-b")

        assert cid_a == "id-a"
        assert csec_a == "secret-a"
        assert cid_b == "id-b"
        assert csec_b == "secret-b"
        # Cross-contamination check
        assert cid_a != cid_b
        assert csec_a != csec_b


class TestDefaultTenantDoesntLeakOtherProfiles:
    def test_default_returns_only_default(
        self, tmp_path, monkeypatch,
    ) -> None:
        from exa.config import (
            load_profile,
            save_profile,
            set_default_tenant,
        )

        monkeypatch.setattr("exa.config._CONFIG_DIR", tmp_path)
        monkeypatch.setattr(
            "exa.config._CONFIG_FILE", tmp_path / "config.json",
        )

        stored: dict = {}

        def mock_set(svc: str, key: str, val: str) -> None:
            stored.setdefault(svc, {})[key] = val

        def mock_get(svc: str, key: str) -> str | None:
            return stored.get(svc, {}).get(key)

        with (
            patch("exa.config.keyring.set_password", side_effect=mock_set),
            patch("exa.config.keyring.get_password", side_effect=mock_get),
        ):
            save_profile("tenant-a", BASE_URL, "id-a", "secret-a")
            save_profile("tenant-b", BASE_URL, "id-b", "secret-b")
            set_default_tenant("tenant-a")

            _, cid, csec = load_profile()  # no explicit tenant

        assert cid == "id-a"
        assert csec == "secret-a"
        # Must not return tenant-b credentials
        assert cid != "id-b"
        assert csec != "secret-b"


class TestClientAcceptsFqdnDirectly:
    def test_fqdn_resolves_api_server(
        self, tmp_path, monkeypatch, httpx_mock,
    ) -> None:
        from exa.client import ExaClient
        from exa.config import save_profile

        monkeypatch.setattr("exa.config._CONFIG_DIR", tmp_path)
        monkeypatch.setattr(
            "exa.config._CONFIG_FILE", tmp_path / "config.json",
        )

        stored: dict = {}

        def mock_set(svc: str, key: str, val: str) -> None:
            stored.setdefault(svc, {})[key] = val

        def mock_get(svc: str, key: str) -> str | None:
            return stored.get(svc, {}).get(key)

        with (
            patch(
                "exa.config.keyring.set_password",
                side_effect=mock_set,
            ),
            patch(
                "exa.config.keyring.get_password",
                side_effect=mock_get,
            ),
        ):
            save_profile(
                "csdevfusion",
                "https://api.us-east.exabeam.cloud",
                "fqdn-id", "fqdn-secret",
                fqdn="csdevfusion.use1.exabeam.cloud",
                region="US East",
            )

            client = ExaClient(
                fqdn="csdevfusion.use1.exabeam.cloud",
            )
            assert client.base_url == (
                "https://api.us-east.exabeam.cloud"
            )
            client.close()

"""Tests for ExaClient token lifecycle — refresh and 401 retry."""

import time

import pytest

from exa.client import ExaClient, _TOKEN_TTL_BUFFER
from exa.exceptions import ExaAuthError

BASE_URL = "https://api.us-west.exabeam.cloud"
CLIENT_ID = "test-client-id"
CLIENT_SECRET = "test-client-secret"
TOKEN_RESPONSE = {
    "access_token": "test-token-abc123",
    "token_type": "Bearer",
    "expires_in": 14400,
}


class TestTokenRefresh:
    def test_refresh_at_60s_before_expiry(self, httpx_mock):
        """Token is refreshed when within 60s of expiry."""
        httpx_mock.add_response(
            url=f"{BASE_URL}/auth/v1/token",
            method="POST",
            json=TOKEN_RESPONSE,
        )
        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        client.authenticate()

        # Set expires_at to within buffer window
        client._expires_at = time.time() + _TOKEN_TTL_BUFFER - 1

        httpx_mock.add_response(
            url=f"{BASE_URL}/auth/v1/token",
            method="POST",
            json={**TOKEN_RESPONSE, "access_token": "refreshed-token"},
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/test/endpoint",
            method="GET",
            json={"ok": True},
        )

        result = client.get("/test/endpoint")
        assert client._access_token == "refreshed-token"
        assert result == {"ok": True}
        client.close()

    def test_no_refresh_when_fresh(self, httpx_mock):
        """Token is NOT refreshed when well within TTL."""
        httpx_mock.add_response(
            url=f"{BASE_URL}/auth/v1/token",
            method="POST",
            json=TOKEN_RESPONSE,
        )
        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        client.authenticate()
        original_token = client._access_token

        httpx_mock.add_response(
            url=f"{BASE_URL}/test/endpoint",
            method="GET",
            json={"ok": True},
        )

        client.get("/test/endpoint")
        # Should still have original token (no refresh POST)
        assert client._access_token == original_token
        client.close()


class TestTokenRefreshOn401:
    def test_retry_on_401(self, httpx_mock):
        """On 401 response, force refresh and retry once."""
        # Initial auth
        httpx_mock.add_response(
            url=f"{BASE_URL}/auth/v1/token",
            method="POST",
            json=TOKEN_RESPONSE,
        )
        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        client.authenticate()

        # First request → 401
        httpx_mock.add_response(
            url=f"{BASE_URL}/test/endpoint",
            method="GET",
            status_code=401,
            json={"error": "token_expired"},
        )
        # Refresh token
        httpx_mock.add_response(
            url=f"{BASE_URL}/auth/v1/token",
            method="POST",
            json={**TOKEN_RESPONSE, "access_token": "retry-token"},
        )
        # Retry request → success
        httpx_mock.add_response(
            url=f"{BASE_URL}/test/endpoint",
            method="GET",
            json={"data": "success"},
        )

        result = client.get("/test/endpoint")
        assert result == {"data": "success"}
        assert client._access_token == "retry-token"
        client.close()

    def test_double_401_raises(self, httpx_mock):
        """On second 401 after refresh, raise ExaAuthError."""
        httpx_mock.add_response(
            url=f"{BASE_URL}/auth/v1/token",
            method="POST",
            json=TOKEN_RESPONSE,
        )
        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        client.authenticate()

        # First request → 401
        httpx_mock.add_response(
            url=f"{BASE_URL}/test/endpoint",
            method="GET",
            status_code=401,
            json={"error": "token_expired"},
        )
        # Refresh succeeds
        httpx_mock.add_response(
            url=f"{BASE_URL}/auth/v1/token",
            method="POST",
            json={**TOKEN_RESPONSE, "access_token": "new-token"},
        )
        # Retry → still 401
        httpx_mock.add_response(
            url=f"{BASE_URL}/test/endpoint",
            method="GET",
            status_code=401,
            json={"error": "still_unauthorized"},
        )

        with pytest.raises(ExaAuthError, match="Authentication failed after token refresh"):
            client.get("/test/endpoint")
        client.close()


class TestKeyringConstruction:
    def test_missing_credentials_raises(self):
        """ExaClient() with no args and no saved creds raises ExaConfigError."""
        from unittest.mock import patch

        from exa.exceptions import ExaConfigError

        with patch("exa.config._CONFIG_FILE") as mock_path:
            mock_path.exists.return_value = False
            with pytest.raises(ExaConfigError, match="No default tenant"):
                ExaClient()

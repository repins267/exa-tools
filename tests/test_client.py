"""Tests for ExaClient."""

import time

import httpx
import pytest

from exa.client import ExaClient, _RetryTransport, _TOKEN_TTL_BUFFER
from exa.exceptions import ExaAPIError, ExaAuthError

BASE_URL = "https://api.us-west.exabeam.cloud"
CLIENT_ID = "test-client-id"
CLIENT_SECRET = "test-client-secret"
TOKEN_RESPONSE = {
    "access_token": "test-token-abc123",
    "token_type": "Bearer",
    "expires_in": 14400,
}


class TestAuthentication:
    def test_authenticate_success(self, mock_auth):
        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        client.authenticate()
        assert client._access_token == "test-token-abc123"
        assert client._expires_at > time.time()
        client.close()

    def test_authenticate_failure(self, httpx_mock):
        httpx_mock.add_response(
            url=f"{BASE_URL}/auth/v1/token",
            method="POST",
            status_code=401,
            json={"error": "invalid_client"},
        )
        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        with pytest.raises(ExaAuthError, match="401"):
            client.authenticate()
        client.close()

    def test_auto_refresh_on_expired_token(self, httpx_mock):
        httpx_mock.add_response(
            url=f"{BASE_URL}/auth/v1/token",
            method="POST",
            json=TOKEN_RESPONSE,
        )
        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        client.authenticate()
        # Force token to appear expired
        client._expires_at = time.time() - 10

        # Register a second auth response + a GET
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

    def test_token_buffer_triggers_refresh(self, httpx_mock):
        httpx_mock.add_response(
            url=f"{BASE_URL}/auth/v1/token",
            method="POST",
            json=TOKEN_RESPONSE,
        )
        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        client.authenticate()
        # Set expires_at within the buffer window
        client._expires_at = time.time() + _TOKEN_TTL_BUFFER - 1

        httpx_mock.add_response(
            url=f"{BASE_URL}/auth/v1/token",
            method="POST",
            json={**TOKEN_RESPONSE, "access_token": "buffer-refreshed"},
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/test/endpoint",
            method="GET",
            json={"ok": True},
        )

        client.get("/test/endpoint")
        assert client._access_token == "buffer-refreshed"
        client.close()


class TestHTTPMethods:
    def test_get(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json={"tables": []},
        )
        result = exa.get("/context-management/v1/tables")
        assert result == {"tables": []}

    def test_post(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="POST",
            json={"table": {"id": "123"}},
        )
        result = exa.post(
            "/context-management/v1/tables",
            json={"name": "Test Table", "contextType": "Other"},
        )
        assert result["table"]["id"] == "123"

    def test_put(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/test/resource",
            method="PUT",
            json={"updated": True},
        )
        result = exa.put("/test/resource", json={"key": "value"})
        assert result["updated"] is True

    def test_delete(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/test/resource",
            method="DELETE",
            text="",
            status_code=204,
        )
        result = exa.delete("/test/resource")
        assert result is None

    def test_api_error_raised(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/test/resource",
            method="GET",
            status_code=404,
            json={"error": "not found"},
        )
        with pytest.raises(ExaAPIError, match="404"):
            exa.get("/test/resource")


class TestContextManager:
    def test_context_manager(self, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/test/endpoint",
            method="GET",
            json={"ok": True},
        )
        with ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET) as exa:
            result = exa.get("/test/endpoint")
            assert result == {"ok": True}

    def test_close_is_idempotent(self, mock_auth):
        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        client.authenticate()
        client.close()
        # Second close should not raise
        client.close()


class TestBatchWriteSleep:
    def test_batch_write_sleep_duration(self):
        start = time.monotonic()
        ExaClient.batch_write_sleep()
        elapsed = time.monotonic() - start
        assert elapsed >= 0.9  # allow small timing variance


class TestRetryTransport:
    def test_backoff_calculation(self):
        transport = _RetryTransport()
        assert transport._backoff_ms(1) == 500  # 500 * 2^0
        assert transport._backoff_ms(2) == 1000  # 500 * 2^1
        assert transport._backoff_ms(3) == 2000  # 500 * 2^2
        assert transport._backoff_ms(10) == 60000  # capped at max

    def test_follow_redirects_enabled(self):
        client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        assert client._http.follow_redirects is True
        client.close()

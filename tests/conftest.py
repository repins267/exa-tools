"""Shared test fixtures for exa-tools."""

import pytest

from exa.client import ExaClient


TOKEN_RESPONSE = {
    "access_token": "test-token-abc123",
    "token_type": "Bearer",
    "expires_in": 14400,
}

BASE_URL = "https://api.us-west.exabeam.cloud"
CLIENT_ID = "test-client-id"
CLIENT_SECRET = "test-client-secret"


@pytest.fixture()
def mock_auth(httpx_mock):
    """Pre-register the auth endpoint so ExaClient can authenticate."""
    httpx_mock.add_response(
        url=f"{BASE_URL}/auth/v1/token",
        method="POST",
        json=TOKEN_RESPONSE,
    )
    return httpx_mock


@pytest.fixture()
def exa(mock_auth):
    """Authenticated ExaClient backed by httpx_mock."""
    client = ExaClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
    client.authenticate()
    yield client
    client.close()

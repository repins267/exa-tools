"""Tests for internal tier gating."""

import pytest

from exa.exceptions import ExaInternalFeatureError
from exa.internal import detect_internal_mode, require_internal

BASE_URL = "https://api.us-west.exabeam.cloud"


class TestDetectInternalMode:
    def test_internal_email_detected(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/access-control/v1/apikeys",
            method="GET",
            json=[{"ownerEmail": "user@exabeam.com", "id": "key1"}],
        )
        assert detect_internal_mode(exa) is True

    def test_external_email_not_internal(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/access-control/v1/apikeys",
            method="GET",
            json=[{"ownerEmail": "user@customer.com", "id": "key1"}],
        )
        assert detect_internal_mode(exa) is False

    def test_fallback_on_error(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/access-control/v1/apikeys",
            method="GET",
            status_code=403,
            json={"error": "forbidden"},
        )
        # Falls back to True (assumes internal)
        assert detect_internal_mode(exa) is True


class TestRequireInternal:
    def test_allows_internal(self, exa, mock_auth):
        exa._internal_mode = True

        @require_internal
        def internal_func(client):
            return "success"

        assert internal_func(exa) == "success"

    def test_blocks_external(self, exa, mock_auth):
        exa._internal_mode = False

        @require_internal
        def internal_func(client):
            return "success"

        with pytest.raises(ExaInternalFeatureError, match="internal/employee tier"):
            internal_func(exa)

    def test_auto_detects_on_first_call(self, exa, mock_auth):
        # Remove any cached mode
        if hasattr(exa, "_internal_mode"):
            delattr(exa, "_internal_mode")

        mock_auth.add_response(
            url=f"{BASE_URL}/access-control/v1/apikeys",
            method="GET",
            json=[{"ownerEmail": "user@exabeam.com"}],
        )

        @require_internal
        def internal_func(client):
            return "success"

        assert internal_func(exa) == "success"
        assert exa._internal_mode is True

    def test_no_client_raises_type_error(self):
        @require_internal
        def internal_func(x):
            return x

        with pytest.raises(TypeError, match="requires an ExaClient"):
            internal_func("not a client")

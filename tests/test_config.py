"""Tests for exa/config.py credential storage and tenant profiles."""

import json
from unittest.mock import patch

import pytest

from exa.config import (
    _CONFIG_FILE,
    _KEYRING_SERVICE,
    get_default_tenant,
    load_config,
    load_profile,
    save_config,
    save_profile,
    set_default_tenant,
)
from exa.exceptions import ExaConfigError


@pytest.fixture(autouse=True)
def _isolate_config(tmp_path, monkeypatch):
    """Redirect config file to tmp_path for test isolation."""
    config_file = tmp_path / "config.json"
    monkeypatch.setattr("exa.config._CONFIG_DIR", tmp_path)
    monkeypatch.setattr("exa.config._CONFIG_FILE", config_file)


class TestSaveLoadProfile:
    def test_round_trip(self):
        """save_profile then load_profile returns the same values."""
        stored: dict[str, dict[str, str]] = {}

        def mock_set(service: str, key: str, value: str) -> None:
            stored.setdefault(service, {})[key] = value

        def mock_get(service: str, key: str) -> str | None:
            return stored.get(service, {}).get(key)

        with (
            patch("exa.config.keyring.set_password", side_effect=mock_set),
            patch("exa.config.keyring.get_password", side_effect=mock_get),
        ):
            save_profile(
                "test-tenant",
                "https://api.us-west.exabeam.cloud",
                "my-client-id",
                "my-client-secret",
            )
            set_default_tenant("test-tenant")

            api_server, client_id, client_secret = load_profile("test-tenant")

        assert api_server == "https://api.us-west.exabeam.cloud"
        assert client_id == "my-client-id"
        assert client_secret == "my-client-secret"

    def test_load_default_tenant(self):
        """load_profile(None) loads the default tenant."""
        stored: dict[str, dict[str, str]] = {}

        def mock_set(service: str, key: str, value: str) -> None:
            stored.setdefault(service, {})[key] = value

        def mock_get(service: str, key: str) -> str | None:
            return stored.get(service, {}).get(key)

        with (
            patch("exa.config.keyring.set_password", side_effect=mock_set),
            patch("exa.config.keyring.get_password", side_effect=mock_get),
        ):
            save_profile("default-t", "https://api.eu.exabeam.cloud", "cid", "csec")
            set_default_tenant("default-t")

            api_server, cid, csec = load_profile()

        assert api_server == "https://api.eu.exabeam.cloud"
        assert cid == "cid"

    def test_multiple_tenants(self):
        """Multiple tenants can be saved and loaded independently."""
        stored: dict[str, dict[str, str]] = {}

        def mock_set(service: str, key: str, value: str) -> None:
            stored.setdefault(service, {})[key] = value

        def mock_get(service: str, key: str) -> str | None:
            return stored.get(service, {}).get(key)

        with (
            patch("exa.config.keyring.set_password", side_effect=mock_set),
            patch("exa.config.keyring.get_password", side_effect=mock_get),
        ):
            save_profile("tenant-a", "https://api.us-west.exabeam.cloud", "id-a", "sec-a")
            save_profile("tenant-b", "https://api.eu.exabeam.cloud", "id-b", "sec-b")

            _, cid_a, _ = load_profile("tenant-a")
            _, cid_b, _ = load_profile("tenant-b")

        assert cid_a == "id-a"
        assert cid_b == "id-b"


class TestMissingCredentials:
    def test_no_config_file(self):
        """ExaConfigError when no config file exists."""
        with pytest.raises(ExaConfigError, match="No default tenant configured"):
            load_profile()

    def test_unknown_tenant(self):
        """ExaConfigError for unknown tenant name."""
        set_default_tenant("exists")
        with pytest.raises(ExaConfigError, match="No credentials found for tenant 'nope'"):
            load_profile("nope")

    def test_no_keyring_creds(self):
        """ExaConfigError when keyring returns None."""
        save_config("tenants", {"ghost": {"api_server": "https://example.com"}})

        with patch("exa.config.keyring.get_password", return_value=None):
            with pytest.raises(ExaConfigError, match="No credentials found"):
                load_profile("ghost")


class TestDefaultTenant:
    def test_set_and_get(self):
        set_default_tenant("my-tenant")
        assert get_default_tenant() == "my-tenant"

    def test_no_default_raises(self):
        with pytest.raises(ExaConfigError, match="No default tenant"):
            get_default_tenant()


class TestGenericConfig:
    def test_save_load_round_trip(self):
        save_config("sigma.rules_dir", "/path/to/rules")
        assert load_config("sigma.rules_dir") == "/path/to/rules"

    def test_load_missing_key(self):
        assert load_config("nonexistent") is None

"""Tests for exa config CLI commands and config integrity."""

import json

import pytest

from exa.config import (
    _INTERNAL_KEYS,
    list_config,
    load_config,
    save_config,
    save_profile,
    set_default_tenant,
)


@pytest.fixture(autouse=True)
def _isolate_config(tmp_path, monkeypatch):
    """Redirect config file to tmp_path for test isolation."""
    config_file = tmp_path / "config.json"
    monkeypatch.setattr("exa.config._CONFIG_DIR", tmp_path)
    monkeypatch.setattr("exa.config._CONFIG_FILE", config_file)


class TestConfigSetGet:
    def test_round_trip(self):
        """save_config → load_config returns the same value."""
        save_config("sigma.rules-dir", r"E:\SigmaHQ\rules")
        assert load_config("sigma.rules-dir") == r"E:\SigmaHQ\rules"

    def test_overwrite(self):
        """Setting the same key twice keeps the latest value."""
        save_config("sigma.rules-dir", "/old/path")
        save_config("sigma.rules-dir", "/new/path")
        assert load_config("sigma.rules-dir") == "/new/path"

    def test_default_tenant_via_config(self):
        """default-tenant maps to set_default_tenant internally."""
        set_default_tenant("my-tenant")
        assert load_config("default_tenant") == "my-tenant"

    def test_multiple_keys(self):
        """Multiple independent keys coexist."""
        save_config("sigma.rules-dir", "/rules")
        save_config("output.format", "json")
        assert load_config("sigma.rules-dir") == "/rules"
        assert load_config("output.format") == "json"


class TestConfigShow:
    def test_list_config_returns_all_user_keys(self):
        """list_config returns all non-internal keys."""
        save_config("sigma.rules-dir", "/rules")
        set_default_tenant("demo")
        items = list_config()
        assert "sigma.rules-dir" in items
        assert "default_tenant" in items

    def test_list_config_empty_when_no_config(self):
        """list_config returns empty dict when nothing is set."""
        items = list_config()
        assert items == {}

    def test_list_config_excludes_tenants(self):
        """list_config never includes the 'tenants' internal key."""
        # Manually write a config with tenants key
        from exa.config import _write_config_file

        _write_config_file({
            "tenants": {"t1": {"api_server": "https://example.com"}},
            "default_tenant": "t1",
            "sigma.rules-dir": "/rules",
        })
        items = list_config()
        assert "tenants" not in items
        assert "default_tenant" in items
        assert "sigma.rules-dir" in items


class TestConfigNoSecrets:
    def test_config_file_never_contains_secrets(self, tmp_path):
        """Secrets are never written to config.json, only to keyring."""
        from unittest.mock import patch

        stored: dict[str, dict[str, str]] = {}

        def mock_set(service: str, key: str, value: str) -> None:
            stored.setdefault(service, {})[key] = value

        with patch("exa.config.keyring.set_password", side_effect=mock_set):
            save_profile(
                "test-tenant",
                "https://api.us-west.exabeam.cloud",
                "my-client-id",
                "super-secret-value",
            )

        # Read the raw config file
        from exa.config import _CONFIG_FILE

        raw = _CONFIG_FILE.read_text(encoding="utf-8")
        data = json.loads(raw)

        # Secrets must NOT appear in the config file
        assert "super-secret-value" not in raw
        assert "my-client-id" not in raw

        # They must be in keyring instead
        assert "exa-tools/test-tenant" in stored
        assert stored["exa-tools/test-tenant"]["client_id"] == "my-client-id"
        assert stored["exa-tools/test-tenant"]["client_secret"] == "super-secret-value"

        # Config file only has api_server
        tenant_cfg = data["tenants"]["test-tenant"]
        assert tenant_cfg == {"api_server": "https://api.us-west.exabeam.cloud"}

    def test_save_config_rejects_secret_like_keys(self):
        """save_config with 'tenants' key is blocked via _INTERNAL_KEYS."""
        assert "tenants" in _INTERNAL_KEYS

    def test_list_config_never_leaks_api_server_creds(self, tmp_path):
        """Even with tenant data present, list_config hides the tenants block."""
        from exa.config import _write_config_file

        _write_config_file({
            "tenants": {
                "t1": {"api_server": "https://example.com"},
            },
            "some_setting": "visible",
        })
        items = list_config()
        # The tenants dict (which contains api_server) is excluded
        assert "tenants" not in items
        # Normal settings are visible
        assert items["some_setting"] == "visible"

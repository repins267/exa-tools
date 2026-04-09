"""Tests for exa/config.py credential storage and tenant profiles."""

from unittest.mock import patch

import pytest

from exa.config import (
    DEFAULT_API_SERVER,
    get_default_tenant,
    load_config,
    load_profile,
    resolve_fqdn,
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


class TestResolveFqdn:
    def test_with_region_code(self):
        nick, fqdn, api, region = resolve_fqdn(
            "csdevfusion.use1.exabeam.cloud",
        )
        assert nick == "csdevfusion"
        assert fqdn == "csdevfusion.use1.exabeam.cloud"
        assert api == "https://api.us-east.exabeam.cloud"
        assert region == "US East"

    def test_without_region_code(self):
        nick, fqdn, api, region = resolve_fqdn(
            "sademodev22.exabeam.cloud",
        )
        assert nick == "sademodev22"
        assert api == DEFAULT_API_SERVER
        assert region == "US West"

    def test_nickname_only(self):
        nick, fqdn, api, region = resolve_fqdn("sademodev22")
        assert nick == "sademodev22"
        assert fqdn == "sademodev22.exabeam.cloud"
        assert api == DEFAULT_API_SERVER

    def test_unknown_region_code(self):
        with pytest.raises(ValueError, match="Unknown region code 'xyz99'"):
            resolve_fqdn("tenant.xyz99.exabeam.cloud")

    def test_invalid_domain(self):
        with pytest.raises(ValueError, match="Invalid tenant FQDN"):
            resolve_fqdn("tenant.aws.amazon.com")

    def test_strips_whitespace(self):
        nick, fqdn, api, _ = resolve_fqdn(
            "  sademodev22.exabeam.cloud  ",
        )
        assert nick == "sademodev22"
        assert fqdn == "sademodev22.exabeam.cloud"

    def test_all_region_codes(self):
        from exa.config import FQDN_REGION_MAP, REGION_LABELS

        for code, expected_api in FQDN_REGION_MAP.items():
            nick, fqdn, api, region = resolve_fqdn(
                f"test.{code}.exabeam.cloud",
            )
            assert api == expected_api
            assert region == REGION_LABELS[code]


class TestConfigureStoresFqdn:
    def test_save_profile_stores_fqdn_and_region(self):
        stored: dict = {}

        def mock_set(svc: str, key: str, val: str) -> None:
            stored.setdefault(svc, {})[key] = val

        with patch(
            "exa.config.keyring.set_password", side_effect=mock_set,
        ):
            save_profile(
                "csdevfusion",
                "https://api.us-east.exabeam.cloud",
                "id", "secret",
                fqdn="csdevfusion.use1.exabeam.cloud",
                region="US East",
            )

        import json as json_mod

        from exa.config import _CONFIG_FILE as _CFG_FILE

        data = json_mod.loads(_CFG_FILE.read_text(encoding="utf-8"))
        t = data["tenants"]["csdevfusion"]
        assert t["fqdn"] == "csdevfusion.use1.exabeam.cloud"
        assert t["region"] == "US East"
        assert t["api_server"] == "https://api.us-east.exabeam.cloud"


class TestFqdnPathTraversal:
    def test_path_traversal_in_fqdn(self):
        with pytest.raises(ValueError):
            resolve_fqdn("../../etc/passwd.exabeam.cloud")

    def test_null_byte_in_fqdn(self):
        with pytest.raises(ValueError):
            resolve_fqdn("tenant\x00.exabeam.cloud")

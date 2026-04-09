"""Credential storage and tenant configuration.

Secrets (client_id, client_secret) are stored in Windows Credential Manager
via keyring. Non-secret config (tenant name, api_server) is stored in
~/.exa/config.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import keyring

from exa.exceptions import ExaConfigError

_KEYRING_SERVICE = "exa-tools"
_CONFIG_DIR = Path.home() / ".exa"
_CONFIG_FILE = _CONFIG_DIR / "config.json"

REGIONS: dict[str, str] = {
    "US West": "https://api.us-west.exabeam.cloud",
    "US East": "https://api.us-east.exabeam.cloud",
    "EU": "https://api.eu.exabeam.cloud",
    "UK": "https://api.uk.exabeam.cloud",
    "AU": "https://api.au.exabeam.cloud",
    "CA": "https://api.ca.exabeam.cloud",
    "SG": "https://api.sg.exabeam.cloud",
    "JP": "https://api.jp.exabeam.cloud",
    "CH": "https://api.ch.exabeam.cloud",
    "SA": "https://api.sa.exabeam.cloud",
}


def _read_config_file() -> dict[str, Any]:
    """Read the full config.json, returning empty dict if missing."""
    if not _CONFIG_FILE.exists():
        return {}
    return json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))


def _write_config_file(data: dict[str, Any]) -> None:
    """Write the full config.json, creating ~/.exa/ if needed."""
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


# -- Profile management ------------------------------------------------------


def save_profile(
    tenant: str,
    api_server: str,
    client_id: str,
    client_secret: str,
) -> None:
    """Save a tenant profile.

    Stores client_id and client_secret in Windows Credential Manager
    via keyring under service "exa-tools/<tenant>".
    Stores tenant and api_server in ~/.exa/config.json.
    """
    service = f"{_KEYRING_SERVICE}/{tenant}"
    keyring.set_password(service, "client_id", client_id)
    keyring.set_password(service, "client_secret", client_secret)

    config = _read_config_file()
    tenants = config.setdefault("tenants", {})
    tenants[tenant] = {"api_server": api_server}
    _write_config_file(config)


def load_profile(tenant: str | None = None) -> tuple[str, str, str]:
    """Load a tenant profile.

    Args:
        tenant: Tenant name. If None, uses the default tenant.

    Returns:
        (api_server, client_id, client_secret)

    Raises:
        ExaConfigError: If no credentials are found.
    """
    if tenant is None:
        tenant = get_default_tenant()

    config = _read_config_file()
    tenants = config.get("tenants", {})
    tenant_config = tenants.get(tenant)
    if not tenant_config:
        raise ExaConfigError(
            f"No credentials found for tenant '{tenant}'. Run 'exa configure' first."
        )

    api_server = tenant_config.get("api_server", "")
    if not api_server:
        raise ExaConfigError(
            f"No API server configured for tenant '{tenant}'. Run 'exa configure' first."
        )

    service = f"{_KEYRING_SERVICE}/{tenant}"
    client_id = keyring.get_password(service, "client_id")
    client_secret = keyring.get_password(service, "client_secret")

    if not client_id or not client_secret:
        raise ExaConfigError(
            f"No credentials found for tenant '{tenant}'. Run 'exa configure' first."
        )

    return api_server, client_id, client_secret


# -- Default tenant -----------------------------------------------------------


def set_default_tenant(tenant: str) -> None:
    """Set the default tenant in config.json."""
    config = _read_config_file()
    config["default_tenant"] = tenant
    _write_config_file(config)


def get_default_tenant() -> str:
    """Get the default tenant name from config.json.

    Raises:
        ExaConfigError: If no default tenant is set.
    """
    config = _read_config_file()
    default = config.get("default_tenant")
    if not default:
        raise ExaConfigError("No default tenant configured. Run 'exa configure' first.")
    return default


# -- Generic config -----------------------------------------------------------


def save_config(key: str, value: Any) -> None:
    """Save a key-value pair to ~/.exa/config.json."""
    config = _read_config_file()
    config[key] = value
    _write_config_file(config)


def load_config(key: str) -> Any:
    """Load a value from ~/.exa/config.json. Returns None if not found."""
    config = _read_config_file()
    return config.get(key)


# Keys that are managed internally — not user-settable via `exa config set`
_INTERNAL_KEYS: frozenset[str] = frozenset({"tenants"})

# Keys that map to dedicated functions
_SPECIAL_KEYS: dict[str, str] = {
    "default-tenant": "default_tenant",
}


def list_config() -> dict[str, Any]:
    """Return all user-visible config key-value pairs.

    Excludes internal keys (tenants) and never includes secrets.
    """
    config = _read_config_file()
    return {k: v for k, v in config.items() if k not in _INTERNAL_KEYS}

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

# FQDN region code → API server mapping
FQDN_REGION_MAP: dict[str, str] = {
    "use1": "https://api.us-east.exabeam.cloud",
    "usw1": "https://api.us-west.exabeam.cloud",
    "euw1": "https://api.eu.exabeam.cloud",
    "ukw1": "https://api.uk.exabeam.cloud",
    "aue1": "https://api.au.exabeam.cloud",
    "cac1": "https://api.ca.exabeam.cloud",
    "apse1": "https://api.sg.exabeam.cloud",
    "apne1": "https://api.jp.exabeam.cloud",
    "che1": "https://api.ch.exabeam.cloud",
    "sae1": "https://api.sa.exabeam.cloud",
}

DEFAULT_API_SERVER = "https://api.us-west.exabeam.cloud"
DEFAULT_REGION_LABEL = "US West"

REGION_LABELS: dict[str, str] = {
    "use1": "US East",
    "usw1": "US West",
    "euw1": "EU",
    "ukw1": "UK",
    "aue1": "AU",
    "cac1": "CA",
    "apse1": "SG",
    "apne1": "JP",
    "che1": "CH",
    "sae1": "SA",
}

_EXA_DOMAIN = ".exabeam.cloud"


def resolve_fqdn(fqdn: str) -> tuple[str, str, str, str]:
    """Parse tenant FQDN and resolve to API server.

    Returns:
        (nickname, fqdn, api_server, region_label)

    Examples:
        "csdevfusion.use1.exabeam.cloud"
          -> ("csdevfusion", "csdevfusion.use1.exabeam.cloud",
              "https://api.us-east.exabeam.cloud", "US East")

        "sademodev22.exabeam.cloud"
          -> ("sademodev22", "sademodev22.exabeam.cloud",
              "https://api.us-west.exabeam.cloud", "US West")

        "sademodev22"
          -> ("sademodev22", "sademodev22.exabeam.cloud",
              "https://api.us-west.exabeam.cloud", "US West")
    """
    raw = fqdn.strip().rstrip("/")
    if not raw:
        raise ValueError("Tenant FQDN cannot be empty")

    # Validate no path traversal characters
    if any(c in raw for c in ("\x00", "<", ">", " ")):
        raise ValueError(
            f"Invalid tenant FQDN '{raw}'. "
            f"Expected format: <name>.exabeam.cloud or "
            f"<name>.<region>.exabeam.cloud"
        )

    # Nickname only (no dots)
    if "." not in raw:
        _validate_tenant_name(raw)
        return (
            raw,
            raw + _EXA_DOMAIN,
            DEFAULT_API_SERVER,
            DEFAULT_REGION_LABEL,
        )

    # Must end with .exabeam.cloud
    if not raw.endswith(_EXA_DOMAIN):
        raise ValueError(
            f"Invalid tenant FQDN '{raw}'. "
            f"Expected format: <name>.exabeam.cloud or "
            f"<name>.<region>.exabeam.cloud\n"
            f"Examples: sademodev22.exabeam.cloud\n"
            f"          csdevfusion.use1.exabeam.cloud"
        )

    prefix = raw.replace(_EXA_DOMAIN, "")
    parts = prefix.split(".")

    if ".." in raw or "/" in prefix or "\\" in prefix:
        raise ValueError(
            f"Invalid tenant FQDN '{raw}'. "
            f"Expected format: <name>.exabeam.cloud or "
            f"<name>.<region>.exabeam.cloud"
        )

    if len(parts) == 1:
        nickname = parts[0]
        _validate_tenant_name(nickname)
        return nickname, raw, DEFAULT_API_SERVER, DEFAULT_REGION_LABEL

    if len(parts) == 2:
        nickname = parts[0]
        code = parts[1]
        _validate_tenant_name(nickname)

        api_server = FQDN_REGION_MAP.get(code)
        if not api_server:
            known = ", ".join(sorted(FQDN_REGION_MAP.keys()))
            raise ValueError(
                f"Unknown region code '{code}' in FQDN '{raw}'. "
                f"Known codes: {known}. "
                f"Contact Exabeam support if your region "
                f"code is missing."
            )
        region_label = REGION_LABELS.get(code, code)
        return nickname, raw, api_server, region_label

    raise ValueError(
        f"Invalid tenant FQDN '{raw}'. "
        f"Expected format: <name>.exabeam.cloud or "
        f"<name>.<region>.exabeam.cloud"
    )


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


def _validate_tenant_name(tenant: str) -> None:
    """Validate tenant name for safety — no path traversal or injection."""
    if not tenant or not tenant.strip():
        raise ValueError("Tenant name cannot be empty")
    if any(c in tenant for c in ("/", "\\", "..", "\x00", "<", ">")):
        raise ValueError(
            f"Invalid tenant name: {tenant!r} — "
            f"must not contain path separators or special characters"
        )


def save_profile(
    tenant: str,
    api_server: str,
    client_id: str,
    client_secret: str,
    *,
    fqdn: str = "",
    region: str = "",
) -> None:
    """Save a tenant profile.

    Stores client_id and client_secret in Windows Credential Manager
    via keyring under service "exa-tools/<tenant>".
    Stores tenant, api_server, fqdn, and region in ~/.exa/config.json.
    """
    _validate_tenant_name(tenant)
    service = f"{_KEYRING_SERVICE}/{tenant}"
    keyring.set_password(service, "client_id", client_id)
    keyring.set_password(service, "client_secret", client_secret)

    config = _read_config_file()
    tenants = config.setdefault("tenants", {})
    entry: dict[str, str] = {"api_server": api_server}
    if fqdn:
        entry["fqdn"] = fqdn
    if region:
        entry["region"] = region
    tenants[tenant] = entry
    _write_config_file(config)


def load_profile(
    tenant: str | None = None,
) -> tuple[str, str, str]:
    """Load a tenant profile.

    Args:
        tenant: Tenant name or FQDN. If None, uses the default tenant.
                If contains '.exabeam.cloud', resolves FQDN to nickname.

    Returns:
        (api_server, client_id, client_secret)

    Raises:
        ExaConfigError: If no credentials are found.
    """
    if tenant is None:
        tenant = get_default_tenant()
    elif _EXA_DOMAIN in tenant:
        nickname, _, _, _ = resolve_fqdn(tenant)
        tenant = nickname

    config = _read_config_file()
    tenants = config.get("tenants", {})
    tenant_config = tenants.get(tenant)
    if not tenant_config:
        raise ExaConfigError(
            f"No credentials found for tenant '{tenant}'. "
            f"Run 'exa configure' first."
        )

    api_server = tenant_config.get("api_server", "")
    if not api_server:
        raise ExaConfigError(
            f"No API server configured for tenant '{tenant}'. "
            f"Run 'exa configure' first."
        )

    service = f"{_KEYRING_SERVICE}/{tenant}"
    client_id = keyring.get_password(service, "client_id")
    client_secret = keyring.get_password(service, "client_secret")

    if not client_id or not client_secret:
        raise ExaConfigError(
            f"No credentials found for tenant '{tenant}'. "
            f"Run 'exa configure' first."
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
        raise ExaConfigError(
            "No default tenant configured. Run 'exa configure' first."
        )
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

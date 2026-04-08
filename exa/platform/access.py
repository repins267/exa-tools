"""Platform and access control operations for Exabeam New-Scale.

API paths:
  /platform/v1/tenant
  /access-control/v1/apikeys
  /access-control/v1/roles
  /access-control/v1/users
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient


def get_tenant_info(client: ExaClient) -> dict[str, Any]:
    """Get tenant configuration and metadata."""
    return client.get("/platform/v1/tenant")


def get_api_keys(client: ExaClient) -> list[dict[str, Any]]:
    """List all API keys in the tenant."""
    return client.get("/access-control/v1/apikeys")


def get_roles(client: ExaClient) -> list[dict[str, Any]]:
    """List all roles in the tenant."""
    return client.get("/access-control/v1/roles")


def get_users(client: ExaClient) -> list[dict[str, Any]]:
    """List all users in the tenant."""
    return client.get("/access-control/v1/users")


def get_user(client: ExaClient, user_id: str) -> dict[str, Any]:
    """Get a specific user by ID."""
    return client.get(f"/access-control/v1/users/{user_id}")

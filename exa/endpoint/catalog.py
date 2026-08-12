"""Endpoint catalog loader.

Reads the endpoint_inventory from api-verification-results.json (produced by a prior
audit run or the Exabeam developer MCP). Falls back to an empty catalog so the module
still runs on first use with --discover-only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Default location written by the last audit run
_DEFAULT_CATALOG = Path.home() / ".exa" / "api-verification-results.json"

# Fallback: repo-local copy (written during development runs)
_REPO_CATALOG = Path(__file__).parents[2] / "api-verification-results.json"

# Endpoints to skip regardless of flags — destructive or auth-only
SKIP_ALWAYS = frozenset({
    "POST /auth/v1/token",
})

# Endpoints that return binary/non-JSON responses — will always 406 with a JSON client.
# Spec does not document the Accept header requirement or content-type for these.
# Skipped with reason "binary_response" so the audit table shows them clearly.
BINARY_RESPONSE_PATHS = frozenset({
    "/site-collectors/v1/cores/{coreId}/certificates/download",
})

# Endpoints that modify data — skipped unless --destructive is passed
DESTRUCTIVE_METHODS = frozenset({"DELETE", "PUT", "PATCH"})
# POST endpoints known to create or modify data (GET paths are never destructive).
# Note: /records is GET-only; the write endpoint is /addRecords.
DESTRUCTIVE_PATHS = frozenset({
    "/context-management/v1/tables/{id}/addRecords",       # write records
    "/context-management/v1/tables/{id}/addRecordsFromCsv",
    "/context-management/v1/tables/{id}/deleteRecords",    # POST bulk-delete
    "/context-management/v1/tables",                       # POST creates table
    "/correlation-rules/v2/rules",                         # POST creates rule
    "/correlation-rules/v2/rules/import",                  # POST imports rules
    "/correlation-rules/v2/rules/delete",                  # POST bulk-delete
    "/correlation-rules/v2/rules/setrulesstate",           # POST bulk enable/disable
    "/correlation-rules/v2/rules/{ruleId}/{status}",       # POST enable/disable one rule
    "/detection-management/v1/analytics-rules/import",
    "/threat-center/v1/cases/{caseId}",                    # POST updates case
    "/threat-center/v2/cases/{caseId}",
    "/threat-center/v1/alerts/{alertId}",                  # POST updates alert
    "/threat-center/v1/cases",                             # POST creates case (deprecated)
    "/threat-center/v2/cases",                             # POST creates case
    "/threat-center/v1/manual-cases",
    "/threat-center/v1/cases/{caseId}/notes",
    "/site-collectors/v1/cores",
    "/site-collectors/v1/collectors",
    "/site-collectors/v1/templates",
    "/auth/v1/token",
})


def load_catalog(path: Path | None = None) -> list[dict[str, Any]]:
    """Load endpoint inventory from JSON, trying default paths in order.

    Returns an empty list if no catalog is found.
    """
    candidates = [p for p in [path, _DEFAULT_CATALOG, _REPO_CATALOG] if p is not None]
    for candidate in candidates:
        if candidate.exists():
            data = json.loads(candidate.read_text(encoding="utf-8"))
            inventory = data.get("endpoint_inventory", [])
            return inventory
    return []


def is_destructive(endpoint: dict[str, Any]) -> bool:
    """Return True if this endpoint modifies data."""
    method = endpoint.get("method", "").upper()
    path = endpoint.get("path", "")
    if method in DESTRUCTIVE_METHODS:
        return True
    # POST endpoints known to write/modify
    if method == "POST" and path in DESTRUCTIVE_PATHS:
        return True
    return False


def is_skipped(endpoint: dict[str, Any]) -> bool:
    """Return True if this endpoint should always be excluded from results entirely."""
    key = f"{endpoint.get('method', '').upper()} {endpoint.get('path', '')}"
    return key in SKIP_ALWAYS


def is_binary_response(endpoint: dict[str, Any]) -> bool:
    """Return True if this endpoint returns binary/non-JSON content.

    These endpoints will always return HTTP 406 when called with Accept: application/json.
    The spec does not document the content-type constraint. Skip them to avoid false findings.
    """
    return endpoint.get("path", "") in BINARY_RESPONSE_PATHS


def filter_catalog(
    catalog: list[dict[str, Any]],
    *,
    spec: str | None = None,
    path_filter: str | None = None,
    include_destructive: bool = False,
) -> list[dict[str, Any]]:
    """Apply filters to the catalog and return the runnable subset."""
    results = []
    for ep in catalog:
        if is_skipped(ep):
            continue
        # Apply spec/path filters first so --spec and --endpoint always scope the output,
        # even for entries that will be shown as skipped.
        if spec and ep.get("spec", "").lower() != spec.lower():
            continue
        if path_filter and path_filter.lower() not in ep.get("path", "").lower():
            continue
        if is_binary_response(ep):
            ep = {**ep, "_skipped": "binary_response"}
        elif not include_destructive and is_destructive(ep):
            ep = {**ep, "_skipped": "destructive"}
        results.append(ep)
    return results

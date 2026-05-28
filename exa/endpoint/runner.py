"""Live endpoint audit runner.

For each endpoint in the catalog, makes a real HTTP call via ExaClient and compares
the actual HTTP status code against what the OpenAPI spec documents as valid.

ID resolution strategy:
  Path params like {alertId}, {ruleId}, {id} are resolved lazily on first use.
  Each resource type has one resolver that fetches a valid ID from the list endpoint.
  Resolvers are cached per run so the list endpoint is only called once per type.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from exa.exceptions import ExaAPIError

if TYPE_CHECKING:
    from exa.client import ExaClient

_AUDIT_DIR = Path.home() / ".exa" / "endpoint-audits"

# Map param name patterns → resolver functions (populated lazily)
_PARAM_RESOLVERS: dict[str, Any] = {}

# Cache of resolved IDs per resource type
_ID_CACHE: dict[str, str] = {}


# ---------------------------------------------------------------------------
# ID resolvers — fetch one valid ID per resource type
# ---------------------------------------------------------------------------

def _resolve_alert_id(client: ExaClient) -> str | None:
    r = client.post("/threat-center/v1/search/alerts", json={
        "fields": ["alertId"], "limit": 1, "filter": "",
        "startTime": "2025-01-01T00:00:00Z", "endTime": "2099-01-01T00:00:00Z",
    })
    rows = r.get("rows", [])
    return rows[0].get("alertId") if rows else None


def _resolve_case_id(client: ExaClient) -> str | None:
    r = client.post("/threat-center/v1/search/cases", json={
        "fields": ["caseId"], "limit": 1, "filter": "",
        "startTime": "2025-01-01T00:00:00Z", "endTime": "2099-01-01T00:00:00Z",
    })
    rows = r.get("rows", [])
    return rows[0].get("caseId") if rows else None


def _resolve_rule_id(client: ExaClient) -> str | None:
    r = client.get("/correlation-rules/v2/rules")
    rules = r if isinstance(r, list) else r.get("rules", r.get("items", []))
    return rules[0].get("id") if rules else None


def _resolve_analytics_id(client: ExaClient) -> str | None:
    r = client.get("/detection-management/v1/analytics-rules")
    rules = r.get("rules", [])
    return rules[0].get("id") if rules else None


def _resolve_table_id(client: ExaClient) -> str | None:
    r = client.get("/context-management/v1/tables")
    tables = r if isinstance(r, list) else r.get("tables", [])
    return tables[0].get("id") if tables else None


def _resolve_site_core_id(client: ExaClient) -> str | None:
    r = client.get("/site-collectors/v1/cores")
    items = r if isinstance(r, list) else r.get("data", r.get("items", []))
    return items[0].get("id") if items else None


def _resolve_site_collector_id(client: ExaClient) -> str | None:
    r = client.get("/site-collectors/v1/collectors")
    items = r if isinstance(r, list) else r.get("data", r.get("items", []))
    return items[0].get("id") if items else None


def _resolve_site_template_id(client: ExaClient) -> str | None:
    r = client.get("/site-collectors/v1/templates")
    items = r if isinstance(r, list) else r.get("data", r.get("items", []))
    return items[0].get("id") if items else None


def _resolve_cloud_collector_id(client: ExaClient) -> str | None:
    r = client.get("/cloud-collectors/v1/configs")
    items = r if isinstance(r, list) else r.get("data", r.get("items", []))
    return items[0].get("id") if items else None


def _resolve_cloud_account_id(client: ExaClient) -> str | None:
    r = client.get("/cloud-collectors/v1/accounts")
    items = r if isinstance(r, list) else r.get("data", r.get("items", []))
    return items[0].get("id") if items else None


_RESOLVER_MAP: dict[re.Pattern[str], tuple[str, Any]] = {
    re.compile(r"\{alertId\}",      re.I): ("alertId",          _resolve_alert_id),
    re.compile(r"\{caseId\}",       re.I): ("caseId",           _resolve_case_id),
    re.compile(r"\{ruleId\}",       re.I): ("ruleId",           _resolve_rule_id),
    re.compile(r"\{coreId\}",       re.I): ("coreId",           _resolve_site_core_id),
    re.compile(r"\{collectorId\}",  re.I): ("collectorId",      _resolve_site_collector_id),
    re.compile(r"\{templateId\}",   re.I): ("templateId",       _resolve_site_template_id),
    re.compile(r"\{accountId\}",    re.I): ("accountId",        _resolve_cloud_account_id),
    # trackerId comes from an upload operation — no live ID available; will be skipped
    re.compile(r"\{trackerId\}",    re.I): ("trackerId",        None),
    re.compile(r"\{id\}",           re.I): ("genericId",        None),  # resolved per spec below
}


def _resolve_path(client: ExaClient, path: str, spec: str) -> tuple[str, bool]:
    """Replace path params with real IDs. Returns (resolved_path, all_resolved)."""
    resolved = path
    all_ok = True

    params = re.findall(r"\{(\w+)\}", path)
    for param in params:
        cache_key = f"{spec}:{param}"
        if cache_key in _ID_CACHE:
            resolved = resolved.replace(f"{{{param}}}", _ID_CACHE[cache_key])
            continue

        # Find a resolver
        resolver_fn = None
        for pattern, (cache_name, fn) in _RESOLVER_MAP.items():
            if pattern.search(f"{{{param}}}"):
                resolver_fn = fn
                break

        # For generic {id}, pick resolver by spec name
        if param == "id" and resolver_fn is None:
            if "correlation" in spec:
                resolver_fn = _resolve_rule_id
            elif "detection" in spec or "analytics" in spec:
                resolver_fn = _resolve_analytics_id
            elif "context" in spec or "table" in spec:
                resolver_fn = _resolve_table_id
            elif "threat" in spec or "alert" in spec:
                resolver_fn = _resolve_alert_id

        if resolver_fn:
            try:
                value = resolver_fn(client)
                if value:
                    _ID_CACHE[cache_key] = value
                    resolved = resolved.replace(f"{{{param}}}", value)
                else:
                    all_ok = False
            except Exception:
                all_ok = False
        else:
            all_ok = False

    return resolved, all_ok


# ---------------------------------------------------------------------------
# Minimal request bodies for POST/PUT endpoints that aren't write operations
# ---------------------------------------------------------------------------

_MINIMAL_BODIES: dict[str, dict[str, Any]] = {
    "/search/v2/events": {
        "query": "activity_type:\"authentication\"",
        "filter": "",
        "startTime": "2026-01-01T00:00:00Z",
        "endTime":   "2026-01-02T00:00:00Z",
        "limit": 1,
    },
    "/audit/v1/events": {
        "fields": ["*"],
        "filter": "",
        "startTime": "2026-01-01T00:00:00Z",
        "endTime":   "2026-01-02T00:00:00Z",
        "limit": 1,
    },
    "/threat-center/v1/search/alerts": {
        "fields": ["alertId", "alertName"], "limit": 1,
        "filter": "",
        "startTime": "2025-01-01T00:00:00Z",
        "endTime":   "2099-01-01T00:00:00Z",
    },
    "/threat-center/v1/search/cases": {
        "fields": ["caseId", "name"], "limit": 1,
        "filter": "",
        "startTime": "2025-01-01T00:00:00Z",
        "endTime":   "2099-01-01T00:00:00Z",
    },
    "/threat-center/v1/alerts/threat-explainer/prompt": {
        # alertId resolved from path params in caller; body is minimal
        "alertId": "__resolved_from_path__",
    },
    "/correlation-rules/v2/rules/export": {
        "ruleIds": [],   # intentionally empty — will 400, spec documents this
    },
    "/detection-management/v1/analytics-rules/export": {
        "ruleIds": [],
    },
    # site-collector command endpoints — read-safe, generate install strings
    "/site-collectors/v1/collectors/commands/installation": {},
    "/site-collectors/v1/collectors/commands/uninstallation": {},
    "/site-collectors/v1/collectors/commands/support-package": {},
}


def _get_body(path: str) -> dict[str, Any] | None:
    """Return a minimal safe request body for known read-safe POST endpoints."""
    for key, body in _MINIMAL_BODIES.items():
        if key in path:
            return body
    return None


# ---------------------------------------------------------------------------
# Core audit runner
# ---------------------------------------------------------------------------

def _status_ok(actual: int, documented: list[int]) -> bool:
    """True if the actual status code is in the documented list."""
    if not documented:
        return True   # no spec data — can't evaluate
    return actual in documented


def run_audit(
    client: ExaClient,
    endpoints: list[dict[str, Any]],
    *,
    verbose: bool = False,
    on_progress: Any = None,
) -> list[dict[str, Any]]:
    """Run a live conformance test for each endpoint.

    Args:
        client:      Authenticated ExaClient.
        endpoints:   Filtered endpoint catalog (from catalog.filter_catalog).
        verbose:     Include full response body in results.
        on_progress: Optional callable(index, total, endpoint) for progress reporting.

    Returns:
        List of result dicts.
    """
    results: list[dict[str, Any]] = []
    total = len(endpoints)

    for i, ep in enumerate(endpoints):
        if on_progress:
            on_progress(i, total, ep)

        method   = ep.get("method", "GET").upper()
        path     = ep.get("path", "")
        spec     = ep.get("spec", "")
        doc_codes = ep.get("documented_status_codes", [])

        # Already marked as skipped by filter_catalog
        if ep.get("_skipped"):
            results.append({
                **_base_result(ep),
                "skipped": ep["_skipped"],
                "confirmed_status": None,
                "status_match": None,
                "new_finding": False,
                "finding_notes": f"Skipped: {ep['_skipped']}",
            })
            continue

        # Resolve path params
        resolved_path, all_resolved = _resolve_path(client, path, spec)
        if not all_resolved and "{" in resolved_path:
            results.append({
                **_base_result(ep),
                "skipped": "unresolved_params",
                "confirmed_status": None,
                "status_match": None,
                "new_finding": False,
                "finding_notes": f"Could not resolve path params: {resolved_path}",
            })
            continue

        # Make the request
        actual_status: int | None = None
        response_body: Any = None
        error_msg: str | None = None

        try:
            if method == "GET":
                response_body = client.get(resolved_path)
                actual_status = 200
            elif method == "POST":
                body = _get_body(path)
                if body is None:
                    # Unknown POST with no registered safe body — skip.
                    results.append({
                        **_base_result(ep),
                        "skipped": "unknown_post_body",
                        "confirmed_status": None,
                        "status_match": None,
                        "new_finding": False,
                        "finding_notes": "POST endpoint with no known safe body — skipped",
                    })
                    continue
                response_body = client.post(resolved_path, json=body)
                actual_status = 200
            else:
                results.append({
                    **_base_result(ep),
                    "skipped": f"method_{method.lower()}",
                    "confirmed_status": None,
                    "status_match": None,
                    "new_finding": False,
                    "finding_notes": f"Method {method} not tested in this run",
                })
                continue

        except ExaAPIError as exc:
            # ExaAPIError carries the actual HTTP status code directly.
            actual_status = exc.status_code
            error_msg = exc.detail[:300] if exc.detail else str(exc)[:300]
        except Exception as exc:
            error_msg = str(exc)[:300]

        status_ok = _status_ok(actual_status, doc_codes) if actual_status else None

        # Detect new findings
        new_finding = False
        notes: list[str] = []

        if actual_status and not status_ok:
            new_finding = True
            notes.append(
                f"HTTP {actual_status} not in documented codes {doc_codes}"
            )

        if actual_status == 500:
            new_finding = True
            notes.append("HTTP 500 — server error, should not appear in conformant API")

        if actual_status == 404 and 404 not in doc_codes:
            new_finding = True
            notes.append("HTTP 404 — endpoint may not be implemented")

        if error_msg and actual_status is None:
            new_finding = True
            notes.append(f"Request error: {error_msg}")

        result = {
            **_base_result(ep),
            "confirmed_status": actual_status,
            "status_match": status_ok,
            "new_finding": new_finding,
            "finding_notes": "; ".join(notes) if notes else "OK",
        }

        if verbose and response_body is not None:
            result["response_preview"] = str(response_body)[:500]

        results.append(result)

    return results


def _base_result(ep: dict[str, Any]) -> dict[str, Any]:
    return {
        "spec":                   ep.get("spec", ""),
        "method":                 ep.get("method", ""),
        "path":                   ep.get("path", ""),
        "summary":                ep.get("summary", ""),
        "documented_status_codes": ep.get("documented_status_codes", []),
        "tested_at":              datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

def save_audit(
    results: list[dict[str, Any]],
    tenant: str,
    *,
    output_path: Path | None = None,
) -> Path:
    """Save audit results to ~/.exa/endpoint-audits/{tenant}-{timestamp}.json."""
    _AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = output_path or (_AUDIT_DIR / f"{tenant}-{ts}.json")
    path.write_text(
        json.dumps({"tenant": tenant, "tested_at": ts, "results": results}, indent=2),
        encoding="utf-8",
    )
    return path


def load_last_audit(tenant: str) -> list[dict[str, Any]]:
    """Load the most recent audit for the given tenant."""
    if not _AUDIT_DIR.exists():
        return []
    files = sorted(_AUDIT_DIR.glob(f"{tenant}-*.json"), reverse=True)
    if not files:
        return []
    data = json.loads(files[0].read_text(encoding="utf-8"))
    return data.get("results", [])


def diff_audits(
    old: list[dict[str, Any]],
    new: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Compare two audit runs. Returns {fixed, broken, unchanged, new}."""
    old_map = {f"{r['method']} {r['path']}": r for r in old}
    new_map = {f"{r['method']} {r['path']}": r for r in new}

    fixed, broken, unchanged, added = [], [], [], []

    for key, new_r in new_map.items():
        old_r = old_map.get(key)
        if old_r is None:
            added.append(new_r)
            continue
        was_finding = old_r.get("new_finding", False)
        is_finding  = new_r.get("new_finding", False)
        if was_finding and not is_finding:
            fixed.append(new_r)
        elif not was_finding and is_finding:
            broken.append(new_r)
        else:
            unchanged.append(new_r)

    return {"fixed": fixed, "broken": broken, "unchanged": unchanged, "new": added}

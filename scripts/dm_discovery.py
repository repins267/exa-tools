"""Detection Management API endpoint discovery against sademodev22."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime

from exa.client import ExaClient
from exa.exceptions import ExaAPIError, ExaAuthError

PATHS = [
    # Known working — control
    "/detection-management/v1/analytics-rules",
    # Export/import candidates
    "/detection-management/v1/analytics-rules/export",
    "/detection-management/v1/analytics-rules/import",
    "/detection-management/v1/analytics-rules/bulk-export",
    "/detection-management/v1/analytics-rules/bulk",
    # Schema/discovery
    "/detection-management/v1/openapi.json",
    "/detection-management/v1/swagger.json",
    "/detection-management/v1/swagger-ui.html",
    "/detection-management/openapi.json",
    "/detection-management/swagger.json",
    "/detection-management/v1/",
    "/detection-management/",
    "/openapi.json",
    "/swagger.json",
    # Alternate module paths
    "/detection-mgmt/api/v1/",
    "/detection-mgmt/api/v1/exclusions",
    "/api/v1/rules/expensive/",
    "/api/v2/rules/training-status/",
]

INTERESTING_HEADERS = {"content-type", "x-request-id", "x-correlation-id", "www-authenticate", "retry-after", "allow"}


def probe(client, path: str) -> dict:
    result = {"path": path, "status": None, "body_excerpt": "", "headers": {}}
    try:
        resp = client.request("GET", path)
        _fill_from_response(result, resp)
    except ExaAPIError as exc:
        result["status"] = exc.status_code
        # Try to parse detail as JSON for top-level keys
        try:
            parsed = json.loads(exc.detail)
            if isinstance(parsed, dict):
                result["body_excerpt"] = json.dumps({k: "..." for k in list(parsed.keys())[:20]}, indent=2)[:500]
            else:
                result["body_excerpt"] = exc.detail[:500]
        except Exception:
            result["body_excerpt"] = exc.detail[:500]
    except ExaAuthError as exc:
        result["status"] = "AUTH_ERROR"
        result["body_excerpt"] = str(exc)[:500]
    except Exception as exc:
        result["status"] = f"ERROR({type(exc).__name__})"
        result["body_excerpt"] = str(exc)[:500]
    return result


def _fill_from_response(result: dict, resp) -> None:
    result["status"] = resp.status_code
    ct = resp.headers.get("content-type", "")
    for h in INTERESTING_HEADERS:
        if h in resp.headers:
            result["headers"][h] = resp.headers[h]
    raw = resp.text[:1000]
    if "json" in ct:
        try:
            parsed = resp.json()
            if isinstance(parsed, dict):
                result["body_excerpt"] = json.dumps({k: "..." for k in list(parsed.keys())[:20]}, indent=2)[:500]
            else:
                result["body_excerpt"] = json.dumps(parsed)[:500]
        except Exception:
            result["body_excerpt"] = raw[:500]
    else:
        result["body_excerpt"] = raw[:500]


def main() -> None:
    print("Authenticating...", flush=True)
    client = ExaClient()
    client.authenticate()
    print(f"Authenticated. Probing {len(PATHS)} paths...\n", flush=True)

    results = []
    for path in PATHS:
        print(f"  GET {path}", end=" ", flush=True)
        r = probe(client, path)
        results.append(r)
        print(f"-> {r['status']}", flush=True)

    client.close()

    # Console table
    print("\n" + "=" * 100)
    print(f"{'Path':<55} {'Status':<12} {'Body excerpt'}")
    print("-" * 100)
    for r in results:
        snippet = r["body_excerpt"].replace("\n", " ")[:40]
        print(f"{r['path']:<55} {str(r['status']):<12} {snippet}")

    # Markdown report
    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Detection Management Endpoint Discovery",
        f"",
        f"Tenant: sademodev22  |  Date: {ts}",
        f"",
        f"## Summary Table",
        f"",
        f"| Path | Status | Content-Type |",
        f"|---|---|---|",
    ]
    for r in results:
        ct = r["headers"].get("content-type", "-")
        lines.append(f"| `{r['path']}` | {r['status']} | {ct} |")

    lines += ["", "## Detail", ""]
    for r in results:
        lines.append(f"### `{r['path']}`")
        lines.append(f"")
        lines.append(f"**Status:** {r['status']}")
        if r["headers"]:
            lines.append(f"")
            lines.append(f"**Headers:**")
            for k, v in r["headers"].items():
                lines.append(f"- `{k}`: {v}")
        if r["body_excerpt"]:
            lines.append(f"")
            lines.append(f"**Body (excerpt):**")
            lines.append(f"```")
            lines.append(r["body_excerpt"])
            lines.append(f"```")
        lines.append(f"")

    out_path = r"E:\Python\exa-prompts\dm-endpoint-discovery-results.md"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()

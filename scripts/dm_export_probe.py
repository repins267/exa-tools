"""Probe the detection-management export endpoint with various POST payloads."""

from __future__ import annotations

import json

from exa.client import ExaClient
from exa.exceptions import ExaAPIError, ExaAuthError

EXPORT_PATH = "/detection-management/v1/analytics-rules/export"

# First get a real rule ID to use in payloads
LIST_PATH = "/detection-management/v1/analytics-rules"

PAYLOADS = [
    ("empty body", {}),
    ("null ruleIds", {"ruleIds": None}),
    ("empty ruleIds list", {"ruleIds": []}),
    ("no body (None)", None),
    ("export all flag", {"exportAll": True}),
    ("ids key", {"ids": []}),
    ("rules key", {"rules": []}),
]


def post_probe(client, path: str, body) -> dict:
    result = {"body_sent": repr(body), "status": None, "response": ""}
    try:
        resp = client.request("POST", path, json=body)
        result["status"] = resp.status_code
        try:
            parsed = resp.json()
            result["response"] = json.dumps(parsed, indent=2)[:800]
        except Exception:
            result["response"] = resp.text[:800]
    except ExaAPIError as exc:
        result["status"] = exc.status_code
        try:
            parsed = json.loads(exc.detail)
            result["response"] = json.dumps(parsed, indent=2)[:800]
        except Exception:
            result["response"] = exc.detail[:500]
    except ExaAuthError as exc:
        result["status"] = "AUTH_ERROR"
        result["response"] = str(exc)[:300]
    except Exception as exc:
        result["status"] = f"ERROR({type(exc).__name__})"
        result["response"] = str(exc)[:300]
    return result


def main() -> None:
    client = ExaClient()
    client.authenticate()
    print("Authenticated.\n")

    # Get one real rule ID
    try:
        resp = client.request("GET", LIST_PATH)
        rules_data = resp.json()
        rules = rules_data.get("rules", rules_data) if isinstance(rules_data, dict) else rules_data
        first_id = rules[0].get("id") if rules else None
        print(f"Got {len(rules)} rules. First ID: {first_id}\n")
    except Exception as exc:
        print(f"Could not fetch rules: {exc}")
        first_id = None

    if first_id:
        PAYLOADS.append(("single ruleIds with real ID", {"ruleIds": [first_id]}))
        PAYLOADS.append(("ids with real ID", {"ids": [first_id]}))

    print(f"Probing POST {EXPORT_PATH} with {len(PAYLOADS)} payloads...\n")
    print("=" * 80)

    for label, body in PAYLOADS:
        r = post_probe(client, EXPORT_PATH, body)
        print(f"Payload: {label}")
        print(f"  Sent:   {r['body_sent']}")
        print(f"  Status: {r['status']}")
        resp_lines = r["response"].splitlines()
        for line in resp_lines[:15]:
            print(f"  {line}")
        print()

    client.close()


if __name__ == "__main__":
    main()

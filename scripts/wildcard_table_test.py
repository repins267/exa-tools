"""Definitive test: do context table wildcard values work in correlation rules?

Creates a context table with "HOST10783*" as the stored value, deploys a
LIVE correlation rule using that table, waits for natural auth events to
arrive on sademodev22, then checks if any alerts fired.

If wildcards ARE expanded at rule evaluation: alerts will appear for
  events where user=HOST10783$ (or any HOST10783... user)
If exact-only: zero alerts (no event has user literally = "HOST10783*")

Cleans up rule + table regardless of outcome.
"""
from __future__ import annotations

import time

from exa.case.alerts import search_alerts
from exa.client import ExaClient
from exa.context.tables import add_records, create_table, delete_table, get_tables
from exa.correlation.rules import create_rule, delete_rule, get_rules

client = ExaClient(tenant="sademodev22")
client.authenticate()

TABLE_NAME = "EXA_TOOLS_WILDCARD_TEST"
RULE_NAME  = "EXA_TOOLS_WILDCARD_TEST - delete me"

# ── Step 1: find a real HOST* user with recent auth events ─────────────────
from exa.search.events import search_events

print("=== Step 1: find a real HOST* user ===")
rows = search_events(client, 'activity_type:"authentication"', limit=100)
host_users = sorted({r.get("user") for r in rows
                     if r.get("user") and r.get("user") != "system"})
print("HOST$ users with recent auth events:", host_users)

if not host_users:
    print("No HOST$ users found — aborting")
    raise SystemExit(1)

# Use the first one; strip the trailing $ to build a prefix pattern
test_user = host_users[0]
# Pattern: "HOST10783*" matches HOST10783$ but NOT the literal string "HOST10783*"
import re as _re
# Build a regex that matches the test_user exactly — e.g. HOST890$ -> ^HOST890\$$
# Also test a broad regex: HOST.* which should match all HOST* users
regex_exact = "^" + _re.escape(test_user) + "$"   # e.g. ^HOST890\$$
regex_broad = f"^{_re.escape(test_user[:4])}.*"     # matches any user starting with same 4 chars
pattern = regex_broad   # use broad regex to maximise chance of match if supported
print(f"Test user:      {test_user!r}")
print(f"Regex (broad):  {pattern!r}  (stored in table)")
print(f"Regex (exact):  {regex_exact!r}  (for reference)")
print(f"Exact count baseline: ", end="", flush=True)
baseline = search_events(client, f'activity_type:"authentication" AND user:"{test_user}"', limit=5)
print(f"{len(baseline)} recent auth events for this user")

# ── Step 2: create context table with the wildcard pattern ─────────────────
print(f"\n=== Step 2: create table '{TABLE_NAME}' with value '{pattern}' ===")
existing = get_tables(client)
for t in existing:
    if (t.get("displayName") or t.get("name") or "").lower() == TABLE_NAME.lower():
        delete_table(client, t["id"])
        time.sleep(1)

resp = create_table(client, TABLE_NAME, context_type="Other",
                    attributes=[{"id": "value", "isKey": True}])
table_obj = resp.get("table", resp) if isinstance(resp, dict) else resp
table_id  = table_obj["id"]
add_records(client, table_id, [{"value": pattern}], operation="replace")
print(f"  Table id: {table_id}  record: '{pattern}'")
time.sleep(3)

# ── Step 3: create and ENABLE a live correlation rule ─────────────────────
print(f"\n=== Step 3: deploy live correlation rule ===")

for r in get_rules(client, name="EXA_TOOLS_WILDCARD_TEST"):
    delete_rule(client, r["id"])
    time.sleep(1)

eql = f'activity_type:"authentication" AND user IN "{TABLE_NAME}"'
rule_body = {
    "name": RULE_NAME,
    "description": "Temporary wildcard-in-context-table test - safe to delete",
    "severity": "low",
    "enabled": True,
    "sequencesConfig": {
        "sequences": [{
            "name": "Sequence 1",
            "query": eql,
            "condition": {"triggerOnAnyMatch": True},
        }],
        "sequencesExecution": "CREATION_ORDER",
    },
}
rule_resp = create_rule(client, rule_body)
rule_id = rule_resp.get("id", "")
print(f"  Rule id: {rule_id}")
print(f"  EQL:     {eql}")
print(f"  Enabled: True")

try:
    # ── Step 4: wait for natural events ──────────────────────────────────
    wait_secs = 90
    print(f"\n=== Step 4: waiting {wait_secs}s for natural auth events to trigger rule ===")
    for i in range(wait_secs // 10):
        time.sleep(10)
        print(f"  {(i+1)*10}s elapsed...", flush=True)

    # ── Step 5: check for alerts ──────────────────────────────────────────
    print(f"\n=== Step 5: check for alerts from '{RULE_NAME}' ===")
    alert_rows = search_alerts(client, filter=f'alert_name:"{RULE_NAME}"', limit=20)
    print(f"  Alerts found: {len(alert_rows)}")
    for a in alert_rows[:5]:
        print(f"    - {a.get('alertName')}  users={a.get('users')}  created={a.get('alertCreationTimestamp')}")

    # ── Verdict ───────────────────────────────────────────────────────────
    print("\n" + "="*60)
    print("VERDICT")
    if len(alert_rows) > 0:
        print(f"  WILDCARDS SUPPORTED: rule fired {len(alert_rows)} alert(s)")
        print(f"  Stored '{pattern}' matched events with user='{test_user}' (or similar)")
    else:
        print(f"  EXACT ONLY (or no new events in {wait_secs}s window)")
        print(f"  Stored '{pattern}' produced zero alerts")
        exact_eql = f'activity_type:"authentication" AND user:"{test_user}"'
        exact_rows = search_events(client, exact_eql, limit=5)
        print(f"  Cross-check: {len(exact_rows)} recent events for exact user '{test_user}'")
        if exact_rows:
            print("  -> Events exist but rule did NOT fire => wildcard NOT expanded in table values")
        else:
            print("  -> No recent events; result is inconclusive")

finally:
    # ── Cleanup always runs ───────────────────────────────────────────────
    print(f"\n=== Cleanup ===")
    try:
        delete_rule(client, rule_id)
        print(f"  Rule {rule_id} deleted")
    except Exception as e:
        print(f"  Rule delete failed: {e}")
    try:
        delete_table(client, table_id)
        print(f"  Table {table_id} deleted")
    except Exception as e:
        print(f"  Table delete failed: {e}")
    print("Done.")

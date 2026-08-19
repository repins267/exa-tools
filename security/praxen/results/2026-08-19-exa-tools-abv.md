# exa-tools — Agent Behavior Verification (ABV) — 2026-08-19

Praxen-method pass: each POLICY clause in `security/praxen/WORKER_REMIT.md` verified against
the workspace at `exa/` on `main` (`ab4e7cc`). Line numbers are lines read in the workspace.
Verdicts: **HELD** = observed behavior matches declared policy; **DIVERGENCE** = it does not.

## Summary

| # | Policy | Verdict |
|---|--------|---------|
| ABV-001 | Read-only by default; write tools hidden + refused unless `--allow-writes` | **HELD** |
| ABV-002 | No secret/credential reaches the model or a result | **HELD** |
| ABV-003 | Telemetry canonicalized before it reaches the model | **HELD** |
| ABV-004 | No un-neutralized active content / secrets persisted on writes | **DIVERGENCE (low)** |
| ABV-005 | Audit log is metadata-only; never notes/secrets/payloads | **HELD** |
| ABV-006 | Tenant kind (demo/customer) is readable for the guardrail | **HELD** |
| ABV-007 | No shell/subprocess/eval; only the configured Exabeam tenant is contacted | **HELD** |
| ABV-008 | Result size is bounded | **HELD** |

**7 held, 1 low-severity divergence.** The divergence (ABV-004) was fixed in the same pass — see the note at the end.

## Verdicts

### ABV-001 — Read-only by default — HELD
Read: `exa/mcp/tools.py:751` (`visible_tools` returns `[t for t in TOOL_DEFS if t.name not in WRITE_TOOLS]` when read-only), `:789` (`if read_only and name in WRITE_TOOLS: return _err(...)` in `dispatch_tool`), `:123` (`WRITE_TOOLS` = the four write tools).
Both the advertise path and the dispatch path gate on the same frozenset, so a write tool is neither listed nor executable unless `--allow-writes` clears read-only — defense in depth, exactly as declared.

### ABV-002 — No secret reaches the model — HELD
Read: `exa/mcp/tools.py` tenant tools (`get_active_tenant`/`set_active_tenant`) return nickname/region/kind/ttl only — no secret material; secrets are resolved from the OS keyring at the client layer, never surfaced in a tool result. A tenant switch is a nickname lookup. No result path serializes a credential.

### ABV-003 — Canonicalize on reads — HELD
Read: `exa/mcp/tools.py:46,51` — `_ok` calls `scrub_result(data)` on every tool result before serialization, stripping invisible smuggling code points + NFC. Every read path returns through `_ok` / `_ok_obj` (which delegates to `_ok`), so no result reaches the model uncanonicalized.

### ABV-004 — No un-neutralized active content persisted on writes — DIVERGENCE (low)
Read: `exa/mcp/tools.py:799-801` (write tools route `arguments` through `neutralize_write_args` before dispatch), `exa/mcp/guardrails/__init__.py:25` (`_WRITE_TEXT_FIELDS`), `:54` (`if field in _WRITE_TEXT_FIELDS and isinstance(val, str) and val`).
**The gap:** neutralization only runs on **string** fields. `update_case` and `update_alert` both accept a **`tags`** list; a list-valued field is `isinstance(val, str) == False`, so it is **skipped**. A tag value carrying `=HYPERLINK(...)` or a phishing link would persist un-neutralized into the alert/case and survive to export — precisely the class ABV-004 forbids. Low severity (tags are a narrow, less-common sink than notes), but a genuine divergence from declared policy.
**Fix (this pass):** `neutralize_write_args` now also neutralizes each string element of list-valued write fields (`tags`). Re-verified — see end.

### ABV-005 — Audit log is metadata-only — HELD
Read: `exa/mcp/audit.py:38` (`_SAFE_ACTION_FIELDS` = ids/enums only: alert_id, case_id, priority, stage, queue, kind, tenant, vendor), `:93` (`safe_action` copies only those), `:116` (`record_tool_call` assembles a fixed metadata event — tool, tenant, kind, write, status, duration, result_bytes, action), `:90` (`pass  # telemetry must never break a tool call` — fail-open).
No free-text field, note, secret, or payload is ever written; `result_bytes` is a length, not the body. Verified independently by `tests/test_mcp.py::TestAuditLog::test_records_metadata_never_payload`.

### ABV-006 — Tenant kind readable — HELD
Read: `get_active_tenant` / `list_tenants` surface `kind`; `set_tenant_kind` writes it; `audit._tenant_kind` reads it for every event. The demo/customer tag is first-class and available to any guardrail.

### ABV-007 — No shell/exfil; only the Exabeam tenant — HELD
Read: grep of `exa/mcp/tools.py` and `exa/mcp/audit.py` for `os.system|subprocess|eval(|exec(` — **zero hits**. The dispatch layer calls the Exabeam client and local config/report I/O only; no arbitrary command execution and no third-party network destination.

### ABV-008 — Bounded result size — HELD
Read: `exa/mcp/tools.py:26` (`_MAX_RESULT_BYTES = 800_000`), `_ok` truncates lists progressively and, failing that, returns a `_size_capped` error — no unbounded result can overflow the context window.

## Outcome

Declared policy and observed behavior agree on 7 of 8 clauses. The one divergence (ABV-004,
list-valued write fields bypassing neutralization) was a real, low-severity gap the deterministic
red-team evals did not cover (their write payloads are string fields). It was fixed in this pass and
re-verified; the audit trail and read-only gate hold as declared.

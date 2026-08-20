# /// script
# requires-python = ">=3.11"
# ///
"""Generate the exa-tools TOOL SPINE — the factual tool -> API-endpoint map — from source,
with a `--check` freshness/validity gate for CI.

The Deep Dive's prose (formulas, caveats, how-to-verify) is human-authored, but its
*factual spine* — which MCP tool hits which Exabeam endpoint — must never drift from the
code. This script makes the spine machine-checkable:

  1. COMPLETENESS — every MCP tool in `exa.mcp.tools.TOOL_DEFS` has a spine entry, and no
     spine entry names a tool that no longer exists. A new/removed tool fails the gate.
  2. VALIDITY — every REST endpoint a spine entry claims still appears as an API-path
     literal in `exa/` (f-strings included, matched by static stem). A renamed/removed
     endpoint fails the gate.
  3. FRESHNESS — the on-disk `security/tool_spine.md` matches what this script generates
     from the current TOOL_ENDPOINTS map. `--check` fails if it is stale.

What this does NOT prove: that the hand-declared mapping is *semantically* right (that a
tool truly calls endpoint Y, not Z). That one assertion is seeded from the verified
four-agent provenance extraction and reviewed on change — but completeness + validity +
freshness catch the drift that actually happens (a tool added without docs, an endpoint
path renamed). Deterministic: same code -> byte-identical output (no timestamp).

Usage:
    uv run security/gen_tool_spine.py            # (re)write security/tool_spine.md
    uv run security/gen_tool_spine.py --check    # non-zero exit if stale/incomplete/invalid
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "security" / "tool_spine.md"

# ---------------------------------------------------------------------------
# Authoritative tool -> endpoint(s) map, in Deep Dive group order.
# Endpoints are "METHOD /path" (path may be templated with {id}); non-REST tools use a
# "(...)" marker. Seeded from the verified provenance extraction (2026-08-20). The gate
# below enforces that this stays complete (vs TOOL_DEFS) and valid (endpoints exist in code).
# ---------------------------------------------------------------------------
TOOL_ENDPOINTS: dict[str, list[str]] = {
    # Search, cases & alerts
    "search_alerts": ["POST /threat-center/v1/search/alerts"],
    "get_alert": ["POST /threat-center/v1/search/alerts"],
    "search_cases": ["POST /threat-center/v1/search/cases"],
    "get_case": ["GET /threat-center/v1/cases/{id}"],
    "search_events": ["POST /search/v2/events"],
    "create_case": ["POST /threat-center/v2/cases", "POST /threat-center/v1/cases (fallback)"],
    "update_case": ["POST /threat-center/v2/cases/{id}", "POST /threat-center/v1/cases/{id} (fallback)"],
    "update_alert": ["POST /threat-center/v1/alerts/{id}"],
    "add_case_note": ["POST /threat-center/v1/cases/{id}/notes (UNVERIFIED)"],
    # Detection
    "list_detection_rules": ["GET /detection-management/v1/analytics-rules"],
    # Tenant (local only)
    "get_active_tenant": ["(local: session + ~/.exa/config.json)"],
    "list_tenants": ["(local: ~/.exa/config.json)"],
    "set_active_tenant": ["(local: config write + client re-auth)"],
    "set_tenant_kind": ["(local: ~/.exa/config.json)"],
    # Health & ingest
    "get_license_consumption": ["GET /health-consumption/v2/consumption/licenseDetails"],
    "get_app_status": ["GET /health-consumption/v1/health/appStatus"],
    "list_collectors": ["GET /cloud-collectors/v1/configs"],
    "parser_health": ["POST /search/v2/events"],
    "ingest_value": [
        "POST /search/v2/events",
        "GET /health-consumption/v2/consumption/licenseDetails",
        "GET /detection-management/v1/analytics-rules",
    ],
    "source_detail": ["POST /search/v2/events", "GET /detection-management/v1/analytics-rules"],
    # Identity & context
    "identity_health": [
        "GET /context-management/v1/tables",
        "GET /context-management/v1/tables/{id}/records",
        "POST /search/v2/events",
    ],
    "context_table": [
        "GET /context-management/v1/tables",
        "GET /context-management/v1/tables/{id}/records",
    ],
    # AI/LLM
    "aillm_sources": ["POST /search/v2/events", "GET /cloud-collectors/v1/configs"],
    "aillm_validate": [
        "GET /context-management/v1/tables",
        "GET /context-management/v1/tables/{id}/records",
        "POST /search/v2/events",
    ],
    "aillm_rules": ["GET /detection-management/v1/analytics-rules", "POST /search/v2/events"],
    "aillm_risk": ["POST /search/v2/events", "(local: cached AI/LLM reference dataset)"],
    "aillm_gaps": [
        "GET /context-management/v1/tables",
        "GET /context-management/v1/tables/{id}/records",
        "POST /search/v2/events",
    ],
    "ai_domain_lookup": ["(none: local cached reference dataset)"],
    # SOC & tuning
    "soc_kpis": ["POST /threat-center/v1/search/cases"],
    "tuning_report": ["POST /threat-center/v1/search/alerts", "GET /detection-management/v1/analytics-rules"],
    # Reports
    "render_report": ["(none: renders caller-supplied spec)"],
    "render_dashboard": ["POST /search/v2/events (live SAMPLE only)", "(none: layout)"],
    "render_abv": ["(none: hand-authored in-code snapshot)"],
}

_PATH_LITERAL = re.compile(r'f?["\'](/[a-z][a-z0-9-]*/v[0-9]+/[^"\'{]*)')
_REST = re.compile(r"^(GET|POST|PUT|DELETE|PATCH)\s+(/\S+)")


def code_endpoint_stems() -> set[str]:
    """Every API-path literal in exa/ reduced to its static stem (prefix before any '{')."""
    stems: set[str] = set()
    for py in (ROOT / "exa").rglob("*.py"):
        try:
            text = py.read_text(encoding="utf-8")
        except OSError:
            continue
        for m in _PATH_LITERAL.finditer(text):
            stems.add(m.group(1).split("{")[0])
    return stems


def _doc_stem(path: str) -> str:
    """The comparable stem for a documented endpoint path (strip any '(note)' + template)."""
    path = path.split(" (")[0]  # drop "(fallback)"/"(UNVERIFIED)" suffixes
    return path.split("{")[0]


def validate() -> list[str]:
    """Completeness + validity problems; empty list means the spine is sound."""
    from exa.mcp.tools import TOOL_DEFS

    problems: list[str] = []
    tool_names = {t.name for t in TOOL_DEFS}
    spine_names = set(TOOL_ENDPOINTS)

    for missing in sorted(tool_names - spine_names):
        problems.append(f"tool '{missing}' exists in TOOL_DEFS but has no spine entry")
    for stale in sorted(spine_names - tool_names):
        problems.append(f"spine entry '{stale}' names a tool not in TOOL_DEFS")

    stems = code_endpoint_stems()
    for tool, endpoints in TOOL_ENDPOINTS.items():
        for ep in endpoints:
            m = _REST.match(ep)
            if not m:
                continue  # a "(local ...)" / "(none ...)" marker — nothing to verify
            path = _doc_stem(m.group(2))
            if path not in stems:
                problems.append(
                    f"tool '{tool}' claims endpoint '{ep}' but no matching API-path "
                    f"literal (stem '{path}') was found in exa/"
                )
    return problems


def build_md() -> str:
    """Deterministic Markdown spine (grouped in TOOL_ENDPOINTS order)."""
    lines = [
        "# exa-tools tool spine (generated — do not edit by hand)",
        "",
        "Machine-checked map of each MCP tool to the Exabeam API endpoint(s) it calls.",
        "Generated by `security/gen_tool_spine.py`; CI runs `--check` to fail the build if",
        "this drifts from the code. Human-readable provenance (query, computation, limits,",
        "how to verify) lives in the Deep Dive; this file guarantees the endpoint column is true.",
        "",
        f"Tools: {len(TOOL_ENDPOINTS)}",
        "",
        "| MCP tool | Endpoint(s) |",
        "| --- | --- |",
    ]
    for tool, endpoints in TOOL_ENDPOINTS.items():
        lines.append(f"| `{tool}` | {' · '.join(endpoints)} |")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    problems = validate()
    if problems:
        print("TOOL SPINE INVALID:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(
            "Fix the TOOL_ENDPOINTS map in security/gen_tool_spine.py (and the Deep Dive) "
            "to match the code.",
            file=sys.stderr,
        )
        return 1

    md = build_md()
    if "--check" in argv:
        if not OUT.exists():
            print("tool_spine.md missing — run: uv run security/gen_tool_spine.py", file=sys.stderr)
            return 1
        if OUT.read_text(encoding="utf-8") != md:
            print("tool spine is stale vs code — run: uv run security/gen_tool_spine.py", file=sys.stderr)
            return 1
        print(f"tool spine is fresh ({len(TOOL_ENDPOINTS)} tools).")
        return 0

    OUT.write_text(md, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(TOOL_ENDPOINTS)} tools)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

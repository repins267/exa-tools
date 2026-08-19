# /// script
# requires-python = ">=3.11"
# ///
"""Generate exa-tools' AI Bill of Materials (CycloneDX 1.6) from the repo's own sources.

exa-tools is an AI-adjacent *application* — an MCP server + Claude skills that run on a
hosted foundation model (Claude) and call the Exabeam New-Scale API. Model-card BOM tools
(which ingest a Hugging Face model id) can't describe that, so this assembles a CycloneDX
AI-BOM directly from what exa-tools actually ships:

  - the root component (this package) from pyproject.toml,
  - the foundation model (Claude) as an external machine-learning-model component,
  - the skills / methodology (plugin/skills/*/SKILL.md) as a `data` component,
  - the runtime Python dependencies (pyproject) as `library` components,
  - the Exabeam New-Scale API as a `service` with its inbound/outbound data flows,
  - governance/guardrails (read-only default, write gate, canonicalize/neutralize,
    metadata-only audit log, keyring secrets, tenant-kind) as metadata properties.

Deterministic: same repo state -> byte-identical output (stable uuid5 serial; timestamp
from SOURCE_DATE_EPOCH if set, else current UTC — `--check` ignores the timestamp so CI
can verify freshness).

Design follows socxen's gen_aibom.py (Apache-2.0); this is an independent implementation
for exa-tools' own sources.

Usage:
    uv run security/gen_aibom.py            # (re)write security/aibom.cdx.json + .html
    uv run security/gen_aibom.py --check    # non-zero exit if the on-disk BOM is stale
"""

from __future__ import annotations

import datetime
import json
import os
import re
import sys
import tomllib
import uuid
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEC = ROOT / "security"
JSON_OUT = SEC / "aibom.cdx.json"
HTML_OUT = SEC / "aibom.html"

_NS = uuid.UUID("6e6f5f65-7861-7400-8000-000000000000")  # fixed namespace -> stable serial

# SPDX ids for the runtime PyPI deps, verified against PyPI/upstream. A dep added to
# pyproject without an entry here ships with no license claim rather than a guessed one.
DEP_LICENSES = {
    "httpx": "BSD-3-Clause",
    "keyring": "MIT",
    "rich": "MIT",
    "typer": "MIT",
    "pydantic": "MIT",
    "pandas": "BSD-3-Clause",
    "openpyxl": "MIT",
    "mcp": "MIT",
}
SUPPLIER = {"name": "Exabeam, Inc.", "url": ["https://github.com/repins267/exa-tools"]}


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _dep_name(spec: str) -> tuple[str, str | None]:
    m = re.match(r"([A-Za-z0-9_.\-]+)\s*(.*)", spec.strip())
    return m.group(1), (m.group(2).strip() or None)


def _skills() -> list[str]:
    return sorted(p.name for p in (ROOT / "plugin" / "skills").iterdir() if (p / "SKILL.md").exists())


def _tool_count() -> int:
    txt = (ROOT / "exa" / "mcp" / "tools.py").read_text(encoding="utf-8")
    return len(set(re.findall(r'name="([a-z_]+)"', txt)))


def _timestamp() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    dt = (datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc)
          if epoch else datetime.datetime.now(datetime.timezone.utc))
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_bom() -> dict:
    pp = _pyproject()["project"]
    name, version = pp["name"], pp.get("version", "0")
    deps = pp.get("dependencies", [])
    skills = _skills()
    ntools = _tool_count()
    root_ref = f"pkg:pypi/{name}@{version}"

    components: list[dict] = [
        {
            "bom-ref": "model:anthropic-claude",
            "type": "machine-learning-model",
            "name": "Claude (Anthropic)",
            "description": (
                "Foundation model the skills run on. Hosted API — weights are not distributed "
                "with exa-tools. The specific member (Opus / Sonnet / Haiku) is selected at "
                "runtime by the Claude client, not pinned by exa-tools."
            ),
            "supplier": {"name": "Anthropic", "url": ["https://www.anthropic.com"]},
            "externalReferences": [
                {"type": "website", "url": "https://docs.anthropic.com"},
            ],
        },
        {
            "bom-ref": "data:skills-methodology",
            "type": "data",
            "name": "exa-tools skills & methodology",
            "description": (
                f"{len(skills)} agentic skills (prompt + method) that drive the MCP tools and CLI: "
                + ", ".join(skills)
                + ". Includes tenant-preflight, report method, and prompt-injection traps. Static "
                "text shipped in the repo — not learned weights."
            ),
        },
    ]

    for spec in deps:
        dn, ver = _dep_name(spec)
        comp = {
            "bom-ref": f"pkg:pypi/{dn}",
            "type": "library",
            "name": dn,
            "purl": f"pkg:pypi/{dn}",
        }
        if ver:
            comp["version"] = ver
        if dn in DEP_LICENSES:
            comp["licenses"] = [{"license": {"id": DEP_LICENSES[dn]}}]
        components.append(comp)

    services = [{
        "bom-ref": "service:exabeam-nsa",
        "name": "Exabeam New-Scale Analytics API",
        "description": "The SIEM/UEBA backend exa-tools reads from and (when --allow-writes) writes to.",
        "endpoints": ["https://<tenant>.api.<region>.exabeam.cloud"],
        "authenticated": True,
        "x-trust-boundary": True,
        "data": [
            {"flow": "inbound", "classification": "security-telemetry",
             "description": "alerts, cases, events, rules, license, collectors, parser health"},
            {"flow": "outbound", "classification": "analyst-action",
             "description": "case create/update, alert update, case notes — only when --allow-writes; "
                            "free text is neutralized before it persists"},
        ],
    }]

    properties = [
        {"name": "exa:mcp:tools", "value": str(ntools)},
        {"name": "exa:mcp:skills", "value": str(len(skills))},
        {"name": "exa:governance:default-read-only", "value": "true"},
        {"name": "exa:governance:write-gate", "value": "--allow-writes (4 write tools hidden+refused by default)"},
        {"name": "exa:governance:tenant-kind", "value": "demo/customer tags gate customer-tenant actions"},
        {"name": "exa:guardrail:input-canonicalization", "value": "on: strips smuggling code points + NFC on every result"},
        {"name": "exa:guardrail:output-neutralization", "value": "on: defang formulas/links + redact secrets on write inputs"},
        {"name": "exa:guardrail:redteam-evals", "value": "tests/redteam/ — A07/A10/A11/D01-D03 regression"},
        {"name": "exa:audit:log", "value": "metadata-only, default-on, fail-open, rotating jsonl (~/.exa/audit.jsonl)"},
        {"name": "exa:secrets", "value": "OS credential store (keyring) — never files; no secret reaches the model"},
    ]

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(_NS, root_ref)}",
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(),
            "component": {
                "bom-ref": root_ref,
                "type": "application",
                "name": name,
                "version": version,
                "description": "Exabeam New-Scale TAM/SOC toolkit: MCP server (30 tools) + Claude skills + branded reports.",
                "licenses": [{"license": {"id": "MIT"}}],
                "purl": root_ref,
            },
            "supplier": SUPPLIER,
            "properties": properties,
        },
        "components": components,
        "services": services,
        "dependencies": [
            {"ref": root_ref, "dependsOn": [c["bom-ref"] for c in components]},
        ],
    }
    return doc


def _render_html(doc: dict) -> str:
    md = doc["metadata"]
    root = md["component"]
    rows = "".join(
        f"<tr><td><code>{escape(c['name'])}</code></td><td>{escape(c['type'])}</td>"
        f"<td>{escape(c.get('version',''))}</td>"
        f"<td>{escape((c.get('licenses') or [{}])[0].get('license',{}).get('id',''))}</td></tr>"
        for c in doc["components"]
    )
    props = "".join(
        f"<tr><td><code>{escape(p['name'])}</code></td><td>{escape(p['value'])}</td></tr>"
        for p in md["properties"]
    )
    svc = "".join(
        f"<li><b>{escape(s['name'])}</b> — {escape(s['description'])}</li>" for s in doc["services"]
    )
    return f"""<!doctype html><meta charset="utf-8"><title>exa-tools AI-BOM</title>
<style>body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#111}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}td,th{{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;font-size:14px}}
th{{background:#f3f4f6}}code{{background:#f3f4f6;padding:1px 4px;border-radius:3px}}h1{{margin-bottom:0}}small{{color:#666}}</style>
<h1>{escape(root['name'])} <small>v{escape(root['version'])} · AI-BOM</small></h1>
<p><small>CycloneDX {doc['specVersion']} · {escape(md['timestamp'])} · {escape(doc['serialNumber'])}</small></p>
<p>{escape(root['description'])}</p>
<h2>Components ({len(doc['components'])})</h2>
<table><tr><th>Name</th><th>Type</th><th>Version</th><th>License</th></tr>{rows}</table>
<h2>Services</h2><ul>{svc}</ul>
<h2>Governance &amp; guardrails</h2>
<table><tr><th>Property</th><th>Value</th></tr>{props}</table>
"""


def main(argv: list[str]) -> int:
    doc = build_bom()
    if "--check" in argv:
        if not JSON_OUT.exists():
            print("aibom.cdx.json missing — run: uv run security/gen_aibom.py", file=sys.stderr)
            return 1
        on_disk = json.loads(JSON_OUT.read_text(encoding="utf-8"))
        a, b = dict(on_disk), dict(doc)
        a["metadata"] = {k: v for k, v in a.get("metadata", {}).items() if k != "timestamp"}
        b["metadata"] = {k: v for k, v in b["metadata"].items() if k != "timestamp"}
        if a != b:
            print("AI-BOM is stale vs sources — run: uv run security/gen_aibom.py", file=sys.stderr)
            return 1
        print("AI-BOM is fresh.")
        return 0
    SEC.mkdir(parents=True, exist_ok=True)
    JSON_OUT.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    HTML_OUT.write_text(_render_html(doc), encoding="utf-8")
    print(f"wrote {JSON_OUT.relative_to(ROOT)} and {HTML_OUT.relative_to(ROOT)} "
          f"({len(doc['components'])} components, {len(doc['services'])} services)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

"""Generate the API surface KB note from api-verification-results.json.

The output note is MECHANICAL: every line is derived from the audit artifact, so
nothing in it can be assumed or invented. Hand-sourced findings (changelog
deprecations, docs guidance) belong in the sibling note api-drift-log.md, never
here -- mixing them would make the generated note unsafe to regenerate.

Usage:
    uv run python scripts/gen_api_kb.py [OUT_PATH]

Default OUT_PATH is the Exa-tam vault on the personal machine. On the work
laptop, pass the ExaVault path explicitly.
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

_ARTIFACT = Path(__file__).parents[1] / "api-verification-results.json"
_DEFAULT_OUT = Path.home() / "Exa-tam" / "40-Reference" / "api-surface.md"


def _days_since(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        stamp = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return (datetime.now(UTC) - stamp).days


def build(artifact: dict) -> str:
    inv_meta = artifact.get("inventory_meta", {})
    audit_meta = artifact.get("full_audit_meta", {})
    audit = artifact.get("full_audit", [])
    gaps = artifact.get("spec_vs_reality_gaps", [])

    tested_at = audit_meta.get("tested_at")
    age = _days_since(tested_at)
    doc_refreshed = inv_meta.get("last_refreshed")

    proven = [r for r in audit if r.get("confirmed_status") is not None]
    unproven = [r for r in audit if r.get("confirmed_status") is None]
    mismatched = [r for r in proven if r.get("status_match") is False]

    lines: list[str] = []
    add = lines.append

    add("---")
    add("tags: [reference, generated]")
    add(f"generated: {datetime.now(UTC).date().isoformat()}")
    add("generator: exa-tools/scripts/gen_api_kb.py")
    add("---")
    add("")
    add("# API surface -- what is documented vs what is proven")
    add("")
    add("> **GENERATED FILE -- DO NOT HAND-EDIT.** Every line below is derived from")
    add("> `api-verification-results.json`. Regenerate instead of editing:")
    add("> `uv run python scripts/gen_api_kb.py`")
    add(">")
    add("> Hand-sourced findings (changelog deprecations, docs guidance) go in")
    add("> [[api-drift-log]]. Keeping them out of here is what makes this note safe")
    add("> to regenerate and safe to trust.")
    add("")
    add("**Docs are guidance. A live status code is proof. They are tracked separately")
    add("and must never be merged.**")
    add("")

    # ---- provenance -------------------------------------------------------
    add("## Provenance")
    add("")
    add("| | |")
    add("|---|---|")
    add(f"| Documented endpoints | **{inv_meta.get('total_endpoints', '?')}** "
        f"across {inv_meta.get('specs_count', '?')} specs |")
    add(f"| Docs source | `{inv_meta.get('mcp_server', '?')}` |")
    add(f"| Docs method | {inv_meta.get('refresh_source', '?')} |")
    add(f"| Docs last refreshed | **{doc_refreshed or '?'}** |")
    add(f"| Live probe run | **{str(tested_at)[:10] or '?'}**"
        f"{f' ({age} days ago)' if age is not None else ''} |")
    add(f"| Probed against | `{audit_meta.get('tenant', '?')}` -- ONE tenant, ONE region |")
    add(f"| Endpoints probed | **{audit_meta.get('tested', '?')} of "
        f"{audit_meta.get('total', '?')}** |")
    add(f"| Endpoints never probed | **{audit_meta.get('skipped', '?')}** |")
    add(f"| Status mismatches found | {len(mismatched)} |")
    add("")

    if age is not None and age > 30:
        add(f"> ⚠️ **The proof is {age} days old.** The documented inventory was refreshed")
        add(f"> {doc_refreshed}, later than the probe, so anything added or removed since")
        add(f"> {str(tested_at)[:10]} is UNPROVEN here regardless of what the table says.")
        add("> Re-run the audit before relying on this note for anything that writes.")
        add("")

    add("Reachability is **per region**. The audit recorded at least one endpoint")
    add("returning 404 in one region and 200 in another, so 'proven' below means")
    add("proven *on the probed tenant only*.")
    add("")
    add("Skip reasons:")
    add("")
    for reason, n in sorted(audit_meta.get("skip_breakdown", {}).items()):
        add(f"- `{reason}` -- {n}")
    add("")

    # ---- proven -----------------------------------------------------------
    add(f"## Proven reachable ({len(proven)})")
    add("")
    add(f"Live status codes observed on `{audit_meta.get('tenant', '?')}`, "
        f"{str(tested_at)[:10]}.")
    add("")
    add("| Method | Path | Live status | Matches spec |")
    add("|---|---|---|---|")
    for r in sorted(proven, key=lambda x: (x.get("path") or "", x.get("method") or "")):
        match = r.get("status_match")
        mark = "yes" if match else ("**NO**" if match is False else "-")
        add(f"| {r.get('method')} | `{r.get('path')}` | {r.get('confirmed_status')} | {mark} |")
    add("")

    # ---- unproven ---------------------------------------------------------
    add(f"## NOT proven -- never probed ({len(unproven)})")
    add("")
    add("These are documented and **assumed** to work. No live call has confirmed any")
    add("of them. Treat every row as unverified until the audit covers it.")
    add("")
    by_reason: dict[str, list[dict]] = defaultdict(list)
    for r in unproven:
        by_reason[str(r.get("skipped") or "not-run")].append(r)
    for reason in sorted(by_reason):
        rows = by_reason[reason]
        add(f"### skipped: `{reason}` ({len(rows)})")
        add("")
        for r in sorted(rows, key=lambda x: (x.get("path") or "", x.get("method") or "")):
            add(f"- `{r.get('method')} {r.get('path')}`")
        add("")

    # ---- gaps -------------------------------------------------------------
    add(f"## Spec vs reality ({len(gaps)})")
    add("")
    add("Where the documentation and the live API disagree. These are the entries")
    add("that make 'the docs say so' insufficient as evidence.")
    add("")
    for g in gaps:
        add(f"### `{g.get('endpoint')}`")
        add("")
        add(f"- **Spec documents:** {g.get('spec_documents')}")
        add(f"- **Observed live:** {g.get('observed_in_response')}")
        add(f"- **Gap:** {g.get('gap')}")
        add("")

    # ---- coverage by spec -------------------------------------------------
    add("## Coverage by spec")
    add("")
    counts: dict[str, Counter] = defaultdict(Counter)
    for r in audit:
        key = "proven" if r.get("confirmed_status") is not None else "unproven"
        counts[str(r.get("spec"))][key] += 1
    add("| Spec | Proven | Unproven |")
    add("|---|---|---|")
    for spec in sorted(counts):
        c = counts[spec]
        add(f"| {spec} | {c['proven']} | {c['unproven']} |")
    add("")

    add("---")
    add("")
    add("Related: [[api-drift-log]], [[regional-servers]], [[00-Index]]")
    return "\n".join(lines) + "\n"


def main() -> int:
    if not _ARTIFACT.exists():
        print(f"ERROR: artifact not found: {_ARTIFACT}", file=sys.stderr)
        return 1
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else _DEFAULT_OUT
    if not out.parent.exists():
        print(f"ERROR: output directory not found: {out.parent}", file=sys.stderr)
        return 1
    artifact = json.loads(_ARTIFACT.read_text(encoding="utf-8-sig"))
    out.write_text(build(artifact), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

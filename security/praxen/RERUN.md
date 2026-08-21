# Praxen ABV — re-run instructions

Copy the prompt below into a fresh Claude Code session at the repo root to re-run the
Agent Behavior Verification scan. It bakes in the lesson from the pass-3 stale-clone
incident: **pull first**, or a checkout behind `origin/main` will miss the
`## Accepted risks` section (added in `95cc25a`) and falsely report the accepted risks
as "not declared."

Policy baseline: [`WORKER_REMIT.md`](./WORKER_REMIT.md) · Results: [`results/`](./results/)

---

## Prompt

```
Re-run the Praxen ABV scan on this repository against security/praxen/WORKER_REMIT.md.

FIRST: git pull, then git rev-parse --short HEAD and confirm you're at origin/main.
If HEAD is behind origin/main, pull before scanning — a stale checkout will miss the
`## Accepted risks` section (added in 95cc25a) and falsely report the accepted risks
as "not declared." Do NOT scan a detached/behind HEAD.

Then run a fresh pass — do not diff against prior conclusions, re-derive them:

1. Confirm the closed HIGH and gaps stay closed, BY EXECUTION not inference:
   - PRAX-001 path containment (_contained_output_path): genuine escapes refused,
     contained paths land under the reports root.
   - R-12 error-path canonicalization (canonicalize): zero-width / RTL / plane-14 tag
     stripped, U+2028 -> newline, zero residuals. Note canonicalize() returns (text, hygiene).
   - ABV-004: formula in tags[] defanged via neutralize_write_args.

2. Adjudicate the three declared accepted-risks against the remit's `## Accepted risks`
   section — each must be BOTH declared in the remit AND code-consistent:
   - audit enums: _SAFE_ACTION_FIELDS carries only ids + priority/stage; free-text excluded.
   - dev-only SSE: server.py defaults to loopback + UNAUTHENTICATED warning, louder on
     non-loopback; scoped as operator-responsibility (it must NOT claim to refuse the bind).
   - render_abv snapshot: report/abv.py self-labels as a point-in-time manual snapshot
     deferring to the live scan.
   Any acceptance that is declared but NOT code-consistent is a divergence — flag it.

3. Flag anything genuinely new — scan code that changed since the last results file
   (git log <last-scanned-HEAD>..HEAD) against the Forbidden-tools / Forbidden-network /
   Data-handling rules. No subprocess/eval/network; no secret in CLI output.

Write the findings to security/praxen/results/ dated today. Run a publication sweep
(no tenant names, paths, or credentials) before finishing. If nothing changed since the
last results file, say so plainly instead of re-emitting an identical findings set.
```

---

## Quick empirical re-verify (optional, run from repo root)

The controls above can be driven directly without the full agent pass:

```bash
uv run python - <<'PY'
from pathlib import Path
from exa.mcp.tools import _contained_output_path, _reports_root
from exa.mcp.guardrails.canonicalize import canonicalize
from exa.mcp.guardrails import neutralize_write_args
from exa.mcp.audit import _SAFE_ACTION_FIELDS

base = _reports_root().resolve()
# containment
esc = [r"../../evil.html", r"/etc/passwd", r"C:\Windows\x.html", r"\\server\share\e.html",
       r"..\..\evil.html", r"reports/../../evil.html"]
ref = 0
for p in esc:
    try: _contained_output_path(p)
    except Exception: ref += 1
print(f"containment: {ref}/{len(esc)} escapes refused (expect all)")
# canonicalization
for name, v in {"ZWSP":"a\u200bb","RTL":"a\u202eb","TAG":"a\U000e0041b","LS":"a\u2028b"}.items():
    out, hy = canonicalize(v)
    print(f"canon {name}: {out!r} stripped={hy.counts['stripped']}")
# tags[] neutralization
neu, notes = neutralize_write_args({"tags":['=HYPERLINK("https://evil.example")',"ok"]})
print(f"tags neutralized: {neu['tags']} notes={len(notes)}")
# audit allowlist
print(f"audit fields: {_SAFE_ACTION_FIELDS}")
PY

uv run pytest tests/test_redteam_guardrails.py tests/test_mcp.py -q
```

Expected: all escapes refused, every canon probe `stripped=1` with no residual, the tag
formula defanged to `'=HYPERLINK("hxxps://evil[.]example")`, audit fields limited to
ids + `priority`/`stage`, and the two test files green.

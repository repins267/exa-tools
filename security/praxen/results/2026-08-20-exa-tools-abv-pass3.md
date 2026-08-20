# Praxen ABV — pass 3 (adjudicated), 2026-08-20

**Result: clean.** No HIGH, no gaps, all three declared accepted-risks adjudicate as
policy against the current remit, and the one genuinely-new code surface introduces
nothing. Every closed control was re-confirmed **by execution**, not by inference.

| | |
|---|---|
| Scan timestamp | 2026-08-20 |
| Workspace | `E:\Python\exa-tools` |
| HEAD scanned | `0171733` (`017173371ec71c06a4c59968add35616a0b023c3`), origin/main |
| Remit baseline | `security/praxen/WORKER_REMIT.md` @ `0171733` (incl. `## Accepted risks`, added in `95cc25a`) |
| Findings emitted | 0 new · 0 HIGH · 0 gap |

---

## 0. Correction to the prior pass-3 attempt (the stale-clone artifact)

An earlier pass-3 run on the **work laptop** (`C:\Github\exa-tools`, HEAD `d763e9c`)
concluded the three accepted risks were "not adjudicable as policy — the remit is
silent." **That conclusion was an artifact of a stale checkout, not a real gap.**

`d763e9c` is an *ancestor* of the current baseline, 6 commits behind. The acceptance
language it could not find was added **after** it:

```
d763e9c  identity_health paged reads          ← laptop HEAD (STALE, pass-2 baseline)
f5b2333  Praxen pass-2 remediations
10f6cf8  close 3 residuals + config_path guard
95cc25a  finishing move + DECLARE ACCEPTED RISKS   ← the section the laptop missed
ee6fe00  pin mcp
214afa7  exa mcp overhaul                      ← new surface, never scanned before
0171733  README client table                   ← current origin/main
```

Everything the laptop pass flagged as "open" was fixed in `f5b2333` / `10f6cf8` /
`95cc25a`, all of which are on `origin/main`. **Fix for the laptop: `git pull`.** Its
*empirical* re-verification of the closed HIGH/gap still stands (that code is unchanged
between `d763e9c` and `0171733`); only its acceptance adjudication was against the wrong
remit. This pass re-runs the whole thing against the baseline that actually has the
acceptances.

---

## 1. Closed controls — re-confirmed by execution at `0171733`

Drove the controls directly rather than trusting the hash.

**PRAX-2026-08-19-001 / HIGH — arbitrary file write (path containment).** `_contained_output_path`
resolves any caller `output_path` under the reports root and rejects on `is_relative_to`.
- 6/6 genuine escapes refused: `../../evil.html`, `/etc/passwd`, `C:\Windows\x.html`,
  `\\server\share\e.html`, `..\..\evil.html`, `reports/../../evil.html`.
- Contained paths accepted and verified *inside* the root: `ok.html`, `sub/ok.html`,
  `reports/../secret.html` (→ `<root>/secret.html`), `~/e.html` (literal `~` subdir; no
  `expanduser`). **Not escapes** — both land under the root. **CLOSED.**

**R-12 / gap — error-path canonicalization.** `canonicalize()` on hostile input:
- U+200B (zero-width) → stripped, U+202E (RTL override) → stripped, U+E0041 (plane-14 tag)
  → stripped, U+2028 (line sep) → newline. Zero residuals in every case. **CLOSED.**

**ABV-004 — `tags[]` list neutralization.** `neutralize_write_args({"tags":[…]})` defanged
`=HYPERLINK("https://evil.example")` → `'=HYPERLINK("hxxps://evil[.]example")` (leading
quote, `hxxps`, `[.]`), 1 note fired. String **and** list write fields covered. **CLOSED.**

Corroboration: `pytest tests/test_redteam_guardrails.py tests/test_mcp.py` → **78 passed**.

---

## 2. Declared accepted-risks — adjudicated as policy (remit § "Accepted risks")

Each is declared in the remit *and* the code matches the declaration — so each adjudicates
as accepted policy, not a divergence. Critically, each acceptance is **scoped to what the
code does**, so it stays violable (a future change that broke the claim would re-raise it).

| # | Accepted risk | Remit claim | Code at `0171733` | Verdict |
|---|---|---|---|---|
| 1 | Audit records `priority`/`stage` | bounded enums, free-text excluded | `_SAFE_ACTION_FIELDS = (alert_id, case_id, priority, stage, kind, tenant)`; `queue`/`vendor`/`note`/`content` absent | **ACCEPTED — consistent** |
| 2 | SSE/HTTP unauthenticated by design | default loopback bind + prominent UNAUTHENTICATED warning, *louder* on non-loopback; hardening is operator's job | `server.py`: default `host=127.0.0.1`; `WARNING: … UNAUTHENTICATED` always; `DANGER: binding to {host} …` when host ∉ {127.0.0.1, ::1, localhost} | **ACCEPTED — consistent** |
| 3 | `render_abv` is a manual snapshot | labels itself a point-in-time snapshot; live Praxen scan is authoritative | `report/abv.py`: "point-in-time, not a live claim" (l.121), "this render does not assert a live commit" (l.129), "the independent scan is the fuller check" (l.144), "Praxen ABV (manual snapshot)" (l.155) | **ACCEPTED — consistent** |

Note on #2: the acceptance does **not** claim SSE refuses a non-loopback bind — it claims
default-loopback + warn + operator-responsibility, which is exactly what the code does. It
is correctly *bounded*, so it silences the finding without deleting the check. Binding to
`0.0.0.0` is still the operator's explicit, warned choice — not a scan pass smuggled in by
an over-broad acceptance.

---

## 3. Genuinely new — the `exa mcp` overhaul (`214afa7`), never scanned before

The laptop's baseline predates this commit, so it is the only new attack surface. Scanned
against the remit's Forbidden-tools / Forbidden-network / Data-handling rules:

- **Forbidden tools:** no `subprocess` / `os.system` / `popen` / `eval(` / `exec(` in the
  diff. Clean.
- **Forbidden network:** no `socket` / `urlopen` / `requests` / `httpx`. `_DOCS_MCP_URL` is
  a string written into a client config; `npx mcp-remote` (docs mode) is spawned by the
  *client*, not by `exa`. Clean.
- **New surface:** read-only `os.environ` (`LOCALAPPDATA`/`APPDATA`) + `glob` to detect a
  Microsoft-Store install. Filesystem/env **reads** only.
- **Data handling:** `--print` emits the config block (command + args incl. the tenant
  *nickname* — non-secret) and filesystem paths; no credential is surfaced. `install`
  writes only `claude_desktop_config.json` to the Claude config dir (intended, unchanged).

**No new finding.**

---

## 4. Bottom line

- HIGH: **closed** (re-verified by execution).
- Gaps: **none** (error-path canonicalization re-verified).
- Accepted risks (audit enums, dev-only SSE, `render_abv` snapshot): **all three adjudicate
  as accepted policy** against the current remit — declared *and* code-consistent.
- New `exa mcp` surface: **clean**.
- Action for the work laptop: **`git pull`** to `0171733`; its "not adjudicable" verdict
  was a stale-checkout artifact and does not reflect the shipped baseline.

Publication note: this file names no tenant, path secret, or credential.

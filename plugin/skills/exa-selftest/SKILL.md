---
name: exa-selftest
description: >-
  Live preflight the Exabeam MCP tool surface against a tenant BEFORE a demo or
  when onboarding a new user. Use when asked to "self test", "preflight", "test
  the tools", "check nothing times out", "is the MCP healthy", "warm up before
  the demo", or when a scheduled task should confirm every tool still works.
  Runs every read tool, times each against a Claude-Desktop latency budget,
  classifies ok/slow/timeout/error, and writes a findings JSON. Read-only.
  Run this for every new skill or MCP tool that goes live. Requires the exa-tools
  MCP server (Code-first — it shells the `exa selftest` CLI).
---

# MCP self-test / demo preflight — Exabeam New-Scale

You are making sure the exa-tools MCP surface will not embarrass anyone in a live
demo or in front of a new user. A tool that takes 40 seconds looks *hung* in Claude
Desktop even when it eventually returns — that is a failure. Your job is to catch
slow/timeout/error tools now, on your own time, not live.

This skill is **Code-first**: it runs the `exa selftest` CLI (which drives the same
`dispatch_tool` path Claude Desktop uses), not the MCP tools one by one.

## When to run it

- **Before every demo** — especially on the tenant you will present (e.g. `sademodev22`).
- **After adding any new skill or MCP tool** — part of the tool-creation process.
- **On a schedule** (Claude Scheduled Task / cron) — a dated findings JSON per run.
- **When a new user reports a hang or timeout** — reproduce it here first.

## How to run it

Warm first, then test — the AI/LLM tools need today's tenant field-profile, which the
MCP server now warms automatically on start, but the CLI selftest should warm it too:

```bash
uv run exa auth --tenant sademodev22          # confirm creds first
uv run exa aillm rules --tenant sademodev22   # warm today's AI/LLM profile (no timeout on CLI)
uv run exa selftest --tenant sademodev22       # the preflight; writes reports/selftest/<tenant>-<date>.json
```

Subset / tuning:

```bash
uv run exa selftest -t sademodev22 --only aillm_validate,aillm_gaps,tuning_report
uv run exa selftest -t sademodev22 --slow-seconds 20 --timeout-seconds 50
uv run exa selftest -t sademodev22 -o preflight.json
```

## How to read the result

The command prints a line per tool and a final verdict, and writes the same to JSON:

- **ok** — completed under the slow threshold. Fine.
- **slow** — completed, but slow enough to look stuck in Desktop. A **demo risk**:
  warm it, narrow the lookback, or avoid it live. Investigate before presenting.
- **timeout** — exceeded the hard ceiling; Desktop would hang or fail. **Must fix**
  before the tool goes in front of anyone.
- **error** — returned an error result or raised. **Must fix.**

`verdict` is **FAIL** if any tool timed out or errored (CLI exits non-zero, so a
scheduled task can alert on it), otherwise **PASS**.

## What to do with findings

1. Report the verdict and name every non-`ok` tool with its seconds and note.
2. For a **slow** AI/LLM tool: the usual cause is a cold tenant field-profile. Confirm
   the MCP server's background warm-up ran, or warm it from the CLI
   (`exa aillm rules --tenant <t>`); the date-stamped cache goes cold every day.
3. For a **timeout/error**: read the note, reproduce with `--only <tool>`, and fix the
   tool — do not ship it live until selftest is green.
4. Keep the dated findings JSON — it is the evidence that the surface was tested before
   the demo. On a schedule, diff against the previous day to catch regressions.

Do not invoke the four write tools here — selftest is read-only by construction, and so
are you when running it.

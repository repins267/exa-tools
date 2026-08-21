# Install guide — exa-tools plugin

Tested path for a Windows work laptop with the repo at `C:\Github\exa-tools`.

Every step has a **check**. If a check fails, stop there — the later steps assume it
passed, and a failure carried forward is much harder to read.

---

## 0. Before anything — one safety item

`exa_mcp_desktop.py` has been sitting in the repo root. That repo is public and the
script mints bearer tokens. Move it out before adding more Desktop wiring:

```powershell
Test-Path C:\Github\exa-tools\exa_mcp_desktop.py
```

If `True`, move it somewhere outside the checkout — your user profile is fine. Do not
gitignore it in place: that makes the drift permanent instead of visible.

---

## 1. Prerequisites

```powershell
uv --version          # required
claude --version      # optional -- only for the Claude Code half
where exa             # may be empty; step 3 can fix it
```

**Check:** `uv` prints a version. Nothing else is mandatory yet.

---

## 2. Get the code

```powershell
cd C:\Github\exa-tools
git fetch
git checkout feat/aillm-analysis
git pull
```

**Check:**

```powershell
Test-Path .\plugin\install.ps1        # True
Test-Path .\.claude-plugin\marketplace.json   # True
```

---

## 3. Credentials

Secrets live in Windows Credential Manager. Nothing written by this install contains
one.

```powershell
uv run exa configure          # first time only
uv run exa auth --tenant sademodev22
```

**Check:** `Authentication successful` and an API server line. If this fails, fix it
here — the installer will refuse to continue anyway, deliberately.

---

## 4. Run the installer

```powershell
cd C:\Github\exa-tools\plugin
.\install.ps1 -Tenant sademodev22 -InstallExaOnPath
```

`-InstallExaOnPath` puts `exa` on PATH via `uv tool install`. The plugin's MCP server
invokes bare `exa`; without it the skill loads and has **no tools**, which looks like a
broken skill rather than a missing prerequisite. Omit the flag if `where exa` already
resolved in step 1.

**Check — every line should read OK, none FAIL:**

```
OK   uv present
OK   exa runs (exa-tools 0.1.0)
OK   authenticated
OK   Claude Desktop config written
OK   servers now configured: exabeam, ...
OK   exa on PATH (...)
OK   plugin available to Claude Code
```

A `WARN` about the claude CLI being absent is fine — it means only the Claude Code half
was skipped, and Desktop is still configured.

Useful flags: `-SkipDesktop`, `-SkipClaudeCode`, `-SkipAuthCheck`, `-Docs`.

---

## 5. Verify Claude Code

The plugin loads in a **new** session.

```powershell
claude plugin details exa-tools
```

**Check:** `Skills (1) exa-health-check` and `MCP servers (1) exabeam`. If skills show
but MCP servers is 0, `exa` is not resolving — go back to step 4 with
`-InstallExaOnPath`.

Then, in a new Claude Code session:

> run a health check on sademodev22

**Check:** it calls tools rather than describing what it would do.

---

## 6. Verify Claude Desktop

Quit Claude Desktop **completely** — from the tray, not just closing the window — then
reopen.

1. **Settings → Developer → Local MCP servers** — `exabeam` should be listed. It said
   "No servers added" before.
2. **Settings → Customize → Skills** — add the skill from
   `C:\Github\exa-tools\plugin\skills\`. Desktop manages skills in-app; there is no
   folder to drop them into.

**Check — verify by NAMING a tool, never by asking a question.** Both the live tenant
server and the API docs server answer Exabeam questions plausibly, so a good-sounding
answer proves nothing. Ask it to run `aillm_sources` against sademodev22. Tool names in
the reply are the only reliable signal.

---

## Troubleshooting

**Skill loads, no tools.** `exa` is not on PATH. `where exa` should print a path;
otherwise re-run step 4 with `-InstallExaOnPath`.

**Desktop shows the server but calls fail.** Check the config has no space inside any
single `args` value — a documented `mcp-remote` bug on Windows. `exa mcp install`
avoids it by passing an absolute exe path. Do **not** wrap the entry in `cmd /c`;
Desktop already launches stdio servers through cmd.exe, so seeing cmd.exe in the log is
normal, not a symptom.

**Desktop logs "started and connected successfully" then nothing works.** Desktop logs
that on *spawn*, roughly 100 ms before a crash — an early exit reads as a transport
failure.

**Answers look right but may be from the docs server.** `list-specs` / `search-endpoints`
in the reply means the docs server; `aillm_*` / `search_events` means the live tenant.

**A second run warns instead of confirming.** It should not — "already installed" is
treated as success. If you see a warning on a repeat run, that is a bug worth reporting.

---

## Uninstall

```powershell
claude plugin uninstall exa-tools@exa-tools
claude plugin marketplace remove exa-tools
```

Then remove the `exabeam` entry from `%APPDATA%\Claude\claude_desktop_config.json` and
restart Desktop.

---

## What this does NOT do

- It does not write any credential to any config file.
- It does not enable write access to a customer tenant. The four write tools
  (`create_case`, `update_case`, `update_alert`, `add_case_note`) instruct the model to
  ask first — but in Claude Desktop that instruction is the **only** gate, because the
  harness-enforced permission rule is a Claude Code feature. Treat customer tenants as
  read-only here.
- It does not reference the vault, a network share, or any home-server path.

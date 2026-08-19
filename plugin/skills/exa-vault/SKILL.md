---
name: exa-vault
description: >-
  Use the ExaVault (the Obsidian TAM knowledge vault) as trusted, durable context.
  Use when asked to "check the vault", "what do we know about <account>", "look up
  the defect", "prep using the vault", "capture this finding", or "update the vault".
  Reads/searches/edits the vault's markdown notes directly (Claude Code, native file
  tools) and pairs them with live Exabeam data from the exa-tools MCP. Read before you
  write; verify old notes against the live tenant.
---

# ExaVault — the TAM knowledge vault

The ExaVault is the durable memory for TAM work: account context, the defect
register, TAM/tuning methods, and reference field data. **The exa-tools MCP tells you
what is TRUE on a tenant right now; the vault tells you what we KNOW and how we WORK.**
Use both — the vault for context, the MCP for live state.

## Where it lives (Claude Code, local)

Default path on the work laptop: `C:\Users\cyrus.field\ExaVault`. Use your native
file tools (Grep / Glob / Read / Edit) directly against it — no MCP needed on Code.
If the path differs, ask once, or read it from `00-Index.md`.

> On **Claude Desktop** (no native file access) use the Obsidian / ares MCP instead
> (`read_note` / `search_notes` / `append_to_note`). The method below is identical;
> only the tool changes. Note the MCP is append-only, so on Desktop you can add a
> dated section but cannot restructure a note.

## The map (orient here first)

Read `00-Index.md` first — it lists customers, runbooks, reference notes, and the
defect register. Then:

| Folder | Holds |
| --- | --- |
| `00-Index.md` | the map + the tier model |
| `10-Customers/<account>.md` | per-account context, findings, engagement notes |
| `20-Defects/EXA-*.md` | the defect register (verified Exabeam API/behavior bugs) |
| `30-Runbooks/` | methods: `TAM-Report-Method`, `mcp-desktop`, update, etc. |
| `40-Reference/` | verified field data: CIM2 fields, activity types, regional servers |
| `50-Skills/` | skill sources (when present) |
| `Personal/`, `wiki/` | **off-limits for TAM work** (personal notes, session handoffs) |

## Reading — find the right note, then trust-but-verify

1. **Find by intent** — `Grep` the vault for the term (account, `EXA-` id, field name);
   `Read` the note by path; follow `[[wikilinks]]` to related notes.
2. **Cite it** — name the note you used ("per `10-Customers/lvcva.md`").
3. **Check freshness** — read the frontmatter / dated sections. A note is what was true
   when written, not necessarily now.
4. **Verify against live** — before repeating a factual claim (a defect reproduces, a
   table is dead, a tenant is over), confirm it with the exa-tools MCP. Vault +
   contradicting live data → trust the live data and note the drift.

## Writing — surgical, sync-safe, never clobber

The vault is **shared and Obsidian-Synced** (phone + other devices edit it too), so:

- **Make small, targeted edits.** Add a dated finding under the right note; do not
  rewrite a note wholesale. Prefer appending a `## Added <date>` section to editing the
  body, so a concurrent Sync change can't be lost.
- **Never edit teammate-authored content.** Some notes flag it explicitly (e.g., a rule
  authored by another analyst) — report, never modify.
- **Right note, right tier** — an account finding → `10-Customers/<account>.md`; a new
  verified bug → a `20-Defects/EXA-*.md` note; a method refinement → the runbook.
- **Keep the conventions** — frontmatter `tags:`, `[[wikilinks]]` to related notes, and
  the note's existing section structure. Convert relative dates to absolute.
- **Don't duplicate the repo.** Code structure, git history, and CLAUDE.md already exist;
  the vault holds what those don't (context, decisions, verified defects).

## How it pairs with exa-tools (the point)

- **Call prep / TAM report** — read the `10-Customers/<account>.md` note for context and
  `30-Runbooks/TAM-Report-Method.md` for the method, then pull live numbers via the MCP
  (`ingest_value`, `parser_health`, `aillm_*`) and render with `render_report`.
- **Investigation** — a case's domains/IPs checked against `20-Defects/` known issues and
  live data; new findings captured back for next time.
- **After the work, capture** — append the durable finding to the vault so the next
  session starts where this one finished.

The vault is the account/defect/method memory you lean on so you never re-explain context.
Read it, ground your answer in it, verify it, and leave it a little richer than you found it.

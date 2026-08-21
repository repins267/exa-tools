---
name: exa-dashboard-preview
description: >-
  Preview and edit an Exabeam dashboard .config before importing it. Use when
  asked to "preview the dashboard", "render the dashboard config", "show me the
  dashboard before I import", "edit the AI/LLM Landscape dashboard", or "change a
  panel and re-preview". Exabeam dashboards import only through the UI, so this is
  the review/iterate loop: render the config, make changes, re-render, then export
  the final .config for a manual import. Requires the exa-tools MCP server.
---

# Dashboard config preview & edit

Exabeam dashboards **import only through the UI** (Dashboards → Import) — there is
no API import. `exa aillm dashboard` and hand-built dashboards produce a `.config`
JSON of panels. Your job is the loop that closes that gap: **render the config so
the analyst can see it, take edits, apply them to the JSON, re-render, and save the
final `.config` for the manual import.**

## The loop

1. **Load the config.** Read the `.config` file the analyst points at (it is JSON).
   If they ask you to build one from scratch or from `exa aillm dashboard` output,
   start from that JSON.
2. **Preview it.** Call `render_dashboard` with `config` (the JSON object) or
   `config_path` (the file). It saves a branded HTML preview showing every panel's
   title, visualization, fields, filter and row limit, grouped by section. Present
   the saved path so they can open it.
3. **Take edits and apply them to the JSON**, not to the HTML. Common edits:
   - **Add a panel** — append a `dashboardElements` entry: `type: "vis"`, a `title`,
     `fields` (e.g. `["event.web_domain", "event.count"]`), a `filter_expression`,
     `vis_config.type` (table/bar/…), and a `limit`. Copy the shape of an existing
     panel in the same config rather than inventing fields.
   - **Remove / reorder** — drop or move entries in `dashboardElements`.
   - **Retitle / re-scope** — edit `title`, `fields`, `filter_expression`, `limit`.
   - **Section headers** are `type: "text"` panels; edit their text to re-group.
4. **Re-render** after each change so the analyst sees the effect.
5. **Save the final `.config`** (valid JSON, same schema) and tell them to import it
   in the Exabeam UI: **Dashboards → Import**.

## Rules

- **Edit the JSON, preview the HTML.** The HTML is a view; the `.config` is the
  artifact that gets imported. Never hand the analyst HTML to import.
- **Keep the schema intact.** `dashboardElements`, per-panel `type`/`title`/`fields`/
  `filter_expression`/`vis_config`/`limit`. Preserve keys you don't understand.
- **Use fields that exist.** Prefer fields already present in the config or the
  tenant's data (check with `search_events` on a sample). A panel on a field the
  tenant never emits renders empty — say so rather than adding dead panels.
- **Every panel filters through a context table.** An AI/LLM panel only lights up
  once its table (e.g. `AI/LLM Proxy Categories`, `AI/LLM DLP Rulesets`) is
  populated — note this when previewing an un-synced tenant (see exa-aillm-sync).
- Read-only against the tenant. Saving a `.config` file locally is fine; importing
  it is a human step in the UI.

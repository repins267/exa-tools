# Architecture

How the SPL → Sigma → EQL conversion pipeline and the Field Oracle work, in detail — the internals that [detection.md](detection.md) and [compliance.md](compliance.md) build on.

[← README](../README.md)

---

This page is the deep reference. If you just want the commands, start at [detection.md](detection.md) (rule conversion) or [compliance.md](compliance.md) (auditing); come here when you need to know *why* a field was rated `schema`, *why* a `stats` clause turned into a warning, or *how* a compliance query adapts itself to one tenant's log sources.

## The SPL → Sigma → EQL pipeline

Splunk SPL and Exabeam EQL are fundamentally different query languages. SPL is a pipe-based
search-and-transform language (`search | stats | eval | lookup …`); EQL is SQL-style, filter-only
(`SELECT / WHERE / GROUP-BY / ORDER-BY`, no pipes). A direct SPL→EQL translator would have to
re-implement Splunk's field vocabulary and modifier semantics from scratch, and would lose
information silently wherever the two languages don't line up.

Instead, exa-tools routes through [Sigma](https://github.com/SigmaHQ/sigma) as a structured
intermediate representation:

```
Splunk SPL search
    ↓  exa/splunk/parser.py      — split head + pipeline; extract index, field conditions,
    ↓                              regex conditions, and a pipeline-stage inventory
    ↓  exa/splunk/to_sigma.py    — build a Sigma rule dict: logsource + detection block
    ↓  exa/sigma/converter.py    — map Sigma fields → CIM2, resolve confidence, build EQL
    ↓
Exabeam EQL correlation rule  →  deploy via API (disabled, "Needs review")
```

`exa/splunk/converter.py` orchestrates the whole chain; `exa sigma convert` enters at the third
stage directly, because a SigmaHQ community rule is *already* the intermediate form.

### Why route through Sigma

Going through Sigma buys four things that a hand-rolled SPL→EQL path would have to reinvent:

- **A community-maintained field vocabulary.** The Sigma project already normalizes vendor field
  names (`Image`, `CommandLine`, `TargetFilename`, `c-uri`, …). exa-tools maps *from* those
  canonical names into Exabeam CIM2, so it inherits thousands of person-hours of field curation
  instead of maintaining its own SPL dictionary.
- **Proper wildcard modifiers.** SPL wildcard values (`*mimikatz*`, `UBR*.py`) become Sigma
  modifiers — `|contains`, `|startswith`, `|endswith` — which the Sigma converter then renders as
  the correct EQL wildcard match (`WLDi("*mimikatz*")`) rather than a brittle literal.
- **Real negations.** SPL `NOT`/`!=` terms become Sigma `filter` blocks and convert to EQL `NOT`
  expressions, instead of being dropped.
- **An explicit inventory of what can't be expressed.** SPL has transforming commands with no EQL
  equivalent. Sigma is a pure detection format, so anything that isn't a field match has nowhere
  to go — and that forces the converter to *account* for it (as a warning) rather than lose it.

### What each stage does

**1 · `parser.py` — parse the SPL.** Splits the search into its head (the base `search` terms)
and its pipeline stages. It pulls out index, field conditions, and regex conditions, and builds a
`pipeline_stages` inventory. Stages with no EQL equivalent are recorded in `dropped_stages` so the
later stages can warn on them. It also collects `lookup`/`inputlookup` table names for
context-table mapping, and strips fields that are always invalid in EQL (`_raw`,
`distinguishedName`, and dotted/curly nested paths).

**2 · `to_sigma.py` — build the Sigma IR.** Translates the parsed SPL into a valid Sigma rule
dict: the `(index, sourcetype)` pair maps to a Sigma `logsource`, and the field/regex conditions
become a Sigma `detection` block. SPL field names are normalized to Sigma-canonical names via
`SPL_TO_SIGMA_FIELD`; anything not in that map passes through unchanged and will draw an
`EXA-UNVERIFIED` warning downstream. The intermediate Sigma YAML is preserved in the output for
audit and review.

**3 · `converter.py` — Sigma → EQL.** Maps each Sigma field to a CIM2 field through the Field
Oracle (see below), derives the `activity_type` from the Sigma logsource
(`process_creation → process-create`, `cloudtrail → app-activity`, …), and assembles the EQL
filter string. Wildcards become `WLDi(...)`, regex modifiers become `RGXi(...)`, `|all` becomes
AND-of-values instead of OR, and the Sigma `condition` expression (`selection and not filter`,
`1 of selection_*`, …) is expanded into the final boolean EQL.

### What can't be expressed in EQL — and becomes a warning

EQL is filter-only, so any SPL command that *transforms* or *aggregates* events has no
representation. The parser flags these stages and the converter turns each into a warning rather
than dropping it silently. The unsupported stages are:

`stats`, `eventstats`, `eval`, `rex`, `spath`, `lookup`, `inputlookup`, `convert`, `fillnull`,
`dedup`, `table`, `sort`, `rename`, `strcat`, `ldapsearch`, `where`, `makemv`.

Each is reported with a human-readable label, e.g.:

| SPL stage | Warning label |
|---|---|
| `stats` | `Dropped: per-user aggregation (stats)` |
| `eventstats` | `Dropped: population-level stats (eventstats)` |
| `eval` | `Dropped: computed fields (eval)` |
| `lookup` / `inputlookup` | `Dropped: enrichment join (lookup)` — plus a context-table candidate |
| `where` | `Dropped: post-pipeline filter (where)` |

Two special cases are handled rather than merely dropped:

- **`lookup` references** are matched against a known-lookup map and become **context-table
  candidates**. A recognized lookup maps to its Exabeam context table; an unknown one produces
  `Unknown lookup '<name>' — create context table` so the analyst knows what to build.
- **Unsupported Sigma modifiers** (`base64`, `base64offset`, `cidr`, `wide`, `utf16*`, `windash`,
  `expand`) can't be faithfully rendered in EQL. The converter warns
  (`Unsupported modifier '…' — EQL may be incomplete`) and falls back to an exact match rather
  than emitting a query that looks right but matches nothing.

Because SPL→EQL is lossy by design, every converted rule lands **disabled** and marked
**`Needs review`** — SPL→EQL always requires human sign-off before enabling. Deploy-readiness is
graded from the warnings: an empty query is `No`, more than two warnings is `No`, any
`passthrough` field is `Needs review`, and a clean conversion is `Yes`.

### The 1024-character EQL limit and RGXi compression

Exabeam's correlation-rule API enforces a **1024-character EQL limit**. SPL searches with large
wildcard value lists (e.g. 40 `file-name=UBR*.py` terms) routinely blow past it. Rather than
silently marking these `EQL too long`, the converter compresses:

- **Wildcard lists** (`file-name=Foo*`, `file-path=*bar*`) collapse into a single
  `RGXi("a|b|c")` alternation per field, preserving each modifier (`startswith → ^prefix`,
  `endswith → suffix$`, `contains → inner`, middle-glob → `^foo.*bar$`).
- **Exact-value lists** (no wildcards) are recorded as context-table candidates in a
  `<output>.tables.json` sidecar for future deployment.

If compression brings the EQL under 1024 chars the rule is promoted to `Needs review` with a note
like `Compressed field 'file_name' wildcard list → RGXi to fit API limit`. Pathological cases
(hundreds of values) that still overflow after compression remain `EQL too long`.

## The Field Oracle

The Field Oracle is the translation engine at the heart of the converter. Rather than relying on
a hand-maintained field map or on incomplete documentation, it reads a tenant's **own live parser
export** and derives the mapping directly from it. Because the export is what the tenant actually
runs, the mapping matches the fields that tenant really parses — no drift against a shared upstream
repo that goes stale.

### How `exa oracle build` builds it

The Oracle is built from a **`Parser_Update.zip`** downloaded from the tenant — a live export of
the parsers that tenant runs, carrying `parsers.conf` (the parser definitions) and
`event_builder.conf` (activity-type/event construction) alongside each other. You point a tenant
at its export once, and `exa oracle build` (`exa/oracle/…`) parses it:

1. **Read the parsers.** It walks `parsers.conf` — roughly **7,900–8,000 parsers** across the
   vendors that tenant ingests (Code42, Digital Guardian, Microsoft O365, Cisco, and many more) —
   extracting for each the parser name, vendor, product, and an `activity_type`, plus:
   - **CIM2 output fields** — every field the parser emits.
   - **Raw → CIM2 mappings** — regex-derived from the parser's field definitions, indexed both by
     the full raw path and by its leaf segment. `event_builder.conf` is read alongside to resolve
     how events are assembled.
2. **Derive the activity type the same way as before**, so the resulting Oracle is a **drop-in**:
   the schema and the index shapes are unchanged, only the *source* of the definitions moved from a
   shared repo to the tenant's own export.
3. **Build the index and write it.** The results are folded into three lookup structures and
   written to `~/.exa/cache/field_oracle-<tenant>.json` with a `built_at` timestamp and build stats:

| Index | Shape | Purpose |
|---|---|---|
| `by_activity_type` | `{activity_type → {cim2_field → [vendor/product, …]}}` | Confirm a field is real for a given activity type |
| `by_vendor` | `{vendor → {activity_type → [cim2_field, …]}}` | Per-vendor field sets |
| `raw_to_cim2` | `{raw_path_or_leaf → cim2_field}` | Direct raw-field → CIM2 translation |

> **The `raw_to_cim2` nuance.** Because the mappings are regex-derived from the export rather than
> read from explicit pC-style declarations, `raw_to_cim2` is **reliable for JSON parsers** and
> **best-effort for CEF**. The other indexes (`by_activity_type`, `by_vendor`) and the confidence
> model below are unaffected.

**The bundled base pack.** exa-tools ships a bundled base pack — the demo set, derived field
metadata only — so conversion and compliance work **out of the box with no setup**. You don't need
a tenant export in hand to get started; you build a tenant-specific Oracle when you want that
tenant's exact field coverage.

**Resolution order.** A consumer (the converter or the compliance resolver) picks the Oracle to use
in this order:

1. **Tenant-specific Oracle** — `field_oracle-<tenant>.json`, if one has been built for the active
   tenant.
2. **Active Oracle** — whatever `exa oracle use` last activated as `field_oracle.json`.
3. **Local base pack** — a base pack built on this machine.
4. **Bundled base** — the demo set that ships with exa-tools, so there is always *something* to
   resolve against.

The commands that manage this live under `exa oracle` — build, activate, and inspect — and are
documented in [configuration.md](configuration.md).

> **Legacy path — `exa update --cim2`.** The Oracle used to be built by cloning
> [Content-Library-CIM2](https://github.com/ExabeamLabs/Content-Library-CIM2) (~500 MB) and
> recursing its `pC_*.md` parser files. That clone is a *shared* reference that drifts from any
> given tenant — measured at 7.5 months behind a live tenant — and isn't what a tenant actually
> runs, which is why the default moved to tenant exports. `exa update` **no longer clones
> Content-Library-CIM2 by default**; `exa update --cim2` opts back into the legacy pC-based build
> for anyone who still wants it. The one thing the old build did that the export can't: it carried
> *explicit* raw→CIM2 mappings rather than regex-derived ones (see the nuance above).

### The three confidence levels

Every field the converter resolves is assigned one of three confidence levels, so you know
exactly what's verified before you deploy. Resolution runs in `resolve_cim2_field()` in
`exa/sigma/converter.py`:

| Confidence | Meaning | How it's reached |
|---|---|---|
| `oracle` | Field confirmed in `DS/` parser definitions for this activity type / vendor — **no warning** | A direct `raw_to_cim2` hit, **or** a `CIM2_FIELD_MAP` name confirmed present in `by_activity_type` |
| `schema` | In `CIM2_FIELD_MAP` but **not** confirmed in `DS/` for this specific source — mapped, unverified | Name is in the static map, oracle is loaded, but the field isn't in the oracle for this activity type |
| `passthrough` | No mapping found anywhere — the field isn't in CIM2 for this vendor | Not in `raw_to_cim2` and not in `CIM2_FIELD_MAP` |

The resolution order is:

1. **`raw_to_cim2` direct hit** → `oracle`. A raw field that appears verbatim in a parser's JSON
   path definition is inherently oracle-confidence — it came straight out of a parser file.
2. **`CIM2_FIELD_MAP` lookup**, then oracle confirmation. If the translated CIM2 name appears in
   `by_activity_type` — first checking the exact `activity_type`, then any activity type — it's
   `oracle`; otherwise `schema`.
3. **No mapping** → `passthrough`.

Confidence drives the warnings and deploy-readiness: a `passthrough` field emits
`Unmapped field: <f> (not in CIM2 DS/)` and forces `Needs review`; a `schema` field (when the
oracle is loaded) emits `Field '<f>' mapped by schema but not confirmed in DS/ for <ctx>`; an
`oracle` field is silent. Crucially, the EQL-building path and the confidence-checking path share
the *same* resolver, so the query and its stated confidence can never disagree on which field was
mapped.

## Field Oracle concept resolution (compliance)

The Field Oracle also powers **tenant-aware compliance auditing** — see [compliance.md](compliance.md)
for the audit workflow itself. The problem it solves: the same control ("group membership is
monitored") must query different `activity_type` values on different tenants, because each tenant
connects a different set of log sources. Hardcoding filters per tenant doesn't scale; querying for
an activity type a tenant never emits produces a false negative that looks like a passed control.

The fix is a layer of **semantic concepts** between controls and activity types. Each control in
the ControlQueries JSON is annotated with one or more concepts (e.g. `GROUP_MANAGEMENT`,
`PERMISSION_CHANGE`, `AUTH_FAILURE`) drawn from a fixed taxonomy of **18 concepts**
(`exa/compliance/concepts.py`), and each concept maps to a small list of CIM2 activity types:

```
GROUP_MANAGEMENT   → group-modify
PERMISSION_CHANGE  → file-permission-modify, ds_object-modify, audit_policy-modify
AUTH_FAILURE       → authentication, endpoint-authentication
PHYSICAL_ACCESS    → physical_location-access
…
```

At audit time the resolution runs as a three-step chain:

```
Control concepts  →  ConceptResolver     (filter to tenant-active activity_types)
                  →  ComplianceQueryBuilder (build the EQL filter string)
                  →  search_events        (live query against the tenant)
```

- **`ConceptResolver`** (`exa/compliance/resolver.py`) first calls `active_activity_types()`,
  which queries the tenant for the distinct `activity_type` values actually seen in the lookback
  window (a `group_by activity_type` search). Then `resolve(concepts, active_types)` expands the
  control's concepts to activity types, keeping **only** the ones confirmed present on that tenant.
- **`ComplianceQueryBuilder`** (`exa/compliance/query_builder.py`) formats the surviving types as
  an EQL filter: `activity_type:"X" OR activity_type:"Y" …`. If concept resolution yields nothing
  — no concepts, or active-type filtering removed everything — it falls back to the static
  `fallback_filter` carried in the control's ControlQueries JSON (this is what `--no-tenant-aware`
  forces unconditionally).

This means compliance queries adapt to each customer's log sources with no manual tuning. Run the
same NIST CSF audit against `acme-demo` and against `<tenant>` and each gets an EQL filter built
from its *own* activity types.

### The physical-access exception

One concept is deliberately **never** filtered by tenant-active types: `PHYSICAL_ACCESS`
(`physical_location-access`). If a tenant hasn't connected a physical access-control source (badge
readers, DNA Fusion, etc.), that activity type won't be in its active set — but suppressing the
query would hide the gap. So `resolve()` always includes `PHYSICAL_ACCESS` regardless of active
types: **0 results then means "the log source isn't connected" — a clear, reportable gap — not a
false negative from a query that was quietly dropped.** That distinction is the whole point of
routing compliance through the Oracle: a missing control fails loudly instead of passing by
accident.

---

[← README](../README.md)

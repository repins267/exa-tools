# Detection

Convert Splunk SPL and SigmaHQ rules to Exabeam EQL, deploy them to a tenant, and manage the
analytics rules already running there.

[← README](../README.md)

---

exa-tools has two front doors into a tenant's correlation rules and one for the analytics rules
already deployed:

- **`exa sigma`** — convert (and deploy) SigmaHQ community YAML rules.
- **`exa splunk`** — convert (and deploy) Splunk SPL searches, batch or one-off.
- **`exa detection`** — list, export, import, diff, and version the analytics (UEBA) rules that
  live on the tenant.

Both converters route through the same `SPL → Sigma → EQL` pipeline, backed by the **Field
Oracle** — a local index built from Exabeam's own parser definitions that rates every field
mapping `oracle`, `schema`, or `passthrough` so you know what's verified before you deploy. The
pipeline internals and the Oracle are documented in
[docs/architecture.md](architecture.md); this page is the command and conversion reference.

Every command takes `--help`, and every command takes `--tenant <name>`.

---

## Sigma → EQL

### `exa sigma convert` (alias `exa sc`)

Convert one Sigma YAML rule or a whole directory to Exabeam EQL correlation rules. The output is a
table showing each rule's EQL query, deploy readiness, and any field-mapping warnings. Rules that
can't be mapped are flagged but don't stop the batch.

```bash
exa sigma convert --rule proc_creation_powershell_encoded.yml
exa sigma convert --dir ./rules/windows/
exa sigma convert --dir ./rules/ --deploy
exa sigma convert --dir ./rules/ --deploy --tenant <tenant>
```

| Flag | Effect |
|---|---|
| `--rule` / `-r` | A single Sigma YAML file |
| `--dir` / `-d` | A directory of Sigma YAML files |
| `--deploy` | Create the deploy-ready rules on the tenant via API |
| `--tenant` / `-t` | Tenant nickname or FQDN |

### `exa sigma deploy` (alias `exa sd`)

Convert and deploy a single Sigma rule in one step — equivalent to `sigma convert --deploy` for one
file. `--rule` is required.

```bash
exa sigma deploy --rule proc_creation_powershell_encoded.yml --tenant <tenant>
```

### `exa sigma browse`

Browse the local SigmaHQ community index (populated by `exa update`) without converting anything.
Filter by logsource category, product, level, ATT&CK tag, or a title keyword. Results are capped
at 50 — narrow the filters to see more.

```bash
exa sigma browse --category process_creation --level high
exa sigma browse --tag attack.t1059 --product windows
exa sigma browse --search "powershell"
```

| Flag | Effect |
|---|---|
| `--category` / `-c` | Logsource category (`process_creation`, `network_connection`, `file_event`, …) |
| `--product` / `-p` | Product (`windows`, `linux`, `macos`, `aws`, `azure`, `gcp`) |
| `--level` / `-l` | `low`, `medium`, `high`, `critical` |
| `--tag` | ATT&CK tag, e.g. `attack.t1059` |
| `--search` / `-s` | Substring match on rule title |

---

## Splunk SPL → EQL

### `exa splunk convert`

Batch-convert an input file of SPL searches. Accepts `.xlsx`, `.csv` (both read `title` and
`search` columns), or a `savedsearches.conf` (stanza names become titles). The input file must
come before any options; quote paths that contain spaces.

```powershell
# Batch convert an Excel file with 'title' and 'search' columns
exa splunk convert searches.xlsx

# Pick a specific sheet (Excel only; default sheet is "in")
exa splunk convert searches.xlsx --sheet Enabled

# CSV and savedsearches.conf inputs work too
exa splunk convert searches.csv --verbose
exa splunk convert savedsearches.conf

# Show all per-rule warnings including field confidence
exa splunk convert searches.xlsx --verbose

# Custom output file
exa splunk convert searches.xlsx --output rules.json

# Skip RGXi auto-compression (see below)
exa splunk convert searches.xlsx --no-compress
```

The rich table shows each rule's index, activity type, EQL preview, warning count, and deploy
status. Two JSON files are written alongside: the API-ready payloads (`*.converted.json`) and, when
oversized value lists were moved to context tables, a `*.tables.json` of table candidates for
`exa splunk create-tables`.

| Flag | Default | Effect |
|---|---|---|
| `--output` / `-o` | auto-named | Output JSON file for API payloads |
| `--sheet` | `in` | Sheet name (Excel only) |
| `--verbose` / `-v` | off | Show full warnings for each rule |
| `--compress` / `--no-compress` | `compress` | Auto-compress oversized EQL (see below) |

### `exa splunk one`

Convert a single SPL search inline — no input file needed. Prints the EQL query, description, and
all warnings; optionally saves the API payload.

```powershell
exa splunk one 'index=c42 severity="High"' --title "Code42 High Severity Alert"
exa splunk one 'index=o365 Operation=Send' --title "O365 Outbound Email"
exa splunk one 'index=ad CommandLine="*mimikatz*"' --json
exa splunk one 'index=fireamp_stream severity="High"' --title "AMP Alert" -o rule.json
```

`--title` / `-t` sets the rule title (default `Ad-hoc SPL Search`), `--output` / `-o` saves the
payload, and `--json` prints the raw payload instead of the rich table.

### `exa splunk deploy`

Deploy the JSON produced by `exa splunk convert`, POSTing each rule to the correlation-rules API.

```powershell
exa splunk deploy rules.json --dry-run --tenant <tenant>   # preview, no writes
exa splunk deploy rules.json --tenant <tenant>             # deploy (disabled by default)
exa splunk deploy rules.json --enabled --tenant <tenant>   # activate immediately (not recommended)
```

Rules are created **disabled** by default — validate the EQL in the Exabeam UI before enabling.
Before each rule is created, the deployer validates its EQL against the live tenant (`--validate`,
on by default): rules with unknown fields or syntax errors are skipped with Exabeam's own error
message, rather than surfacing as broken rules in the UI after the fact. Use `--no-validate` to
deploy unconditionally, or `--dry-run` to see what would be sent without any API calls.

| Flag | Default | Effect |
|---|---|---|
| `--enabled` | off | Create rules in the enabled state |
| `--dry-run` | off | Preview without writing to the tenant |
| `--validate` / `--no-validate` | `validate` | Validate each EQL against the live tenant first |
| `--tenant` / `-t` | saved default | Tenant nickname or FQDN |

### `exa splunk create-tables`

When conversion moves a large exact-value list into a context table (see auto-compression below),
it records the table in a `*.tables.json` file. `create-tables` reads that file and creates each
context table on the tenant, uploading its values as records. The table name matches the
`IN "TableName"` reference already embedded in the converted EQL, so run this **before** deploying
the rules that reference them. Tables that already exist (matched by display name) are updated
in place rather than duplicated.

```powershell
exa splunk convert searches.xlsx                      # generates .converted.json + .tables.json
exa splunk create-tables searches.tables.json --tenant <tenant>
exa splunk deploy searches.converted.json --tenant <tenant>
```

`--operation` is `replace` (default) or `append`; `--dry-run` previews without writing.

### EQL overflow auto-compression

Exabeam's correlation-rule API enforces a **1024-character EQL limit**. SPL searches with large
wildcard or value lists (e.g. 40 `file-name=UBR*.py` conditions) routinely exceed it. Rather than
silently marking these rules `EQL too long`, the converter compresses them in stages, stopping as
soon as the EQL fits:

1. **Wildcard lists** (`file-name=Foo*`, `file-path=*bar*`) collapse into a single
   `RGXi("a|b|c")` alternation per field. Each Sigma modifier is preserved — `startswith` →
   `^prefix`, `endswith` → `suffix$`, `contains` → inner fragment, middle-glob → `^foo.*bar$`.
2. **Exact-value lists** (no wildcards) move into a context table: the values become
   `field IN "TableName"`, and the table is written to `*.tables.json` for `exa splunk
   create-tables`. Exabeam caps this at **2 context-table references per rule**.
3. **Splitting** — if the EQL is still over the limit, the largest field's values are split across
   N rules, each independently under the limit. OR-ing the N subsets covers the same event space
   as the original; the rule is reported as `Split (N parts)`.

When compression brings the EQL under 1024 chars the rule is promoted to `Needs review` with a
warning naming what changed (e.g. `Compressed field 'file_name' wildcard list -> RGXi to fit API
limit`). Only pathological cases — hundreds of values that survive all three stages — remain
`EQL too long` and need a manual rewrite.

Use `--no-compress` to skip all of this and see the raw, unmodified EQL.

### Deploy status and "Needs review"

SPL→EQL is **lossy by design** — `stats`, `eval`, `lookup`, and similar pipeline stages have no
EQL equivalent and are inventoried as warnings rather than silently dropped. So every Splunk-
converted rule lands as `deploy_ready: Needs review`; it always needs human sign-off before you
enable it. The status column can also read:

| Status | Meaning |
|---|---|
| `Needs review` | Converted cleanly; SPL→EQL is lossy, so a human must confirm before enabling |
| `No` | A field was stripped, or a field resolved as Oracle `passthrough` (not in the tenant's parser schema — the UI would reject it) |
| `Split (N parts)` | EQL exceeded the limit; split into N deployable subset rules |
| `EQL too long` | Still over 1024 chars after compression, table substitution, and splitting — manual rewrite required |

Sigma conversions add a `Yes` status for rules that map cleanly with no caveats.

### Supported indexes

`exa splunk` maps each Splunk `(index, sourcetype)` pair to the closest Exabeam CIM2
`activity_type`. Where no sourcetype-specific match exists, the index-only fallback is used.

| Splunk index | Sourcetype | Data source | activity_type |
|---|---|---|---|
| `c42` | *(any)* | Code42 (Incydr) DLP | `file-write` |
| `c42` | `c42-file-exposure` | Code42 file exposure | `file-write` |
| `c42` | `c42-alerts` | Code42 risk alerts | `rule-trigger` |
| `ad` | *(any)* | Active Directory / Sysmon | `process-create` |
| `ad` | `wineventlog` | Windows Event Log | `authentication` |
| `ips` | *(any)* | Cisco Firepower IPS | `rule-trigger` |
| `o365` | *(any)* | Microsoft O365 | `app-activity` |
| `fireamp_stream` | *(any)* | Cisco Secure Endpoint (AMP) | `rule-trigger` |
| `dg` | *(any)* | Digital Guardian DLP | `file-write` |
| `dg` | `syslog_csirtexportprocess` | Digital Guardian process export | `process-create` |
| `docexchange` | *(any)* | Document Exchange (PCB/hardware files) | `file-write` |
| `plminfoexchangelogs` | *(any)* | Agile PLM Info Exchange | `app-activity` |

Several of these mappings are marked `EXA-UNVERIFIED` in the source — the closest CIM2 activity
where a source's parser config decides the real value. Review the `activity_type` against
`Content-Library-CIM2/DS/` before enabling any rule built on one.

---

## Rule naming conventions

Every converted rule is prefixed by its source so you can bulk-manage a whole batch by name:

- **`[Splunk] <title>`** — from `exa splunk`; select the batch with
  `get_correlation_rules(name="[Splunk]*")`.
- **`[Sigma] <title>`** — from `exa sigma`; select with `get_correlation_rules(name="[Sigma]*")`.

Severity defaults to `medium` — adjust before deploying. The intermediate Sigma YAML is preserved
in the converter's output for audit and review.

---

## `exa detection` — manage deployed analytics rules

`exa detection` works on the analytics (UEBA) rules already running on a tenant — the export /
import / diff / snapshot toolkit for rule backup, cross-tenant migration, and gap analysis.

### List and inspect

```bash
exa detection list                                    # first 100 rules, table view
exa detection list --status enabled                   # enabled only
exa detection list --status enabled --limit 0         # all enabled rules (0 = no cap)
exa detection list --name "[Sigma]*"                  # name-substring filter
exa detection get <rule-id>                           # full detail for one rule
```

The `list` table auto-adds **Type** and **Families** columns when the API returns them and prints
a summary of the distinct rule types found. Export the same view as CSV or JSON, to stdout or a
file:

```bash
exa detection list --status enabled --limit 0 --csv --output enabled.csv
exa detection list --limit 0 --json --output all-rules.json
```

The CSV includes `id, name, isEnabled, severity, type, families, author, createdAt, updatedAt,
description`.

### Enable and disable

```bash
exa detection enable <rule-id>
exa detection disable <rule-id>
```

### Export, import, and diff bundles

`export` writes a portable JSON bundle (all rules, or a subset via repeated `--id`). `import`
reads that bundle back — skipping rules whose ID already exists unless `--overwrite` is given.
`diff` compares two bundles and shows rules added, removed, and changed with field-level deltas —
handy for auditing what shifted between TDM update cycles.

```bash
exa detection export all-rules.json                              # every rule
exa detection export subset.json --id <uuid1> --id <uuid2>       # a specific subset
exa detection import all-rules.json                              # skip existing IDs
exa detection import all-rules.json --overwrite                  # replace existing IDs
exa detection diff baseline.json current.json                    # human-readable delta
exa detection diff baseline.json current.json --json             # machine-readable
```

Export first — it's your rollback point before any write.

### Snapshot into a context table

`snapshot` exports every analytics rule and writes it into a context table as a full, atomic
replace, creating the table with the right schema if it doesn't exist. It's idempotent, so it's
safe to re-run after TDM updates to keep an in-tenant record of the current rule set. Accepts a
table name (substring match) or an exact table UUID.

```bash
exa detection snapshot "Detection Snapshot"
exa detection snapshot "Detection Snapshot" --tenant <tenant>
```

> **Writes to the tenant.** `deploy`, `import`, `enable`, `disable`, and `snapshot` all modify
> analytics rules. Name and confirm the tenant before running them, and keep an `export` bundle as
> a rollback point. `convert`, `list`, `get`, `diff`, and `--dry-run` are read-only.

---

For the `SPL → Sigma → EQL` pipeline internals and the Field Oracle, see
[docs/architecture.md](architecture.md).

[← README](../README.md)

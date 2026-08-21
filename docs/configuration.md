# Configuration

How exa-tools stores tenant credentials, keeps reference data current, and manages context tables from the command line.

[← README](../README.md)

---

## Tenancy model

Every tenant is registered once and referenced afterward by a short **nickname**. A tenant profile splits in two:

- **Secrets** — `client_id` and `client_secret` — go to the OS credential store: Windows Credential Manager, macOS Keychain, or Linux Secret Service, under the keyring service `exa-tools/<nickname>`.
- **Non-secret metadata** — API server, FQDN, region, and the demo/customer kind tag — go to `~/.exa/config.json`.

No secret is ever written to `config.json`, to your shell history, or to a report. This is why `--tenant` takes a nickname, not a credential: switching tenants is a lookup, so when Claude drives the CLI through the [MCP server](mcp.md), no secret reaches the model.

Almost every command accepts `-t / --tenant <name>`. When you omit it, the command uses the configured default tenant.

### FQDN and region resolution

`exa configure` resolves the tenant FQDN to the correct regional API server automatically:

- `acme-demo.exabeam.cloud` (or the bare nickname `acme-demo`) → US West, the default region.
- `acme-demo.use1.exabeam.cloud` → the region code (`use1`, `euw1`, `sae1`, …) selects the API server.

You never set the API server by hand — give the FQDN and the region falls out of it.

## `exa configure`

Interactive, no flags. Prompts for the tenant FQDN, client ID, and client secret; tests the connection; and saves the profile (secret to the credential store, the rest to `config.json`).

```bash
exa configure
```

Related:

- `exa config tenants` — list the tenants already configured.
- `exa auth -t <name>` — verify one of them still authenticates.
- `exa config remove -t <name>` — delete a tenant and its stored credentials.

## `exa auth`

Verify authentication for a tenant, or register a **Webhook Cloud Collector**. The same credential-store discipline as `configure`: a collector's token goes to the OS credential store under service `exa-webhook`, key `<tenant>-<format>` — the exact key [`exa simulate`](detection.md) reads — so a registered collector needs no further setup. Only non-secret metadata (name, tenant, format, note, created) is written to `~/.exa/collectors.json`; the token never touches a file, and no list path returns it.

```bash
exa auth                                       # test auth for the default tenant
exa auth -t <tenant>                           # test a specific tenant

# Register a collector (prompts for the token, masked; or reads EXA_WEBHOOK_TOKEN)
exa auth --collector -t <tenant>
exa auth --collector -t <tenant> --format raw --name "Zscaler raw" --note prod
exa auth --collector -t <tenant> --no-prompt   # env-only, never prompt

exa auth --list-collectors                     # registered collectors (never shows tokens)
```

A tenant can register more than one collector — e.g. a `raw` Zscaler collector and a `json` collector — each with its own token, coexisting under `<tenant>-raw` / `<tenant>-json`.

## `exa config`

Inspects and edits `~/.exa/config.json`. It takes **subcommands, not flags** — to add a tenant use `exa configure` (which sets one up); `exa config` inspects what already exists.

```bash
exa config set default_tenant acme-demo   # which tenant is used when --tenant is omitted
exa config set sigma.rules-dir "E:\SigmaHQ\rules\windows"
exa config get sigma.rules-dir
exa config show                           # all current values (never secrets)
exa config tenants                        # nickname, FQDN, region, API server, default marker
```

Settable keys: `default_tenant`, `sigma.rules-dir`, and `sigma.deploy-tenant`.

### Tagging demo vs customer

```bash
exa config set-kind acme-demo demo
exa config set-kind <tenant> customer
```

The kind is non-secret metadata surfaced by the MCP `get_active_tenant` / `list_tenants` tools, so an agent can tell a customer tenant from a demo one **before** it writes. Skills that write announce the active tenant and its kind first.

### Removing a tenant

```bash
exa config remove -t <tenant>             # prompts to confirm
exa config remove -t <tenant> --confirm   # skip the prompt
```

Deletes the keyring credentials and the `config.json` entry. If the removed tenant was the default, the default is cleared too.

## `exa update`

Downloads or refreshes the reference data the converter and the Field Oracle depend on, cloning or pulling into `~/.exa/cache/`:

```bash
exa update             # sync CIM2 + Content Hub + SigmaHQ, rebuild the Field Oracle
exa update --check     # show current repo SHAs without pulling anything
exa update self        # git pull + uv sync on exa-tools itself
```

`exa update` walks Exabeam's own parser definitions to build the Field Oracle — see [Architecture](architecture.md) for what the Oracle is and how conversion uses it. Run it once at setup, and again whenever you want the latest CIM2 parsers or SigmaHQ community rules.

`exa update self` updates the tool in place; it only works when exa-tools was installed from a **git clone** (`git clone … && uv sync`), not from a packaged wheel.

## `exa tables`

Full CRUD for context tables, with automatic 20,000-record batching on every write. Table arguments accept either the table ID or its display name; add `--tenant` to target a non-default environment.

For the AI/LLM reference tables specifically, use `exa aillm` — [AI/LLM tables](aillm.md) — rather than driving `exa tables` by hand.

### Listing

```bash
exa tables list                    # all tables on the tenant
exa tables list --name Compliance  # filter by name substring
exa tables list --json             # ndjson, one table per line
```

### Creating

```bash
exa tables create "My Table"                              # empty, default schema
exa tables create "My Table" --type User --key username   # typed, custom key column
exa tables create "My Table" --csv data.csv --key hostname # schema derived from CSV headers
```

- `--type` — the context type: `Other` (default), `User`, `TI_ips`, `TI_domains`, `Device`, `Domain`, `IP`.
- `--key` — the key column name (default `key`, or the first CSV column when `--csv` is given).
- `--columns a,b,c` — extra column names; **ignored** when `--csv` is supplied.
- `--csv PATH` — CSV headers become the column schema and the rows upload immediately after the table is created.
- `--replace` — use replace semantics for that initial upload instead of the default append.

When `--csv` is given the schema is derived from the CSV headers automatically, so `--columns` has nothing to do and is skipped.

### Records: append vs replace

```bash
exa tables records list "My Table"                     # first 1000 records
exa tables records list "My Table" --limit 100 --offset 200
exa tables records list "My Table" --csv out.csv       # write to a CSV file
exa tables records list "My Table" --json              # ndjson

exa tables records upload "My Table" data.csv          # append (default)
exa tables records upload "My Table" data.csv --replace # atomically replace the whole table
exa tables records upload "My Table" data.csv --key hostname

exa tables records export "My Table" backup.csv        # all pages -> CSV
```

The upload semantics are the non-obvious part:

- **Append is additive.** Re-running an append **creates duplicates** — the API does not de-duplicate. When you need idempotency, use `--replace` or list the existing records first. The first CSV column is the record key unless you assert one with `--key`.
- **Replace rewrites the entire table** in one atomic operation. There is no per-record edit or delete on OOTB (Exabeam-managed) tables — `deleteRecords` returns 404 there — so replacing the whole set is the only way to change or drop an entry.
- **An empty replace does nothing.** Writes batch as `ceil(records / 20000)`, so zero records means zero requests: the table is left untouched and the call still reports success. It is not a wipe — there is no path to empty a context table through this command. Always `exa tables records export` to a CSV before a destructive replace.

### Deleting

```bash
exa tables delete "My Custom Table"                    # prompts to confirm
exa tables delete <table-id> --yes                     # skip the prompt
exa tables delete "My Table" --purge-attributes        # also drop now-unused custom attributes
```

OOTB (Exabeam-managed) tables cannot be deleted through this command.

## Where things live

| Path | Holds |
|---|---|
| `~/.exa/config.json` | Tenant nicknames, API servers, region, kind tags, default tenant, `sigma.*` settings — never secrets |
| OS credential store (`exa-tools/<nickname>`) | `client_id` and `client_secret` per tenant |
| `~/.exa/cache/` | Cloned CIM2, Content Hub, and SigmaHQ reference data; the built Field Oracle |

---

[← README](../README.md)

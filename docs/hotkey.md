# Hot key — Dataflow worker imbalance from coarse Network Zones

Diagnose and fix Apache Beam/Dataflow hot key risk caused by coarse Network Zones context-table entries, then expand those zones to /24 with a rollback manifest written before anything changes.

[← README](../README.md)

## The problem

Exabeam's analytics pipeline runs on Apache Beam/Dataflow, which shards work across workers by key. When the **Network Zones** context table groups IP space into a handful of coarse entries — a single `10.0.0.0/8` covering sixteen million addresses, say — every event whose source IP falls in that block hashes to the *same* key. One worker inherits a disproportionate share of the keyspace while the rest sit idle, and the job stalls behind that one shard.

The symptom is Dataflow worker imbalance: long job runtimes and a flood of `HotKeyLogger` warnings in the worker logs. This was confirmed on a production tenant — a 47-minute job runtime with 96 `HotKeyLogger` warnings, traced directly to coarse Network Zones entries.

The fix is to make the keys finer. A zone written as `/8` or `/16` is one key; split into the `/24`s actually seen in traffic, it becomes many keys that spread across workers evenly. `exa hotkey` finds the coarse zones, confirms which ones carry real traffic, and rewrites them at /24 granularity — reversibly.

## Classification: CRITICAL / COARSE / FINE

Every Network Zones entry is classified by the prefix length of its CIDR key:

| Class | Prefix range | Meaning |
|---|---|---|
| **CRITICAL** | ≤ /16 (e.g. `/8`, `/16`) | Guaranteed hot key. Auto-flagged for expansion regardless of observed traffic — the block is too large to ever shard well. |
| **COARSE** | /17 – /23 | May cause a hot key. Traffic-scanned to confirm before expanding — only flagged `HOT_KEY_RISK` if enough distinct IPs are actually active in the zone. |
| **FINE** | ≥ /24 | Acceptable granularity. `/24` is the expansion target itself, so these are left alone. |

CRITICAL zones expand on the strength of their size alone; COARSE zones have to earn expansion by showing real traffic, so you don't shatter a quiet zone into hundreds of dead /24 keys.

## Workflow

The pipeline is **analyze → scan → expand**, with **rollback** always available and **autofix** running the whole thing end to end:

1. **`analyze`** reads the Network Zones table and classifies every entry (no queries against event data, no writes).
2. **`scan`** searches recent events for the distinct source IPs active per zone, and flags COARSE zones that exceed the threshold as `HOT_KEY_RISK`. CRITICAL zones are shown with `ip_count=--` because they qualify regardless.
3. **`expand`** rewrites flagged coarse zones to /24 granularity. **A rollback manifest is written to `~/.exa/hotkey-rollback/<tenant>/` before any change is made.**
4. **`rollback`** restores the table from the last manifest.
5. **`autofix`** is the full pipeline in one command — analyze, scan, expand — safe to schedule.

### Classify all zones by hot key risk

```bash
# CRITICAL / COARSE / FINE for every Network Zones entry
exa hotkey analyze --tenant <tenant>
exa hotkey analyze --csv --tenant <tenant> > zones.csv      # Excel-compatible CRLF
exa hotkey analyze --json --tenant <tenant>
```

### Scan real traffic

```bash
# Distinct active source IPs per zone; flag COARSE zones as HOT_KEY_RISK
exa hotkey scan --tenant <tenant>
exa hotkey scan --lookback 3 --tenant <tenant>
exa hotkey scan --lookback 3 --threshold 1000 --tenant <tenant>
exa hotkey scan --csv --lookback 3 --tenant <tenant> > scan.csv
```

### Expand coarse zones to /24

```bash
# Rollback manifest is written first, then the table is rewritten
exa hotkey expand --dry-run --tenant <tenant>               # preview without writing
exa hotkey expand --zone "US-Denver" --dry-run --tenant <tenant>
exa hotkey expand --tenant <tenant>
```

By default `expand` uses only the /24s observed in traffic; pass `--enumerate` to write every /24 in the range instead.

### Full pipeline in one step

```bash
exa hotkey autofix --dry-run --tenant <tenant>
exa hotkey autofix --critical-only --dry-run --tenant <tenant>   # skip scan, CRITICAL only
exa hotkey autofix --max-zones 20 --tenant <tenant>
exa hotkey autofix --json --tenant <tenant>                      # pipeable; progress to stderr
```

`autofix` always expands CRITICAL zones without a scan check and requires `HOT_KEY_RISK` confirmation for COARSE zones. It refuses to expand more than `--max-zones` in one run (default 10) as a safety cap, exits non-zero on any failure, and is non-interactive — safe for a scheduled task.

### Undo the last expand

```bash
exa hotkey rollback --tenant <tenant>                       # preview the diff, no changes
exa hotkey rollback --confirm --tenant <tenant>             # apply the rollback
exa hotkey rollback --manifest ~/.exa/hotkey-rollback/<tenant>/2026-05-14.json --confirm
```

`rollback` shows a diff and does nothing without `--confirm`. With no `--manifest`, it uses the most recent manifest for the tenant.

## Key flags

| Command | Flag | Default | Effect |
|---|---|---|---|
| `analyze` | `--csv` | off | Excel-compatible CSV with CRLF line endings |
| `scan` | `--lookback N` | 7 | Days of events to search |
| `scan` | `--threshold N` | 500 | Distinct IPs per zone to flag `HOT_KEY_RISK` |
| `expand` | `--zone NAME` | all flagged | Target a single zone by name |
| `expand` | `--dry-run` | off | Preview changes without writing |
| `expand` | `--enumerate` | off | Enumerate all /24s; default uses observed IPs only |
| `autofix` | `--critical-only` | off | Skip traffic scan; expand CRITICAL zones directly |
| `autofix` | `--max-zones N` | 10 | Safety cap — refuse to expand more than N zones |
| `rollback` | `--manifest PATH` | most recent | Restore from a specific manifest |
| `rollback` | `--confirm` | off | Required to apply; shows the diff without it |

Every command takes `--tenant <name>` and `--help`. The `--ip-field` / `--name-field` options let you name the Network Zones columns holding the IP/subnet and the zone name explicitly; both are auto-detected when omitted.

[← README](../README.md)

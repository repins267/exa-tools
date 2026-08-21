# Compliance

Automated evidence collection and control-by-control gap analysis against your Exabeam
New-Scale tenant, rendered as an HTML/PDF report.

[← README](../README.md)

---

## What an audit does

`exa compliance audit` queries the SIEM for evidence events matching each SIEM-testable
control in the selected framework, then scores every control against a threshold:

```bash
exa frameworks                                            # list frameworks + testable control counts
exa compliance audit --framework "NIST CSF v2.0" --lookback 30
exa compliance audit --framework PCI_DSS --output-html --output-pdf
```

Controls with at least `--min-evidence` events (default 10) in the `--lookback` window
(default 30 days) score **PASS**; those below threshold score **FAIL** or **INSUFFICIENT**.
The result is an HTML report — auto-named in `reports/` — with an executive summary, family
coverage breakdown, and gap analysis, optionally rendered to PDF.

## Tenant-aware vs static mode

Controls are annotated with semantic *concepts* rather than fixed field filters. How those
concepts become an EQL query is the difference between the two modes:

- **Tenant-aware (default)** — the resolver first asks the tenant which `activity_type`
  values are actually present, then builds EQL from only those, using the Field Oracle to
  map concepts to this tenant's real fields. A control whose log source is missing fails as
  a clear gap instead of a false negative from a query that never matched anything. This is
  the accurate mode, and why it is the default.
- **Static (`--no-tenant-aware`)** — skips Field Oracle discovery and runs the hardcoded EQL
  filters straight from the ControlQueries JSON. Faster, but blind to what the tenant emits,
  so an absent source can read as a fail rather than a gap.

The concept-resolution mechanism itself — the Field Oracle, and how a concept resolves to a
verified field — is described in [docs/architecture.md](architecture.md).

```bash
# Tenant-aware (default) — discovers active activity_types via the Field Oracle
exa compliance audit --framework "NIST CSF v2.0" --tenant <tenant> --tenant-aware

# Static — hardcoded filters from JSON only, skips tenant discovery
exa compliance audit --framework "NIST CSF v2.0" --tenant <tenant> --no-tenant-aware
```

## Output flags

Reports are written under `reports/` with an auto-name of `<tenant>-<framework>-<date>`
unless you pass an explicit path. PDF is rendered from the HTML via Microsoft Edge headless
(`msedge.exe --headless --print-to-pdf`) — no extra software needed on Windows.

| Flag | Behavior |
|---|---|
| `--output-html` | Auto-save HTML to `reports/<tenant>-<framework>-<date>.html` |
| `--output-html <path>` | Save HTML to an explicit path |
| `--output-pdf` | Render the HTML to PDF and save it alongside, via Edge headless |
| `--pdf-path <path>` | Save PDF to an explicit path (implies `--output-pdf`) |
| `--output-json <path>` / `-o` | Save the full JSON report to a file |
| `--output-csv <path>` | Save control results as CSV (auto-saved beside the HTML otherwise) |
| `--tenant-aware` | Dynamic EQL via Field Oracle concept resolution (default: on) |
| `--no-tenant-aware` | Static filters from the ControlQueries JSON |

```bash
# Auto-named HTML in reports/
exa compliance audit --framework HIPAA --tenant <tenant> --output-html

# HTML to an explicit path
exa compliance audit --framework HIPAA --tenant <tenant> --output-html C:\reports\audit.html

# PDF to an explicit path
exa compliance audit --framework HIPAA --tenant <tenant> --pdf-path C:\reports\audit.pdf
```

## Supported frameworks

`exa frameworks` lists every framework with its live testable-control count. Seven ship full
queries with concept annotations; four are stubs whose control catalogs exist but whose
queries are still pending.

| Framework | ID | Testable controls | Status |
|---|---|---|---|
| NIST CSF v2.0 | `NIST_CSF` | 60 | Full queries + concept annotations |
| CIS Controls v8 | `CIS_V8` | 110 | Full queries + concept annotations |
| HIPAA | `HIPAA` | 67 | Full queries + concept annotations |
| PCI DSS v4.0.1 | `PCI_DSS` | 153 | Full queries + concept annotations |
| FedRAMP Moderate | `FedRAMP_Moderate` | 145 | Full queries + concept annotations |
| ISO/IEC 27001:2022 | `ISO_27001` | 58 | Full queries + concept annotations |
| CJIS Security Policy v5.9.5 | `CJIS` | 55 | Full queries + concept annotations |
| CMMC Level 2 (NIST SP 800-171r2) | `CMMC_L2` | 33 | Stub (queries pending) |
| CMMC Level 3 (NIST SP 800-172) | `CMMC_L3` | 16 | Stub (queries pending) |
| GDPR | `GDPR` | 17 | Stub (queries pending) |
| Sarbanes-Oxley (SOX) | `SOX` | 9 | Stub (queries pending) |

Pass either the ID or the display name to `--framework` (`NIST_CSF` or `"NIST CSF v2.0"`).

---

[← README](../README.md)

# Changelog

All notable changes to this project are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/); this project uses semantic
versioning (pre-1.0: minor versions may still change behaviour).

## [0.2.0] - 2026-08-21

First tagged release. Adds the **OOTB context-table auto-populator** — assess any
tenant and make its OOTB dashboards work — plus demo tooling and a statistical CI
safety gate.

### Added
- **`exa assess`** — the repeatable engine: discover sources → derive which
  context table+field each OOTB dashboard/rule requires *live* (from deployed
  rules' `ContextListContains` + OOTB dashboard `context_rule` bindings) → gap →
  reviewable record → `--apply --confirm` gated write. Read-only by default.
- **Cross-customer learn loop** — capture knowledge new to exa-tools, tier it
  (auto-promote / review / local-only), and promote only generic values so the
  next customer starts smarter. Customer-specific / PII is never promoted.
- **`exa assess benchmark`** — score the classifier on a labelled golden corpus:
  auto-promote precision, PII-withhold recall, AI recall, Wilson lower bound, and
  an A→E learn-loop proof. JSON + HTML scorecard; exits non-zero on FAIL.
- **Isotonic calibration** (`calibration.py`) — PAVA + Wilson-lower-bound
  precision-floor thresholding, staged for a future scoring/LLM tier.
- **`exa dashboard preview`** — render any Exabeam dashboard `.config` (or a
  folder) as a branded, PII-scrubbed report; `custom_looker_map`/`bubble` now draw
  as bars.
- **`exa aillm report --format html|pdf|json|csv`** — pick the output format.
- **`exa aillm cycle`** — snapshot→populate→audit→verify→rollback stability
  harness (N iterations, rollback even on failure).
- **`exa simulate timing`** + run ledger — end-to-end detection timing (MTTD)
  against a recorded send's expected rules.
- **`exa-assess` MCP skill** — TAM-facing wrapper; Claude is the LLM-assist for
  the review tier (skills 16 → 17).
- **CI safety gate** (`.github/workflows/ci-pipeline.yml`) — deterministic
  heuristic gate on push/PR (blocking) + nightly LLM leaderboard (non-blocking);
  CODEOWNERS on the golden corpus; corpus-integrity guards.
- **Repo traffic tracker** (`.github/workflows/repo-metrics.yml`) — weekly
  clones/views snapshot beyond GitHub's 14-day retention.

### Changed
- Format-aware webhook token resolution (env → OS credential store `<tenant>-<fmt>`
  / `<tenant>` → prompt) so multiple collectors coexist.
- `render_dashboard` MCP tool gains a `scrub` option; shared headless-Edge PDF
  helper (`exa/report/pdf.py`) reused by compliance and AI/LLM reports.

### Fixed
- PII-detection gap: a DLP alert name embedding an SSN reached the review tier;
  `_looks_per_record` now flags SSN / 6+ digit ids / DLP-wrapper phrasing
  (PII-withhold recall 0.833 → 1.000).
- `_is_measure` "country trap": `geo_src_ip_country` was misread as a measure
  because it contains "count", breaking geo-map previews.

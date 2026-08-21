# OOTB validation — assess, preview, prove

The workflow that makes Exabeam's out-of-the-box dashboards work in any tenant and proves it: `exa assess` populates the context tables a dashboard needs, `exa dashboard preview` shows them lit up, and `exa simulate timing` proves the detections actually fire.

[← README](../README.md)

The three commands form one loop. An OOTB dashboard's panels gate on an exact `field IN table` membership test, and the tables ship with only a thin slice of generic seed values — so in a real tenant the panels render empty. **Assess** closes that gap from what the tenant actually emits; **preview** renders the dashboard so you can see the panels populate; **timing** injects a scenario and measures how fast the populated tables drive a detection to a case. Run them in that order to take an OOTB pack from empty to proven.

## `exa assess` — make the OOTB dashboards work in any tenant

`assess` discovers what a tenant actually emits, derives which context table + field each deployed rule and OOTB dashboard requires *live* — from `ContextListContains(table, field)` in the deployed rules and the dashboards' own `context_rule` bindings — then closes the gap so the exact `field IN table` panel filters match. Newly-seen **generic** knowledge is learned across customers (A → B → C gets smarter); customer-specific values and PII are never promoted to shared knowledge. See [the six AI/LLM tables it populates](aillm.md).

```bash
# Assess a tenant and print the requirement map + gap report (no writes)
exa assess --tenant <tenant>
exa assess --dashboards exabeam_OOTB_dashboards/   # derive from local OOTB .config files
exa assess --lookback 30 --out assessments/        # write the assessment record

# Apply the closed gap (gated) and manage the learn loop
exa assess --apply --confirm --tenant <tenant>             # write reviewed proposals
exa assess --apply --promote --approve-reviews             # auto-promote high-confidence generic
exa assess --apply --no-promote                            # apply, keep nothing to shared knowledge
```

Writes are gated: dry-run is the default, only the reviewed propose-bucket is written, and `--confirm` is required to touch a tenant. The learn loop separates *generic* new values (safe to promote and reuse for the next customer) from *customer-specific* / PII (kept local, never promoted) — the discipline the safety metrics below exist to enforce.

### `exa assess benchmark` — prove the classifier on known data

```bash
exa assess benchmark --golden tests/data/classifier_golden.jsonl
exa assess benchmark --model claude --output-json scorecard.json
exa assess benchmark --fail-under-precision 1.0 --fail-under-pii-recall 1.0 --min-corpus 35
```

`benchmark` scores the classifier against a versioned golden corpus and reports per-class precision / recall / F1, with the two safety metrics called out — **auto-promote precision** (the leak metric, target 1.0) and **PII-withhold recall** (1.0) — plus a Wilson lower-bound gate that tightens as the corpus grows. It runs as the blocking CI check ("Heuristic Rules & Safety Verification"), so a classifier or knowledge change is measured, not guessed. Don't weaken those thresholds to make a change pass.

## `exa dashboard preview` — see it lit up

Render any OOTB dashboard `.config` to a standalone HTML / PDF report preview, with customer specifics scrubbed by default so it is safe to share. Panels are populated with sample data grouped by the panel's dimension (the context-table filter is approximated, so counts show shape, not exact scoped values).

```bash
exa dashboard preview dashboards/ai-llm.config
exa dashboard preview dashboards/ai-llm.config --format pdf --out preview.pdf
exa dashboard preview dashboards/ai-llm.config --live --tenant <tenant>   # pull real panel data
exa dashboard preview dashboards/ai-llm.config --no-scrub                 # keep tenant specifics
```

A directory renders one gallery page of every `.config` under it. The preview uses the shared report renderer, so `--brand` and `--no-footer` select the header logo and attribution the same way every report does — see [Reports](mcp.md).

## `exa simulate timing` — prove detection fires (MTTD)

Inject a scenario's synthetic events and measure detection timing (MTTD) against a deadline — the repeatable proof that the populated tables light up the rules. Dry-run is the default; pass `--no-dry-run` to actually send, and `--poll` to watch until the detection lands or the deadline passes.

```bash
exa simulate timing --scenario ai-exfil --tenant <tenant>
exa simulate timing --scenario ai-exfil --deadline 300 --poll --interval 15   # watch until detected
exa simulate timing --scenario ai-exfil --pdf --out reports/mttd.pdf
exa simulate timing --scenario ai-exfil --once                                # single pass (dry-run is the default)
```

Timing closes the loop: after `assess --apply` has populated the tables and `dashboard preview` shows the panels ready, `simulate timing` confirms an emitted event drives the rule to a case inside the deadline. For the broader detection-content workflow this validates, see [Detection](detection.md).

[← README](../README.md)

# Credits & Attribution

exa-tools is MIT-licensed. It stands on the work of others — this file records what
was adapted, what data is pulled in, and whose tools informed the design. If you find
something here that should be credited differently, open an issue.

## Adapted code (attribution required)

These integrations adapt code or patterns from open-source projects. exa-tools ships
independent implementations, but the design and, in places, the approach are theirs.

- **socxen** — [open-agent-ai-security/socxen](https://github.com/open-agent-ai-security/socxen)
  (Apache-2.0). The MCP guardrails — result **canonicalization** (strip invisible smuggling
  code points) and write-input **neutralization** (defang formulas/links, redact secrets) —
  and the red-team test corpus follow socxen. See `exa/mcp/guardrails/` and `tests/redteam/`.
- **observra** — [open-agent-ai-security/observra](https://github.com/open-agent-ai-security/observra).
  The metadata-only, fail-open, default-on **audit log** follows observra's assurance pattern
  (self-contained; no runtime dependency). See `exa/mcp/audit.py`.
- **praxen** — [open-agent-ai-security/praxen](https://github.com/open-agent-ai-security/praxen).
  The **Agent Behavior Verification** (policy remit adjudicated against code) and the AI-BOM
  generator (`security/gen_aibom.py`) follow praxen / its `gen_aibom.py`. See `security/praxen/`.

## Bundled or pulled reference data

Pulled locally by `exa update` into `~/.exa/` and used for field verification, conversion,
and AI/LLM classification. Each remains under its own upstream license.

- **SigmaHQ** — [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — the Sigma rule corpus (`exa sigma`).
- **Exabeam Content-Library-CIM2** — [ExabeamLabs/Content-Library-CIM2](https://github.com/ExabeamLabs/Content-Library-CIM2) — CIM2 field/parser definitions behind the Field Oracle.
- **Exabeam new-scale-content-hub** — [ExabeamLabs/new-scale-content-hub](https://github.com/ExabeamLabs/new-scale-content-hub) — correlation-rule / search content used to verify conversions.
- **AI/LLM domains dataset** — repins267/ai-llm-domains — the curated AI-domain/app/risk reference the `aillm` module classifies against.

## Inspiration & reference (reviewed, not derived)

Tools reviewed for capability ideas. No code was copied from these; they informed planned
or existing features and are credited here in good faith.

- **charliemacas** — [LogRhythmToolchest](https://github.com/charliemacas/LogRhythmToolchest),
  incl. **LogRhythmEcho** and the **Exabeam Echo** desktop app (Electron log-replay tool for
  New-Scale). Echo's replay-and-observe idea — ship known-bad telemetry, then watch what the
  platform detects — directly informed exa-tools' **`simulate timing`** (end-to-end
  detection-timing / MTTD against a recorded run's expected rules). Echo's real-log/PCAP
  **replay** and OOTB use-case **library**, and the Toolchest's **LogRhythm↔Windmill**
  alert-forwarding pattern, continue to inform planned work (`simulate replay`,
  alert→webhook/SOAR forwarding). Independent, separately-authored tools.
- **Kati Hatch** — the Team Innovation Toolkit **Log Comparison Tool** (data-source volume
  diff between two windows) informs a planned `log_volume_compare` capability.

## Design lineage (internal)

The AI/LLM snapshot/rollback guardrail (`exa/aillm/rollback.py`) mirrors exa-tools' own
Network-Zones hotkey rollback (`exa/hotkey/rollback.py`) — same manifest-and-replace pattern.

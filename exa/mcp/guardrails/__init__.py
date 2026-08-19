"""Prompt-injection guardrails for the MCP surface.

Vendored from socxen (open-agent-ai-security/socxen, Apache-2.0) — see
THIRD_PARTY_NOTICES.md. Two pure, deterministic passes on the trust boundary:

- ``canonicalize`` — applied to tool RESULTS (log/telemetry data the model reads):
  strips obvious smuggling code points (zero-width, bidi overrides, tag chars) and
  NFC-normalizes, so an instruction hidden in an alert field can't reach the model
  invisibly. "Do no harm" — legitimate values are left intact.
- ``neutralize_output`` — applied to WRITE inputs (case-note / update text before it
  persists): quote-prefixes spreadsheet formulas, defangs links, and redacts secrets,
  so a payload planted in telemetry can't fire when the artifact is later exported.

These modules are Apache-2.0 and stay Apache-2.0; the rest of exa-tools is MIT.
"""

from __future__ import annotations

from .canonicalize import Hygiene, canonicalize
from .neutralize_output import neutralize_output

__all__ = ["canonicalize", "Hygiene", "neutralize_output", "scrub_result", "neutralize_write_args"]

# Free-text write fields that get persisted and later exported — the neutralize sink.
_WRITE_TEXT_FIELDS = frozenset({
    "content", "note", "notes", "closed_reason", "closedReason",
    "supporting_reason", "supportingReason", "alertDescription", "description",
})
# List-of-string write fields — each element is a persisted sink too (e.g. a tag
# carrying =HYPERLINK(...) would survive to export). ABV-004.
_WRITE_LIST_FIELDS = frozenset({"tags"})


def scrub_result(obj):
    """Canonicalize every string leaf of a tool result. Pure, structure-preserving."""
    if isinstance(obj, str):
        clean, _ = canonicalize(obj)
        return clean
    if isinstance(obj, list):
        return [scrub_result(x) for x in obj]
    if isinstance(obj, dict):
        return {k: scrub_result(v) for k, v in obj.items()}
    return obj


def neutralize_write_args(arguments: dict) -> tuple[dict, list]:
    """Neutralize free-text fields in a write tool's arguments before they persist.

    Returns (new_arguments, notes). Known free-text string fields and the string
    elements of known list fields (e.g. tags) are neutralized; ids, priorities, and
    everything else pass through unchanged.
    """
    if not isinstance(arguments, dict):
        return arguments, []
    notes: list = []
    out = dict(arguments)
    for field, val in arguments.items():
        if field in _WRITE_TEXT_FIELDS and isinstance(val, str) and val:
            clean, n = neutralize_output(val)
            if clean != val:
                out[field] = clean
                notes.extend({**note, "field": field} for note in n)
        elif field in _WRITE_LIST_FIELDS and isinstance(val, list):
            new_list, changed = [], False
            for item in val:
                if isinstance(item, str) and item:
                    clean, n = neutralize_output(item)
                    if clean != item:
                        changed = True
                        notes.extend({**note, "field": field} for note in n)
                    new_list.append(clean)
                else:
                    new_list.append(item)
            if changed:
                out[field] = new_list
    return out, notes

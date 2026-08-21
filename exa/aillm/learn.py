"""Cross-customer learning: capture NEW generic knowledge and promote it safely.

A gap analysis proposes values a tenant emits that a context table lacks. Some
are already in exa-tools' shared knowledge (they just need syncing); some are
NEW. Of the new ones, the GENERIC (non-customer, non-PII) values are promotable
knowledge that makes the next customer start smarter; customer-specific /
per-record / PII values are **local-only** and never leave the tenant.

Promotion is tiered: high-confidence generic **auto-promotes**; the rest go to
**review**; per-record/PII is **local-only**. Deterministic and auditable -- the
LLM only ever assists on the review tail (elsewhere), never here.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path

_LEARN_DIR = Path.home() / ".exa" / "aillm-learn"
_PROMOTED = _LEARN_DIR / "promoted.json"

AUTO = "auto-promote"
REVIEW = "review"
LOCAL = "local-only"

_JSONISH = re.compile(r"[{}\[\]\":]")
_EMAILISH = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def _looks_per_record(value: str) -> bool:
    """A value that is really per-event data (PII risk), not shareable taxonomy."""
    v = value or ""
    return len(v) > 80 or bool(_EMAILISH.search(v)) or len(_JSONISH.findall(v)) >= 2


@dataclass
class LearnCandidate:
    value: str
    field: str
    table: str
    verdict: str      # AUTO | REVIEW | LOCAL
    reason: str
    raw_count: int = 0


def load_promoted() -> list[dict]:
    if _PROMOTED.exists():
        try:
            return json.loads(_PROMOTED.read_text(encoding="utf-8")).get("values", [])
        except (OSError, json.JSONDecodeError):
            return []
    return []


def _promoted_values() -> set[str]:
    return {str(e.get("value", "")).lower() for e in load_promoted()}


def load_known() -> set[str]:
    """Lowercased union of bundled reference data + vendor packs + promoted overlay."""
    known: set[str] = set()
    try:
        from exa.aillm.reference import load_reference_data
        ref = load_reference_data()
        for attr in ("known_ai_domains", "known_ai_apps", "proxy_categories",
                     "web_categories", "ai_apps", "ai_domains"):
            vals = getattr(ref, attr, None)
            if isinstance(vals, (list, set, tuple)):
                known |= {str(v).lower() for v in vals}
    except Exception:  # noqa: BLE001 -- best effort; missing reference != crash
        pass
    try:
        from exa.aillm.vendors import known_ai_categories
        known |= {str(v).lower() for v in known_ai_categories()}
    except Exception:  # noqa: BLE001
        pass
    return known | _promoted_values()


def classify(value: str, reason: str, redacted: bool) -> tuple[str, str]:
    """Tiered verdict for a NEW value (not already known)."""
    if redacted or _looks_per_record(value):
        return LOCAL, "per-record/PII -- never promoted"
    if reason in {"vendor-pack-category", "ai-category", "vendor-pack-template"} \
            and len(value) <= 60:
        return AUTO, f"high-confidence generic ({reason})"
    if reason in {"ai-classified", "ai-signal-over-vendor-noise", "ai-runtime-process"}:
        return REVIEW, f"generic candidate ({reason})"
    return REVIEW, f"new value ({reason})"


def extract_learn_candidates(
    gap_dict: dict, known: set[str] | None = None
) -> list[LearnCandidate]:
    """New (not-already-known) proposed values from a gap report, tier-classified."""
    known = load_known() if known is None else known
    out: list[LearnCandidate] = []
    for t in gap_dict.get("tables", []):
        for p in t.get("propose", []):
            val = str(p.get("value", ""))
            if not val or val.lower() in known:
                continue  # empty, or already-known generic (sync, not learn)
            verdict, reason = classify(val, str(p.get("reason", "")), bool(p.get("redacted")))
            out.append(LearnCandidate(
                value=val, field=str(p.get("field", "")), table=str(p.get("table", "")),
                verdict=verdict, reason=reason, raw_count=int(p.get("live_values") or 0),
            ))
    return out


def write_learn_file(tenant: str, candidates: list[LearnCandidate]) -> Path:
    """Persist candidates; LOCAL values are counted but their value is redacted."""
    _LEARN_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    recs = []
    for c in candidates:
        d = asdict(c)
        if c.verdict == LOCAL:
            d["value"] = "[redacted -- local only]"
        recs.append(d)
    path = _LEARN_DIR / f"{tenant}-{ts}.json"
    path.write_text(
        json.dumps({"tenant": tenant, "captured_at": ts, "candidates": recs}, indent=2),
        encoding="utf-8",
    )
    return path


def promote(candidates: list[LearnCandidate], *, approve_reviews: bool = False) -> list[dict]:
    """Merge promotable candidates into the shared knowledge overlay.

    Auto-promotes the AUTO tier; includes REVIEW only when ``approve_reviews`` (the
    human gate). LOCAL is NEVER promoted -- the hard no-customer-data-leak rule.
    Returns the newly-added records.
    """
    promotable = [
        c for c in candidates
        if c.verdict == AUTO or (approve_reviews and c.verdict == REVIEW)
    ]
    existing = load_promoted()
    seen = {str(e.get("value", "")).lower() for e in existing}
    added: list[dict] = []
    for c in promotable:
        if c.verdict == LOCAL or c.value.lower() in seen:  # belt-and-suspenders
            continue
        rec = {"value": c.value, "field": c.field, "reason": c.reason}
        existing.append(rec)
        seen.add(c.value.lower())
        added.append(rec)
    _LEARN_DIR.mkdir(parents=True, exist_ok=True)
    _PROMOTED.write_text(json.dumps({"values": existing}, indent=2), encoding="utf-8")
    return added

"""Render synthetic vendor events from a vendor pack's wire template.

`scenarios.py` builds Sysmon events; this builds anything a pack declares a
`wire_template` for. The point is that adding a vendor is a JSON edit rather than a
new module -- 22 packs would otherwise mean 22 emitters, each drifting with parser
version and differing per tenant deployment.

**The condition assertion is the reason this module exists.** A parser matches on
literal substrings ANDed against the raw log and evaluated BEFORE any extraction.
Miss one and the event lands `parsed:false` with no fields, while ingest still
returns HTTP 200 -- a silent failure that looks exactly like success. So every
rendered event is checked against the pack's `parser_conditions` before it can be
sent, and a miss raises rather than ships.

That check is not proof the event will parse: conditions gate which parser claims a
log, but the field regexes still have to match, and the pack may be transcribed from
a mirror that is stale (EXA-PUBLIC-REPOS-LAG). It proves only that the event cannot
fail for the one reason that is invisible afterwards. `exa simulate verify` remains
the empirical answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from exa.aillm.vendors import load_vendor_packs

if TYPE_CHECKING:
    from exa.aillm.vendors import VendorPack


class ConditionsNotMetError(RuntimeError):
    """A rendered event does not contain every parser match condition."""


class NoTemplateError(RuntimeError):
    """The pack has no wire_template, so nothing can be rendered from it."""


@dataclass(frozen=True)
class VendorEvent:
    """One rendered raw log line, with what it is expected to produce."""

    raw: str
    vendor_key: str
    expects: dict[str, str]  # CIM2 field -> value we expect the parser to extract


def get_pack(vendor_key: str) -> VendorPack:
    packs = load_vendor_packs()
    try:
        return packs[vendor_key]
    except KeyError:
        raise ValueError(
            f"Unknown vendor pack {vendor_key!r}. Known: {', '.join(sorted(packs))}"
        ) from None


def missing_conditions(raw: str, pack: VendorPack) -> list[str]:
    """Which of the pack's parser conditions are absent from a rendered log."""
    return [c for c in pack.parser_conditions if c not in raw]


def render(
    vendor_key: str,
    values: dict[str, Any],
    *,
    when: datetime | None = None,
    expects: dict[str, str] | None = None,
) -> VendorEvent:
    """Render one raw log line from a pack template.

    `values` supplies the template placeholders. `{time}` is filled from `when`
    using the pack's `wire_time_format` unless the caller passes it explicitly.

    Raises ConditionsNotMetError if the result would not satisfy the parser's match
    conditions -- refusing to emit something that would land unparsed.
    """
    pack = get_pack(vendor_key)
    if not pack.wire_template:
        raise NoTemplateError(
            f"{vendor_key} has no wire_template. Add one to vendor_packs.json "
            "alongside its parser_conditions -- see the module docstring."
        )

    filled = dict(values)
    if "time" not in filled:
        stamp = when or datetime.now(UTC)
        fmt = pack.wire_time_format or "%a %b %d %H:%M:%S %Y"
        filled["time"] = stamp.strftime(fmt)

    try:
        raw = pack.wire_template.format(**filled)
    except KeyError as exc:
        raise ValueError(
            f"wire_template for {vendor_key} needs a value for {exc}"
        ) from None

    absent = missing_conditions(raw, pack)
    if absent:
        raise ConditionsNotMetError(
            f"rendered {vendor_key} event is missing parser condition(s): {absent}. "
            "It would be ingested and land unparsed, with HTTP 200 and no fields."
        )

    return VendorEvent(raw=raw, vendor_key=vendor_key, expects=expects or {})


# Fields every Zscaler row shares. Kept apart from the rows so each row states only
# what it varies -- domain, app, category, action -- which is what a reviewer needs to
# read. `module` is a parser match condition and must stay exactly "AI & ML Apps".
_ZSCALER_DEFAULTS: dict[str, str] = {
    "module": "AI & ML Apps",
    "action": "Allowed",
    "reason": "Allowed",
    "dlp_engine": "None",
    "app_class": "AI & ML",
    "proto": "HTTPS",
    "method": "POST",
    "resp_code": "200",
    "sip": "10.20.30.41",
    "dip": "104.18.6.1",
    "req_size": "1842",
    "resp_size": "9310",
    "total_size": "11152",
    "dept": "Engineering",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
}

# Only what each row varies. `url_cat` AND `url_super_cat` both carry an AI category
# on purpose: the parser takes `category` from whichever of urlSuperCat=/urlCat= it
# reaches first, so leaving the supercategory non-AI would hand `category` a value
# that no AI table can match.
_ZSCALER_AI_ROWS: list[dict[str, str]] = [
    {"dname": "claude.ai", "app_name": "Claude",
     "url_cat": "Generative AI and ML Applications", "login": "m.chen"},
    {"dname": "chat.openai.com", "app_name": "ChatGPT",
     "url_cat": "Generative AI and ML Applications", "login": "r.patel"},
    {"dname": "gemini.google.com", "app_name": "Gemini",
     "url_cat": "Generative AI and ML Applications", "login": "s.okafor"},
    {"dname": "perplexity.ai", "app_name": "Perplexity",
     "url_cat": "Generative AI and ML Applications", "login": "m.chen"},
    # The one string anywhere that separates personal Copilot from the enterprise
    # tenant -- worth having on screen, nothing else surfaces it.
    {"dname": "copilot.microsoft.com", "app_name": "Microsoft Copilot",
     "url_cat": "MS Copilot Personal", "login": "j.whitfield"},
    # Blocked, so the allow-vs-block pivot has both sides rather than one colour.
    {"dname": "huggingface.co", "app_name": "Hugging Face",
     "url_cat": "General AI and ML Applications", "login": "a.novak",
     "action": "Blocked", "reason": "Blocked", "resp_code": "403"},
    # A typosquat and a DLP hit: this is the row that carries the finding, and the
    # only one that populates AI/LLM DLP Rulesets via DLPEng=.
    {"dname": "chatgpt-login.com", "app_name": "ChatGPT",
     "url_cat": "Generative AI and ML Applications", "login": "d.reyes",
     "action": "Blocked", "reason": "Blocked", "resp_code": "403",
     "dlp_engine": "AI Data Protection - Source Code"},
]


def ai_seed_rows(
    *,
    marker: str = "EXA-SIMULATION",
    email_domain: str = "demo.local",
) -> list[dict[str, Any]]:
    """Zscaler rows that put AI values into six AI/LLM context tables.

    The marker rides in `location=`, which no AI/LLM table reads, so seeded rows stay
    identifiable and excludable without contaminating a field the demo depends on.
    """
    rows: list[dict[str, Any]] = []
    for row in _ZSCALER_AI_ROWS:
        filled = {**_ZSCALER_DEFAULTS, **row}
        filled["login"] = f"{row['login']}@{email_domain}"
        filled["url"] = f"{row['dname']}/chat"
        filled.setdefault("url_super_cat", filled["url_cat"])
        filled["location"] = marker
        filled["_expects"] = {
            "web_domain": row["dname"],
            "app": row["app_name"],
            "category": filled["url_cat"],
        }
        rows.append(filled)
    return rows


def render_many(
    vendor_key: str,
    rows: list[dict[str, Any]],
    *,
    when: datetime | None = None,
) -> list[VendorEvent]:
    """Render a batch. An `_expects` key in a row is pulled out, not templated."""
    out: list[VendorEvent] = []
    for row in rows:
        values = {k: v for k, v in row.items() if k != "_expects"}
        out.append(
            render(vendor_key, values, when=when, expects=row.get("_expects") or {})
        )
    return out

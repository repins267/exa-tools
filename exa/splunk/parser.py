"""Parse Splunk SPL search strings into structured metadata.

This is a targeted parser for converting the Supply Chain Splunk
searches to Exabeam EQL.  It does not implement a full SPL grammar —
it extracts the subset of information needed for the conversion:

  - index and sourcetype
  - Top-level field=value / field!=value conditions
  - Pipeline stage inventory (for warning generation)
  - Subsearch lookup table references
  - | regex command conditions
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ParsedSPL:
    """Structured representation of a parsed SPL search."""

    raw: str
    title: str = ""

    # ── Source ──────────────────────────────────────────────────────────────
    index: str = ""
    sourcetype: str | None = None

    # ── Filters extracted from search head ─────────────────────────────────
    # List of (field, operator, value) triples: ("severity", "=", "High")
    field_conditions: list[tuple[str, str, str]] = field(default_factory=list)

    # Raw | regex conditions extracted from pipeline: [(field, pattern)]
    regex_conditions: list[tuple[str, str]] = field(default_factory=list)

    # ── Pipeline analysis ───────────────────────────────────────────────────
    pipeline_stages: list[str] = field(default_factory=list)
    has_stats: bool = False
    has_eval: bool = False
    has_lookup: bool = False
    has_subsearch: bool = False
    has_rex: bool = False
    has_spath: bool = False
    has_ldapsearch: bool = False
    has_makemv: bool = False
    has_eventstats: bool = False

    # Lookup table names found in pipeline or subsearches
    lookup_names: list[str] = field(default_factory=list)

    # Field used in | stats ... by <field>
    stats_by_field: str | None = None

    # Drop pipeline stage names (for warning messages)
    dropped_stages: list[str] = field(default_factory=list)


# Pipeline stages that cannot be converted to EQL
_UNSUPPORTED_STAGES: frozenset[str] = frozenset({
    "stats", "eventstats", "eval", "rex", "spath", "lookup",
    "inputlookup", "convert", "fillnull", "dedup", "table",
    "sort", "rename", "strcat", "ldapsearch", "where", "makemv",
    "mvexpand", "join",
})

# Pipeline stages that can be partially converted
_REGEX_STAGE = "regex"

# SPL field condition pattern: word[.{}-chars]* (!=|=) "value"|value|'value'
_FIELD_COND_RE = re.compile(
    r"""
    (?<!["\w])          # not preceded by quote or word char (avoid matching mid-string)
    ([\w][\w.\-{}\'\"]*?)  # field name (may contain dots, {}, dashes)
    \s*(!=|=)\s*        # operator
    (                   # value — one of:
      "(?:[^"\\]|\\.)*"   #   double-quoted string
    | '(?:[^'\\]|\\.)*'   #   single-quoted string
    | \*[\w.*\-/]*        #   unquoted wildcard starting with *
    | [\w.*\-/]+          #   unquoted plain value or wildcard
    )
    """,
    re.VERBOSE,
)

# Splunk meta-fields to skip (not meaningful for EQL conversion)
_SKIP_FIELDS: frozenset[str] = frozenset({
    "index", "sourcetype", "source", "host", "splunk_server",
    "_raw", "_time", "_indextime",
})


def _split_pipeline(search: str) -> list[str]:
    """Split SPL on pipe ``|``, respecting brackets and quoted strings."""
    segments: list[str] = []
    current: list[str] = []
    depth = 0
    in_quote = False
    quote_char = ""

    for i, ch in enumerate(search):
        if in_quote:
            current.append(ch)
            if ch == quote_char and (i == 0 or search[i - 1] != "\\"):
                in_quote = False
        elif ch in ('"', "'"):
            in_quote = True
            quote_char = ch
            current.append(ch)
        elif ch == "[":
            depth += 1
            current.append(ch)
        elif ch == "]":
            depth -= 1
            current.append(ch)
        elif ch == "|" and depth == 0:
            segments.append("".join(current))
            current = []
        else:
            current.append(ch)

    if current:
        segments.append("".join(current))
    return segments


def _extract_field_conditions(text: str) -> list[tuple[str, str, str]]:
    """Extract (field, op, value) triples from a filter string."""
    results: list[tuple[str, str, str]] = []
    for m in _FIELD_COND_RE.finditer(text):
        field_name = m.group(1).strip("\"'")
        op = m.group(2)
        value = m.group(3).strip("\"'")

        if field_name.lower() in _SKIP_FIELDS:
            continue
        # Skip fields that look like JSON paths with array notation we can't map
        if "{}" in field_name and "." in field_name and len(field_name) > 40:
            continue
        results.append((field_name, op, value))
    return results


def parse_spl(search: str, title: str = "") -> ParsedSPL:
    """Parse a Splunk SPL search string into structured metadata.

    Args:
        search: Raw SPL search string (may be multi-line).
        title: Optional rule title (for context in warnings).

    Returns:
        ParsedSPL with extracted metadata.
    """
    result = ParsedSPL(raw=search, title=title)

    # Normalise whitespace and strip Excel carriage-return encoding (_x000d_ / _x000D_)
    search = re.sub(r'_x000[dD]_', '', search)
    search_norm = " ".join(search.split())

    # Remove backtick macros
    search_no_macro = re.sub(r"`[^`]*`", "", search_norm)

    # ── Split into head + pipeline stages ───────────────────────────────────
    segments = _split_pipeline(search_no_macro)
    head = segments[0].strip() if segments else ""
    pipeline = segments[1:]

    # ── Extract index & sourcetype from head ────────────────────────────────
    m = re.search(r"\bindex\s*=\s*[\"']?(\w+)[\"']?", head, re.IGNORECASE)
    if m:
        result.index = m.group(1).lower()

    m = re.search(r'\bsourcetype\s*=\s*["\']?([\w\-]+)["\']?', head, re.IGNORECASE)
    if m:
        result.sourcetype = m.group(1).lower()

    # ── Detect subsearches in head ──────────────────────────────────────────
    if "[" in head:
        result.has_subsearch = True
        for lm in re.finditer(
            r'\binputlookup\s+["\']?([^"\'\s\]]+)["\']?', head, re.IGNORECASE
        ):
            name = lm.group(1)
            if name not in result.lookup_names:
                result.lookup_names.append(name)
        if re.search(r"\bldapsearch\b", head, re.IGNORECASE):
            result.has_ldapsearch = True

    # ── Extract field conditions from head (outside subsearches) ────────────
    # Mask out subsearch content before extracting conditions
    head_clean = re.sub(r"\[[^\[\]]*\]", "", head)
    head_clean = re.sub(r"\bindex\s*=\s*\S+", "", head_clean, flags=re.IGNORECASE)
    head_clean = re.sub(r"\bsourcetype\s*=\s*\S+", "", head_clean, flags=re.IGNORECASE)
    result.field_conditions = _extract_field_conditions(head_clean)

    # ── Analyse pipeline stages ─────────────────────────────────────────────
    for stage in pipeline:
        stage = stage.strip()
        if not stage:
            continue
        cmd = stage.split()[0].lower() if stage else ""
        result.pipeline_stages.append(cmd)

        if cmd in _UNSUPPORTED_STAGES:
            result.dropped_stages.append(cmd)

        if cmd in ("stats", "eventstats"):
            result.has_stats = True
            if cmd == "eventstats":
                result.has_eventstats = True
            bm = re.search(r"\bby\s+([\w.\-{}'\"]+)", stage, re.IGNORECASE)
            if bm and not result.stats_by_field:
                result.stats_by_field = bm.group(1).strip("\"'")

        elif cmd in ("lookup", "inputlookup"):
            result.has_lookup = True
            parts = stage.split(None, 2)
            if len(parts) > 1:
                name = parts[1].strip("\"'")
                if name not in result.lookup_names:
                    result.lookup_names.append(name)

        elif cmd == "eval":
            result.has_eval = True

        elif cmd == "rex":
            result.has_rex = True
            fm = re.search(r'field=([\w.\-]+)', stage)
            pm = re.search(r'"([^"]+)"', stage)
            if fm and pm:
                result.regex_conditions.append((fm.group(1), pm.group(1)))

        elif cmd == "spath":
            result.has_spath = True

        elif cmd == "ldapsearch":
            result.has_ldapsearch = True

        elif cmd == "makemv":
            result.has_makemv = True

        elif cmd == _REGEX_STAGE:
            # | regex field="pattern" or | regex field!="pattern"
            rm = re.search(r'(\w[\w.\-]*)\s*!?=\s*"([^"]+)"', stage)
            if rm:
                result.regex_conditions.append((rm.group(1), rm.group(2)))
    return result

"""Offline evaluation of correlation-rule EQL against a single event.

Lets `exa simulate` answer "would this event actually trigger that rule?"
without sending anything to a tenant — which is the difference between a
generator that emits plausible-looking logs and one that provably exercises
deployed content.

Supports the subset of EQL the Sigma converter emits:

    field:"value"            exact match, case-insensitive
    field:WLDi("pat")        glob (``*`` wildcard), case-insensitive
    field:RGXi("re")         regex, case-insensitive
    AND / OR / NOT, parentheses

This mirrors backend semantics established empirically against sademodev22
(see EXA-EQL-WLDI-REGEX-ESCAPE in CLAUDE.md): WLDi patterns are regex-compiled,
so a doubled backslash in the pattern denotes one literal backslash, and exact
match is a literal case-insensitive comparison rather than a regex.

Unsupported constructs raise EQLMatchError rather than silently returning
False — a wrong "would not fire" is worse than an explicit gap.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["EQLMatchError", "matches_eql"]


class EQLMatchError(ValueError):
    """The EQL string uses a construct this evaluator does not implement."""


_TOKEN_RE = re.compile(
    r"""
    \s*(?:
      (?P<lparen>\()
    | (?P<rparen>\))
    | (?P<op>\bAND\b|\bOR\b|\bNOT\b)
    | (?P<field>[A-Za-z_][A-Za-z0-9_.]*)\s*:\s*
      (?:
         (?P<fn>WLDi|RGXi)\(\s*"(?P<fnval>(?:[^"\\]|\\.)*)"\s*\)
       | "(?P<exact>(?:[^"\\]|\\.)*)"
       | (?P<bare>[^\s()]+)
      )
    )
    """,
    re.VERBOSE,
)


def _tokenize(eql: str) -> list[tuple[str, Any]]:
    tokens: list[tuple[str, Any]] = []
    pos = 0
    while pos < len(eql):
        if eql[pos].isspace():
            pos += 1
            continue
        m = _TOKEN_RE.match(eql, pos)
        if not m or m.end() == pos:
            raise EQLMatchError(f"Cannot parse EQL near: {eql[pos:pos + 40]!r}")
        pos = m.end()
        if m.group("lparen"):
            tokens.append(("(", None))
        elif m.group("rparen"):
            tokens.append((")", None))
        elif m.group("op"):
            tokens.append((m.group("op").upper(), None))
        else:
            field = m.group("field")
            if m.group("fn"):
                tokens.append(("PRED", (field, m.group("fn"), m.group("fnval"))))
            elif m.group("exact") is not None:
                tokens.append(("PRED", (field, "EXACT", m.group("exact"))))
            else:
                tokens.append(("PRED", (field, "EXACT", m.group("bare"))))
    return tokens


def _unescape(value: str) -> str:
    r"""Undo EQL string escaping: \" -> " (backslashes are left intact)."""
    return value.replace('\\"', '"')


def _wldi_to_regex(pattern: str) -> str:
    r"""Translate a WLDi glob into a regex, matching backend behaviour.

    ``*`` becomes ``.*``; every other character is literal. A doubled
    backslash in the pattern represents one literal backslash.
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            out.append(".*")
            i += 1
        elif ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] == "\\":
            out.append(re.escape("\\"))
            i += 2
        elif ch == "\\" and i + 1 < len(pattern):
            # Single backslash before a metachar: the converter escapes
            # regex metacharacters this way, so take the next char literally.
            out.append(re.escape(pattern[i + 1]))
            i += 2
        else:
            out.append(re.escape(ch))
            i += 1
    return "".join(out)


def _field_values(event: dict[str, Any], field: str) -> list[str]:
    """Return candidate string values for a CIM2 field name.

    Maps the CIM2 names the rules query onto the raw Sysmon JSON keys the
    generator emits, mirroring Exabeam's Sysmon parser extraction.
    """
    aliases = {
        "process_name": ("OriginalFileName", "Image"),
        "process_command_line": ("CommandLine",),
        "command": ("CommandLine",),
        "parent_process_name": ("ParentImage",),
        "parent_process_command_line": ("ParentCommandLine",),
        "process_id": ("ProcessId", "ProcessID"),
        "parent_process_id": ("ParentProcessId",),
        "user": ("User",),
        "host": ("Hostname",),
        "dest_host": ("Hostname",),
        "src_host": ("Hostname",),
        "additional_info": ("Description",),
        "event_code": ("EventID",),
        "activity_type": ("__activity_type__",),
    }
    values: list[str] = []
    for key in aliases.get(field, (field,)):
        if key == "__activity_type__":
            # The generator only emits Sysmon EID 1 process-create events.
            values.append("process-create")
            continue
        raw = event.get(key)
        if raw is None:
            continue
        text = str(raw)
        values.append(text)
        # process_name is the basename of Image backend-side.
        if field == "process_name" and key == "Image":
            values.append(text.rsplit("\\", 1)[-1])
    return values


def _eval_pred(event: dict[str, Any], pred: tuple[str, str, str]) -> bool:
    field, kind, raw = pred
    value = _unescape(raw)
    candidates = _field_values(event, field)
    if not candidates:
        return False

    if kind == "EXACT":
        return any(c.casefold() == value.casefold() for c in candidates)
    if kind == "WLDi":
        rx = re.compile("^" + _wldi_to_regex(value) + "$", re.IGNORECASE | re.DOTALL)
        return any(rx.match(c) for c in candidates)
    if kind == "RGXi":
        rx = re.compile(value, re.IGNORECASE)
        return any(rx.search(c) for c in candidates)
    raise EQLMatchError(f"Unsupported predicate type: {kind}")


class _Parser:
    """Recursive-descent parser for the supported EQL subset."""

    def __init__(self, tokens: list[tuple[str, Any]], event: dict[str, Any]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.event = event

    def peek(self) -> str | None:
        return self.tokens[self.pos][0] if self.pos < len(self.tokens) else None

    def parse(self) -> bool:
        value = self.parse_or()
        if self.pos != len(self.tokens):
            raise EQLMatchError("Trailing tokens in EQL expression")
        return value

    def parse_or(self) -> bool:
        value = self.parse_and()
        while self.peek() == "OR":
            self.pos += 1
            right = self.parse_and()
            value = value or right
        return value

    def parse_and(self) -> bool:
        value = self.parse_unary()
        while self.peek() == "AND":
            self.pos += 1
            right = self.parse_unary()
            value = value and right
        return value

    def parse_unary(self) -> bool:
        if self.peek() == "NOT":
            self.pos += 1
            return not self.parse_unary()
        return self.parse_atom()

    def parse_atom(self) -> bool:
        tok = self.peek()
        if tok == "(":
            self.pos += 1
            value = self.parse_or()
            if self.peek() != ")":
                raise EQLMatchError("Unbalanced parenthesis in EQL")
            self.pos += 1
            return value
        if tok == "PRED":
            pred = self.tokens[self.pos][1]
            self.pos += 1
            return _eval_pred(self.event, pred)
        raise EQLMatchError(f"Unexpected token {tok!r} in EQL")


def matches_eql(event: dict[str, Any], eql: str) -> bool:
    """Return True if a synthetic event satisfies a correlation rule's EQL.

    Raises EQLMatchError when the expression uses unsupported syntax, so an
    unevaluatable rule is never silently reported as "would not fire".
    """
    if not eql or not eql.strip():
        raise EQLMatchError("Empty EQL expression")
    tokens = _tokenize(eql)
    if not tokens:
        raise EQLMatchError("EQL expression produced no tokens")
    return _Parser(tokens, event).parse()

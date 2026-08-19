"""Parser health — classify parsing errors and recommend fixes.

The classification taxonomy, recommendations and offending-field extraction are
ported from the ExaSight tenant-config collector. Pure functions here (no API);
the collector that queries the SIEM and aggregates lives in collect_parser_health.

Queries used by the collector:
  parsed:true   count(id)     -> parsed volume
  parsed:false  count(id)     -> unparsed volume
  error_detail present         -> per-error records (error_detail, msg_type, src_vendor)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

# High-level operational categories a parser error falls into.
PARSER_ERROR_TYPES = (
    "Date/Time Parsing",
    "Regex / Extraction",
    "Type Conversion",
    "Field Validation",
    "JSON Parsing",
    "Other",
)

_RECOMMENDATIONS = {
    "Date/Time Parsing": "Review raw log time extraction and accepted time formats for the "
    "affected parser. Normalize source timezone and timestamp pattern.",
    "Regex / Extraction": "Review parser regex capture groups, named group reuse, and "
    "extraction boundaries. Validate sample raw logs with spaces and optional fields.",
    "Type Conversion": "Review CIM field type mapping. Ensure numeric, boolean, IP, and list "
    "fields are extracted as expected before analytics processing.",
    "Field Validation": "Review CIM validation failures such as email or IP fields. Confirm "
    "the field contains only normalized values expected by Exabeam.",
    "JSON Parsing": "Review JSON path expressions and null or primitive array handling. Add "
    "guards for missing objects and inconsistent structures.",
    "Other": "Review parser error_detail and associated msg_type for unsupported or uncommon "
    "parser failure behavior.",
}


def classify_parser_error(reason: str, message: str = "", field_name: str = "") -> str:
    """Map a parser error (reason + message + field) to a PARSER_ERROR_TYPES bucket."""
    reason_u = (reason or "").strip().upper()
    combined = f"{reason} {message} {field_name}".lower()
    if reason_u == "DATETIME_FIELD_PARSING" or any(
        k in combined for k in ("datetime", "date", "time format")
    ):
        return "Date/Time Parsing"
    if reason_u == "REGEX_EXTRACTION_ERROR" or any(
        k in combined for k in ("regex", "pattern", "group redeclaration", "extract")
    ):
        return "Regex / Extraction"
    if reason_u == "DATA_TYPE_MISMATCH" or any(
        k in combined for k in ("type mismatch", "cimtype", "number", "integer", "boolean")
    ):
        return "Type Conversion"
    if reason_u == "FIELD_DATA_VALIDATION" or any(
        k in combined for k in ("validation", "email", "ipv4", "ipv6")
    ):
        return "Field Validation"
    if reason_u == "JSON_FIELD_PARSING_ERROR" or any(
        k in combined for k in ("json", "jsonpath", "current context")
    ):
        return "JSON Parsing"
    return "Other"


def parser_error_recommendation(error_type: str) -> str:
    """Actionable remediation for a parser error category."""
    return _RECOMMENDATIONS.get(error_type, _RECOMMENDATIONS["Other"])


def extract_offending_field(error: dict[str, Any]) -> str:
    """Best-effort extraction of the field a parser error is about."""
    field_v = str(error.get("field") or "").strip()
    if field_v:
        return field_v
    message = str(error.get("msg") or error.get("message") or "").strip()
    pattern = str(error.get("pattern") or "").strip()
    for rx in (
        r"Datetime field\s+([^=\s]+)=",
        r"group redeclaration\s+([A-Za-z0-9_\-.]+)",
        r"field\s+([A-Za-z0-9_\-.]+)",
    ):
        m = re.search(rx, message, flags=re.I)
        if m:
            return m.group(1)
    m = re.search(r"\(\{([A-Za-z0-9_\-.]+)\}", pattern)
    if m:
        return m.group(1)
    return "Unknown"


@dataclass
class ParserErrorGroup:
    """Aggregated parser errors sharing a category."""

    category: str
    count: int = 0
    recommendation: str = ""
    top_fields: list[tuple[str, int]] = field(default_factory=list)
    top_sources: list[tuple[str, int]] = field(default_factory=list)


@dataclass
class ParserHealth:
    """Parser-health snapshot for a tenant."""

    tenant: str | None = None
    lookback_days: int = 7
    parsed: int = 0
    unparsed: int = 0
    errors_examined: int = 0
    groups: list[ParserErrorGroup] = field(default_factory=list)
    by_source: list[tuple[str, int]] = field(default_factory=list)
    truncated: bool = False
    note: str = ""

    @property
    def total(self) -> int:
        return self.parsed + self.unparsed

    @property
    def unparsed_pct(self) -> float:
        return round(100 * self.unparsed / self.total, 2) if self.total else 0.0

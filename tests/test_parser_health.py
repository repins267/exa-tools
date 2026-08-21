"""Parser-health classifier (ported from ExaSight)."""

from __future__ import annotations

import pytest

from exa.health.parser import (
    CORE_FIELDS,
    ParserHealth,
    classify_parser_error,
    extract_offending_field,
    grade_parser,
    parser_error_recommendation,
)


class TestClassify:
    @pytest.mark.parametrize("reason,expected", [
        ("DATETIME_FIELD_PARSING", "Date/Time Parsing"),
        ("REGEX_EXTRACTION_ERROR", "Regex / Extraction"),
        ("DATA_TYPE_MISMATCH", "Type Conversion"),
        ("FIELD_DATA_VALIDATION", "Field Validation"),
        ("JSON_FIELD_PARSING_ERROR", "JSON Parsing"),
        ("SOMETHING_UNKNOWN", "Other"),
    ])
    def test_reason_codes(self, reason, expected):
        assert classify_parser_error(reason) == expected

    def test_message_keywords(self):
        assert classify_parser_error("", "invalid jsonpath at current context") == "JSON Parsing"
        assert classify_parser_error("", "group redeclaration foo") == "Regex / Extraction"
        assert classify_parser_error("", "bad email validation") == "Field Validation"

    def test_every_category_has_a_recommendation(self):
        from exa.health.parser import PARSER_ERROR_TYPES
        for t in PARSER_ERROR_TYPES:
            rec = parser_error_recommendation(t)
            assert rec and rec != "" and "Review" in rec


class TestFieldExtraction:
    def test_explicit_field_wins(self):
        assert extract_offending_field({"field": "src_ip"}) == "src_ip"

    def test_from_datetime_message(self):
        assert extract_offending_field({"msg": "Datetime field event_time= could not parse"}) == "event_time"

    def test_from_group_redeclaration(self):
        assert extract_offending_field({"msg": "group redeclaration user_name"}) == "user_name"

    def test_unknown(self):
        assert extract_offending_field({"msg": "totally opaque"}) == "Unknown"


class TestParserHealth:
    def test_percentages(self):
        h = ParserHealth(parsed=9900, unparsed=100)
        assert h.total == 10000
        assert h.unparsed_pct == 1.0

    def test_zero_total_safe(self):
        assert ParserHealth().unparsed_pct == 0.0


class TestGradeParser:
    """NGDV-07-style Red/Yellow/Green triage."""

    def test_green_when_no_errors(self):
        assert grade_parser(set()) == "Green"

    def test_red_when_core_field(self):
        assert grade_parser({"src_ip"}) == "Red"
        assert grade_parser({"user", "some_info_field"}) == "Red"  # any core -> Red

    def test_yellow_when_only_non_core(self):
        assert grade_parser({"vendor_custom_note"}) == "Yellow"

    def test_case_insensitive(self):
        assert grade_parser({"HOST"}) == "Red"

    def test_core_fields_cover_identity_network_activity(self):
        for f in ("user", "src_ip", "dest_ip", "host", "activity_type", "outcome"):
            assert f in CORE_FIELDS

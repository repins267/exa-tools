"""Tests for exa.splunk.compress — RGXi compression and TableCandidate extraction."""
from __future__ import annotations

import re

import pytest

from exa.splunk.compress import (
    TableCandidate,
    compress_overflow,
    compress_sigma_selection,
    _val_to_regex_part,
)


# ── _val_to_regex_part ────────────────────────────────────────────────────────


def test_startswith_to_regex():
    assert _val_to_regex_part("startswith", "foo") == "^foo"


def test_endswith_to_regex():
    assert _val_to_regex_part("endswith", "bar") == "bar$"


def test_contains_to_regex():
    assert _val_to_regex_part("contains", "baz") == "baz"


def test_re_passthrough():
    assert _val_to_regex_part("re", "^foo.*bar$") == "^foo.*bar$"


def test_exact_no_wildcard():
    assert _val_to_regex_part(None, "exact") == "^exact$"


def test_exact_with_middle_wildcard():
    result = _val_to_regex_part(None, "UBR*.py")
    assert result.startswith("^")
    assert result.endswith("$")
    assert ".*" in result


def test_glob_special_chars_escaped():
    result = _val_to_regex_part(None, "foo.bar")
    assert r"\." in result


# ── compress_sigma_selection ──────────────────────────────────────────────────


def _make_startswith_selection(field: str, prefixes: list[str]) -> dict:
    return {f"{field}|startswith": prefixes}


def test_small_list_not_compressed():
    """Fields with < 5 values are left unchanged."""
    sel = {"file_name|startswith": ["foo", "bar"]}
    comp, fields, tables = compress_sigma_selection(sel)
    assert "file_name|startswith" in comp
    assert fields == []
    assert tables == []


def test_startswith_wildcards_compressed():
    """5+ startswith values → single RGXi alternation."""
    prefixes = [f"prefix{i}" for i in range(6)]
    sel = _make_startswith_selection("file_name", prefixes)
    comp, fields, tables = compress_sigma_selection(sel)

    assert "file_name|re" in comp
    assert "file_name" in fields
    assert tables == []

    pattern = comp["file_name|re"][0]
    assert "|" in pattern
    for p in prefixes:
        assert re.escape(p) in pattern or p in pattern


def test_contains_wildcards_compressed():
    """5+ contains values → single RGXi alternation."""
    vals = [f"keyword{i}" for i in range(5)]
    sel = {"user_agent|contains": vals}
    comp, fields, tables = compress_sigma_selection(sel)

    assert "user_agent|re" in comp
    assert "user_agent" in fields
    pattern = comp["user_agent|re"][0]
    for v in vals:
        assert v in pattern


def test_exact_values_become_table_candidate():
    """5+ exact values (no wildcards) → TableCandidate, selection unchanged."""
    users = ["alice", "bob", "charlie", "diana", "eve"]
    sel = {"user": users}
    comp, fields, tables = compress_sigma_selection(sel)

    assert fields == []
    assert len(tables) == 1
    tc = tables[0]
    assert isinstance(tc, TableCandidate)
    assert tc.field == "user"
    assert set(tc.values) == set(users)
    # Selection preserved as-is
    assert comp["user"] == users


def test_mixed_wildcard_exact_compresses():
    """Field with both wildcard and exact values is treated as wildcard (not all_exact)."""
    sel = {"file_name|startswith": ["foo", "bar", "baz"], "file_name": ["exact1", "exact2"]}
    comp, fields, tables = compress_sigma_selection(sel, min_values=5)

    assert "file_name" in fields
    assert "file_name|re" in comp
    assert tables == []


def test_compression_produces_valid_regex():
    """Generated RGXi pattern must compile as valid Python regex."""
    prefixes = ["UBR", "AER-DC", "WNC", "CRS", "ASR"]
    sel = _make_startswith_selection("file_name", prefixes)
    comp, fields, _ = compress_sigma_selection(sel)

    pattern = comp["file_name|re"][0]
    re.compile(pattern)  # must not raise


# ── compress_overflow ─────────────────────────────────────────────────────────


def _make_sigma_dict(selection: dict) -> dict:
    return {
        "title": "Test Rule",
        "logsource": {"category": "process_creation"},
        "detection": {"selection": selection, "condition": "selection"},
    }


def test_no_op_when_no_selection():
    """sigma_dict with no selection is returned unchanged."""
    sigma_dict = {"detection": {}}
    result = compress_overflow(sigma_dict, "Test")
    assert result.sigma_dict is sigma_dict
    assert result.compressed_fields == []
    assert result.table_candidates == []


def test_no_op_when_empty_selection():
    """sigma_dict with _empty selection is returned unchanged."""
    sigma_dict = {"detection": {"selection": {"_empty": True}}}
    result = compress_overflow(sigma_dict, "Test")
    assert result.sigma_dict is sigma_dict


def test_no_op_when_nothing_compressible():
    """Selection with only small fields is returned unchanged."""
    sigma_dict = _make_sigma_dict({"file_name|startswith": ["foo", "bar"]})
    result = compress_overflow(sigma_dict, "Test")
    assert result.sigma_dict is sigma_dict
    assert result.compressed_fields == []


def test_compressed_selection_replaced():
    """compress_overflow returns new sigma_dict with compressed selection."""
    prefixes = [f"prefix{i}" for i in range(6)]
    sigma_dict = _make_sigma_dict({"file_name|startswith": prefixes})
    result = compress_overflow(sigma_dict, "My Rule")

    assert result.compressed_fields == ["file_name"]
    assert "file_name|re" in result.sigma_dict["detection"]["selection"]
    assert "file_name|startswith" not in result.sigma_dict["detection"]["selection"]


def test_table_candidate_name_prefixed_with_rule_name():
    """TableCandidate.table_name is prefixed with the rule name."""
    users = ["alice", "bob", "charlie", "diana", "eve"]
    sigma_dict = _make_sigma_dict({"user": users})
    result = compress_overflow(sigma_dict, "My Rule")

    assert len(result.table_candidates) == 1
    assert result.table_candidates[0].table_name == "My Rule - user Values"


def test_original_sigma_dict_not_mutated():
    """compress_overflow must not mutate the input sigma_dict."""
    prefixes = [f"p{i}" for i in range(6)]
    sigma_dict = _make_sigma_dict({"file_name|startswith": prefixes})
    original_sel = dict(sigma_dict["detection"]["selection"])
    compress_overflow(sigma_dict, "Test")
    assert sigma_dict["detection"]["selection"] == original_sel


# ── convert_spl_to_exa_rule integration ──────────────────────────────────────


def _make_long_spl(field: str, n: int, suffix: str = "*") -> str:
    """Build a SPL search with n field=value conditions."""
    conds = " ".join(f'{field}="prefix{i}{suffix}"' for i in range(n))
    return f"index=c42 ({conds})"


def test_compression_triggered_on_long_eql():
    """convert_spl_to_exa_rule compresses when EQL exceeds 1024 chars."""
    from exa.splunk.converter import convert_spl_to_exa_rule

    spl = _make_long_spl("file_name", 50, suffix="*")
    rule = convert_spl_to_exa_rule("Test Rule", spl)

    eql = rule["eql_query"]
    assert len(eql) <= 1024, f"EQL still too long after compression: {len(eql)} chars"
    if len(eql) <= 1024:
        assert "RGXi" in eql or rule["deploy_ready"] == "EQL too long"


def test_no_compress_flag_skips_compression():
    """compress=False leaves EQL as-is even if over limit."""
    from exa.splunk.converter import convert_spl_to_exa_rule

    spl = _make_long_spl("file_name", 50, suffix="*")
    rule = convert_spl_to_exa_rule("Test Rule", spl, compress=False)

    assert rule["deploy_ready"] == "EQL too long"
    assert "RGXi" not in rule["eql_query"]

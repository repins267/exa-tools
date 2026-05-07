"""Tests for the SPL → Sigma → EQL pipeline.

Covers exa.splunk.to_sigma and the rewritten exa.splunk.converter
that routes through exa.sigma.converter for EQL generation.
"""
from __future__ import annotations

import pytest

from exa.splunk.converter import convert_spl_to_exa_rule
from exa.splunk.parser import parse_spl
from exa.splunk.to_sigma import spl_to_sigma_dict, spl_to_sigma_yaml


# ── spl_to_sigma_dict: logsource resolution ─────────────────────────────────

def test_logsource_ad_default():
    parsed = parse_spl('index=ad CommandLine="*mimikatz*"', "t")
    sigma = spl_to_sigma_dict(parsed, "t")
    assert sigma["logsource"] == {"product": "windows", "category": "process_creation"}


def test_logsource_ad_wineventlog():
    parsed = parse_spl('index=ad sourcetype=wineventlog EventID=4625', "t")
    sigma = spl_to_sigma_dict(parsed, "t")
    assert sigma["logsource"] == {"product": "windows", "service": "security"}


def test_logsource_code42():
    parsed = parse_spl('index=c42 sourcetype=c42-file-exposure', "t")
    sigma = spl_to_sigma_dict(parsed, "t")
    assert sigma["logsource"] == {"product": "code42", "service": "incydr"}


def test_logsource_o365():
    parsed = parse_spl('index=o365 Operation="FileAccessed"', "t")
    sigma = spl_to_sigma_dict(parsed, "t")
    assert sigma["logsource"] == {"product": "m365", "service": "threat_management"}


def test_logsource_unknown():
    parsed = parse_spl('index=mystery field=value', "t")
    sigma = spl_to_sigma_dict(parsed, "t")
    assert sigma["logsource"]["product"] == "unknown"


# ── spl_to_sigma_dict: detection block ──────────────────────────────────────

def test_exact_match_in_selection():
    parsed = parse_spl('index=ad User="admin"', "t")
    sigma = spl_to_sigma_dict(parsed, "t")
    assert sigma["detection"]["selection"]["User"] == ["admin"]
    assert sigma["detection"]["condition"] == "selection"


def test_wildcard_contains():
    parsed = parse_spl('index=ad CommandLine="*mimikatz*"', "t")
    sigma = spl_to_sigma_dict(parsed, "t")
    sel = sigma["detection"]["selection"]
    assert "CommandLine|contains" in sel
    assert sel["CommandLine|contains"] == ["mimikatz"]


def test_wildcard_startswith():
    parsed = parse_spl('index=ad Image="C:\\Windows\\*"', "t")
    sigma = spl_to_sigma_dict(parsed, "t")
    sel = sigma["detection"]["selection"]
    assert any(k.startswith("Image|startswith") for k in sel)


def test_wildcard_endswith():
    parsed = parse_spl('index=ad Image="*\\powershell.exe"', "t")
    sigma = spl_to_sigma_dict(parsed, "t")
    sel = sigma["detection"]["selection"]
    assert any(k.startswith("Image|endswith") for k in sel)


def test_negation_becomes_filter():
    parsed = parse_spl('index=ad CommandLine="*foo*" User!="SYSTEM"', "t")
    sigma = spl_to_sigma_dict(parsed, "t")
    det = sigma["detection"]
    assert "filter" in det
    assert det["filter"]["User"] == ["SYSTEM"]
    assert det["condition"] == "selection and not filter"


def test_only_negation_placeholder_selection():
    parsed = parse_spl('index=ad User!="SYSTEM"', "t")
    sigma = spl_to_sigma_dict(parsed, "t")
    det = sigma["detection"]
    assert "_empty" in det["selection"]
    assert "filter" in det
    assert "not filter" in det["condition"]


def test_regex_condition_to_sigma():
    spl = 'index=ad | regex CommandLine="(invoke-mimikatz|mimikatz\\.exe)"'
    parsed = parse_spl(spl, "t")
    sigma = spl_to_sigma_dict(parsed, "t")
    sel = sigma["detection"]["selection"]
    assert any(k.endswith("|re") for k in sel)


def test_unknown_field_passes_through():
    parsed = parse_spl('index=c42 risk.severity="HIGH"', "t")
    sigma = spl_to_sigma_dict(parsed, "t")
    assert "risk.severity" in sigma["detection"]["selection"]


def test_spl_variant_dest_ip_mapped():
    parsed = parse_spl('index=ad dest_ip="10.0.0.1"', "t")
    sigma = spl_to_sigma_dict(parsed, "t")
    assert "DestinationIp" in sigma["detection"]["selection"]


def test_spl_variant_commandline_mapped():
    parsed = parse_spl('index=ad Command_Line="*pwsh*"', "t")
    sigma = spl_to_sigma_dict(parsed, "t")
    sel = sigma["detection"]["selection"]
    assert any("CommandLine" in k for k in sel)


def test_values_are_lists():
    """_build_selection_eql requires list values — verify spl_to_sigma_dict always produces them."""
    parsed = parse_spl('index=ad User="admin" CommandLine="*foo*"', "t")
    sigma = spl_to_sigma_dict(parsed, "t")
    det = sigma["detection"]
    for block_name, block in det.items():
        if block_name == "condition":
            continue
        assert isinstance(block, dict)
        for val in block.values():
            assert isinstance(val, list), f"{block_name} block has non-list value: {val!r}"


def test_multiple_values_same_field():
    """Two conditions on the same field accumulate in the same list."""
    parsed = parse_spl('index=ad User="admin" User="root"', "t")
    sigma = spl_to_sigma_dict(parsed, "t")
    assert len(sigma["detection"]["selection"]["User"]) == 2


# ── spl_to_sigma_yaml ───────────────────────────────────────────────────────

def test_yaml_has_title():
    parsed = parse_spl('index=ad CommandLine="*foo*"', "My Rule")
    yaml_str = spl_to_sigma_yaml(parsed, "My Rule")
    assert "title:" in yaml_str
    assert "My Rule" in yaml_str


def test_yaml_has_logsource():
    parsed = parse_spl('index=ad CommandLine="*foo*"', "t")
    yaml_str = spl_to_sigma_yaml(parsed, "t")
    assert "logsource:" in yaml_str
    assert "windows" in yaml_str


def test_yaml_has_detection():
    parsed = parse_spl('index=ad CommandLine="*mimikatz*"', "t")
    yaml_str = spl_to_sigma_yaml(parsed, "t")
    assert "detection:" in yaml_str
    assert "condition:" in yaml_str


def test_yaml_special_chars_quoted():
    parsed = parse_spl('index=ad User="admin:user"', "t")
    yaml_str = spl_to_sigma_yaml(parsed, "t")
    assert '"admin:user"' in yaml_str


# ── convert_spl_to_exa_rule: output shape ───────────────────────────────────

_REQUIRED_KEYS = {
    "name", "description", "severity", "index", "sourcetype",
    "activity_type_hint", "eql_query", "context_tables",
    "field_mappings", "dropped_stages", "warnings",
    "deploy_ready", "sigma_yaml",
}


def test_output_shape():
    rule = convert_spl_to_exa_rule("Test", 'index=ad CommandLine="*mimikatz*"')
    assert _REQUIRED_KEYS <= rule.keys()


def test_name_prefix():
    rule = convert_spl_to_exa_rule("Mimikatz", 'index=ad CommandLine="*mimikatz*"')
    assert rule["name"] == "[Splunk] Mimikatz"


def test_deploy_ready_always_needs_review():
    rule = convert_spl_to_exa_rule("Test", 'index=ad User="admin"')
    assert rule["deploy_ready"] == "Needs review"


def test_severity_always_medium():
    rule = convert_spl_to_exa_rule("Test", 'index=ad User="admin"')
    assert rule["severity"] == "medium"


def test_index_and_sourcetype_preserved():
    rule = convert_spl_to_exa_rule("Test", 'index=ad sourcetype=wineventlog EventID=4625')
    assert rule["index"] == "ad"
    assert rule["sourcetype"] == "wineventlog"


# ── convert_spl_to_exa_rule: EQL quality ────────────────────────────────────

def test_eql_has_activity_type_for_known_index():
    rule = convert_spl_to_exa_rule("Test", 'index=ad CommandLine="*mimikatz*"')
    assert 'activity_type:"process-create"' in rule["eql_query"]


def test_eql_commandline_maps_to_cim2_command():
    rule = convert_spl_to_exa_rule("Test", 'index=ad CommandLine="*mimikatz*"')
    # Sigma converter maps CommandLine → command (CIM2)
    assert "command" in rule["eql_query"]


def test_eql_user_maps_to_cim2_user():
    rule = convert_spl_to_exa_rule("Test", 'index=ad User="admin"')
    assert 'user:"admin"' in rule["eql_query"]


def test_eql_wildcard_becomes_wldi():
    rule = convert_spl_to_exa_rule("Test", 'index=ad CommandLine="*mimikatz*"')
    assert "WLDi" in rule["eql_query"]


def test_eql_negation_produces_not():
    rule = convert_spl_to_exa_rule("Test", 'index=ad CommandLine="*mimikatz*" User!="SYSTEM"')
    assert "NOT" in rule["eql_query"]


def test_eql_c42_fallback_activity_type():
    rule = convert_spl_to_exa_rule("Test", 'index=c42 risk.severity="HIGH"')
    # c42 has no Sigma category → falls back to source_map → file-write
    assert 'activity_type:"file-write"' in rule["eql_query"]


def test_eql_no_conditions_known_index_activity_type_only():
    """No field conditions but known index → activity_type-only EQL (not TODO)."""
    rule = convert_spl_to_exa_rule("Test", "index=ad | stats count by User")
    assert rule["eql_query"] == 'activity_type:"process-create"'


def test_eql_no_conditions_unknown_index_is_todo():
    """No field conditions and unknown index → TODO EQL."""
    rule = convert_spl_to_exa_rule("Test", "index=unknown | stats count by User")
    assert rule["eql_query"] == "/* TODO: manual EQL query required */"


# ── convert_spl_to_exa_rule: warnings ───────────────────────────────────────

def test_unknown_index_warning():
    rule = convert_spl_to_exa_rule("Test", 'index=unknown field=value')
    assert any("activity_type mapping" in w for w in rule["warnings"])


def test_dropped_stages_stats():
    rule = convert_spl_to_exa_rule("Test", 'index=ad CommandLine="foo" | stats count by User')
    assert "stats" in rule["dropped_stages"]
    assert any("Dropped" in w for w in rule["warnings"])


def test_dropped_stages_eval():
    rule = convert_spl_to_exa_rule("Test", 'index=ad User="admin" | eval x=1')
    assert "eval" in rule["dropped_stages"]


def test_spath_warning():
    rule = convert_spl_to_exa_rule("Test", 'index=ad User="admin" | spath output=x path=y')
    assert any("spath" in w.lower() for w in rule["warnings"])


def test_unknown_field_produces_unmapped_warning():
    rule = convert_spl_to_exa_rule("Test", 'index=c42 risk.severity="HIGH"')
    # Sigma converter emits "Unmapped field" for fields not in CIM2_FIELD_MAP
    assert any("risk.severity" in w or "Unmapped" in w for w in rule["warnings"])


# ── convert_spl_to_exa_rule: context tables & lookups ───────────────────────

def test_known_lookup_resolves_context_table():
    rule = convert_spl_to_exa_rule(
        "Test",
        'index=ad CommandLine="foo" | lookup sco_all_users_lookup.csv User OUTPUT vendor',
    )
    assert "Supply Chain Vendor Users" in rule["context_tables"]


def test_builtin_lookup_not_flagged():
    rule = convert_spl_to_exa_rule(
        "Test",
        'index=ad CommandLine="foo" | lookup dnslookup clientip as src_ip OUTPUT domain',
    )
    assert not rule["context_tables"]
    assert not any("dnslookup" in w for w in rule["warnings"])


def test_unknown_lookup_produces_warning():
    rule = convert_spl_to_exa_rule(
        "Test",
        'index=ad CommandLine="foo" | lookup my_custom_lookup.csv User OUTPUT dept',
    )
    assert any("my_custom_lookup" in w for w in rule["warnings"])


# ── convert_spl_to_exa_rule: sigma_yaml key ─────────────────────────────────

def test_sigma_yaml_present_and_non_empty():
    rule = convert_spl_to_exa_rule("Test", 'index=ad CommandLine="*foo*"')
    assert isinstance(rule["sigma_yaml"], str)
    assert "logsource:" in rule["sigma_yaml"]
    assert "detection:" in rule["sigma_yaml"]


def test_sigma_yaml_reflects_logsource():
    rule = convert_spl_to_exa_rule("Test", 'index=ad CommandLine="*foo*"')
    assert "windows" in rule["sigma_yaml"]
    assert "process_creation" in rule["sigma_yaml"]

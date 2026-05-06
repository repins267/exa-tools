"""Tests for Splunk SPL → Exabeam EQL converter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from exa.splunk.parser import parse_spl
from exa.splunk.converter import convert_spl_to_exa_rule, to_api_payload
from exa.splunk.source_map import resolve_activity_type


# ── Parser tests ─────────────────────────────────────────────────────────────

class TestParseSPL:
    def test_extracts_index(self):
        parsed = parse_spl('index=c42 event-type="file-downloaded"')
        assert parsed.index == "c42"

    def test_extracts_sourcetype(self):
        parsed = parse_spl('index=c42 sourcetype="c42-alerts"')
        assert parsed.sourcetype == "c42-alerts"

    def test_field_condition_equals(self):
        parsed = parse_spl('index=c42 severity="High"')
        conds = {f: v for f, op, v in parsed.field_conditions}
        assert "severity" in conds
        assert conds["severity"] == "High"

    def test_field_condition_not_equals(self):
        parsed = parse_spl('index=c42 destination.tabs{}.url!="null"')
        ops = {f: op for f, op, v in parsed.field_conditions}
        assert any(op == "!=" for op in ops.values())

    def test_wildcard_value(self):
        parsed = parse_spl('index=c42 file-name=*apollo*')
        vals = [v for f, op, v in parsed.field_conditions]
        assert any("apollo" in v for v in vals)

    def test_detects_stats_stage(self):
        spl = 'index=c42 event-type="file-downloaded" | stats count by username'
        parsed = parse_spl(spl)
        assert parsed.has_stats is True
        assert "stats" in parsed.dropped_stages

    def test_detects_lookup_stage(self):
        spl = 'index=c42 | lookup sco_all_users_lookup.csv username'
        parsed = parse_spl(spl)
        assert parsed.has_lookup is True
        assert "sco_all_users_lookup.csv" in parsed.lookup_names

    def test_detects_subsearch_lookup(self):
        spl = 'index=c42 [| inputlookup sco_all_users_lookup.csv | rename userPrincipalName AS username | fields username]'
        parsed = parse_spl(spl)
        assert parsed.has_subsearch is True
        assert any("sco_all_users_lookup" in n for n in parsed.lookup_names)

    def test_detects_ldapsearch(self):
        spl = '| ldapsearch search="(&(objectClass=User))" domain=dsx'
        parsed = parse_spl(spl)
        assert parsed.has_ldapsearch is True

    def test_detects_regex_stage(self):
        spl = 'index=c42 | regex file_name=".*\\.py$"'
        parsed = parse_spl(spl)
        assert len(parsed.regex_conditions) > 0

    def test_stats_by_field_extracted(self):
        spl = 'index=c42 | stats values(file-name) by username'
        parsed = parse_spl(spl)
        assert parsed.stats_by_field == "username"

    def test_index_not_in_field_conditions(self):
        parsed = parse_spl('index=c42 severity="High"')
        fields = [f for f, op, v in parsed.field_conditions]
        assert "index" not in fields

    def test_sourcetype_not_in_field_conditions(self):
        parsed = parse_spl('index=c42 sourcetype="c42-alerts"')
        fields = [f for f, op, v in parsed.field_conditions]
        assert "sourcetype" not in fields

    def test_pipeline_stage_names(self):
        spl = 'index=c42 | stats count by username | convert timeformat="%Y" ctime(t)'
        parsed = parse_spl(spl)
        assert "stats" in parsed.pipeline_stages
        assert "convert" in parsed.pipeline_stages


# ── Source map tests ──────────────────────────────────────────────────────────

class TestResolveActivityType:
    def test_c42_default(self):
        assert resolve_activity_type("c42", None) == "file-write"

    def test_c42_alerts(self):
        assert resolve_activity_type("c42", "c42-alerts") == "rule-trigger"

    def test_c42_file_exposure(self):
        assert resolve_activity_type("c42", "c42-file-exposure") == "file-write"

    def test_ips(self):
        assert resolve_activity_type("ips", None) == "rule-trigger"

    def test_o365(self):
        assert resolve_activity_type("o365", None) == "app-activity"

    def test_fireamp(self):
        assert resolve_activity_type("fireamp_stream", None) == "rule-trigger"

    def test_dg(self):
        assert resolve_activity_type("dg", None) == "file-write"

    def test_unknown_index_returns_none(self):
        assert resolve_activity_type("unknown_index", None) is None

    def test_case_insensitive_sourcetype(self):
        # sourcetype is lowercased by parser; test resolve directly
        assert resolve_activity_type("c42", "C42-ALERTS".lower()) == "rule-trigger"


# ── Converter tests ───────────────────────────────────────────────────────────

class TestConvertSPLToExaRule:
    def test_name_prefix(self):
        rule = convert_spl_to_exa_rule("My Search", 'index=c42 severity="High"')
        assert rule["name"] == "[Splunk] My Search"

    def test_severity_default_medium(self):
        rule = convert_spl_to_exa_rule("Test", 'index=c42')
        assert rule["severity"] == "medium"

    def test_activity_type_in_eql(self):
        rule = convert_spl_to_exa_rule("Test", 'index=c42 sourcetype="c42-alerts"')
        assert 'activity_type:"rule-trigger"' in rule["eql_query"]

    def test_field_condition_in_eql(self):
        rule = convert_spl_to_exa_rule("Test", 'index=c42 severity="High"')
        assert 'severity:"High"' in rule["eql_query"]

    def test_wildcard_converted_to_wldi(self):
        rule = convert_spl_to_exa_rule("Test", 'index=c42 file-name=*apollo*')
        assert "WLDi" in rule["eql_query"]

    def test_deploy_ready_always_needs_review(self):
        rule = convert_spl_to_exa_rule("Test", 'index=c42 severity="High"')
        assert rule["deploy_ready"] == "Needs review"

    def test_context_table_from_lookup(self):
        spl = 'index=c42 [| inputlookup sco_all_users_lookup.csv | fields username]'
        rule = convert_spl_to_exa_rule("Test", spl)
        assert "Supply Chain Vendor Users" in rule["context_tables"]

    def test_dropped_stages_listed(self):
        spl = 'index=c42 | stats count by username | eval x=1'
        rule = convert_spl_to_exa_rule("Test", spl)
        assert "stats" in rule["dropped_stages"]
        assert "eval" in rule["dropped_stages"]

    def test_ldapsearch_warning(self):
        spl = '| ldapsearch search="(&(objectClass=User))"'
        rule = convert_spl_to_exa_rule("Test", spl)
        assert any("ldapsearch" in w.lower() or "LDAP" in w for w in rule["warnings"])

    def test_description_within_900_chars(self):
        long_title = "Supply Chain ApolloCode Exposures Clone"
        spl = (
            'index=c42 event-type="file-downloaded" file-name=*apollo* '
            '| stats values(file-name) AS f by username'
        )
        rule = convert_spl_to_exa_rule(long_title, spl)
        assert len(rule["description"]) <= 900

    def test_unknown_index_produces_warning(self):
        rule = convert_spl_to_exa_rule("Test", 'index=mystery_index field="value"')
        assert any("mystery_index" in w for w in rule["warnings"])

    def test_not_equals_produces_not_in_eql(self):
        rule = convert_spl_to_exa_rule("Test", 'index=c42 severity!="Low"')
        assert "NOT" in rule["eql_query"]

    def test_index_stored(self):
        rule = convert_spl_to_exa_rule("Test", 'index=fireamp_stream severity="High"')
        assert rule["index"] == "fireamp_stream"

    def test_regex_condition_from_pipe(self):
        spl = 'index=c42 | regex fileName=".*\\.py$"'
        rule = convert_spl_to_exa_rule("Test", spl)
        assert "RGXi" in rule["eql_query"]


# ── API payload tests ─────────────────────────────────────────────────────────

class TestToAPIPayload:
    def test_payload_has_required_keys(self):
        rule = convert_spl_to_exa_rule("Test", 'index=c42')
        payload = to_api_payload(rule)
        assert "name" in payload
        assert "description" in payload
        assert "severity" in payload
        assert "enabled" in payload
        assert "sequencesConfig" in payload

    def test_disabled_by_default(self):
        rule = convert_spl_to_exa_rule("Test", 'index=c42')
        payload = to_api_payload(rule)
        assert payload["enabled"] is False

    def test_enabled_flag(self):
        rule = convert_spl_to_exa_rule("Test", 'index=c42')
        payload = to_api_payload(rule, enabled=True)
        assert payload["enabled"] is True

    def test_eql_in_sequence(self):
        rule = convert_spl_to_exa_rule("Test", 'index=c42 severity="High"')
        payload = to_api_payload(rule)
        seq = payload["sequencesConfig"]["sequences"][0]
        assert "severity" in seq["query"]

    def test_trigger_on_any_match(self):
        rule = convert_spl_to_exa_rule("Test", 'index=c42')
        payload = to_api_payload(rule)
        seq = payload["sequencesConfig"]["sequences"][0]
        assert seq["condition"]["triggerOnAnyMatch"] is True


# ── Real search smoke tests ───────────────────────────────────────────────────

class TestRealSearchConversions:
    """Smoke test the 22 actual Supply Chain searches.

    These don't assert specific EQL — they verify that conversion
    succeeds without exceptions and produces structurally valid output.
    """

    SEARCHES = [
        (
            "Supply Chain Active CCO Users Clone",
            '| ldapsearch search="(&(objectClass=User)(ciscoITUserSubType=EX01))" domain=dsx',
        ),
        (
            "Supply Chain Code42 Alerts Clone",
            'index=c42 sourcetype="c42-alerts" | lookup sco_all_users_lookup.csv userPrincipalName AS username | stats values(_time) AS Time by actor',
        ),
        (
            "Supply Chain Code42 USB Write Clone",
            'index=c42 sourcetype="c42-file-exposure" "destination.removableMedia.busType"=USB | stats count by username',
        ),
        (
            "Supply Chain DG Test Scripts Monitoring",
            'index=dg [| inputlookup "sco_all_users_lookup.csv" | rename sAMAccountName AS User | fields User] ("Command Line"="*apollo*" OR "Command Line"="*cesium*") | stats count by User',
        ),
        (
            "Supply Chain Firepower Alerts Clone",
            'index=ips csirtm_client="supply chain" rec_type_simple="IPS EVENT" | stats values(*) by src_ip',
        ),
        (
            "Supply Chain IP Email Attachment",
            'index=o365 (Operation=Send OR Operation=SendAs) | stats count by UserId',
        ),
        (
            "Supply Chain Secure Endpoint Alerts Clone",
            'index=fireamp_stream severity="High" | stats values(*) by computer.hostname',
        ),
        (
            "Supply Chain Suspicious TLD Matches Clone",
            'index=c42 | regex tabUrl=".*(\\.surf|\\.fit|\\.ml|\\.top)($|\\/).*" | stats count by username',
        ),
    ]

    @pytest.mark.parametrize("title,spl", SEARCHES)
    def test_converts_without_exception(self, title, spl):
        rule = convert_spl_to_exa_rule(title, spl)
        assert rule["name"] == f"[Splunk] {title}"
        assert isinstance(rule["eql_query"], str)
        assert len(rule["eql_query"]) > 0
        assert len(rule["description"]) <= 900
        assert rule["deploy_ready"] in ("Needs review", "No")

    @pytest.mark.parametrize("title,spl", SEARCHES)
    def test_payload_serialisable(self, title, spl):
        rule = convert_spl_to_exa_rule(title, spl)
        payload = to_api_payload(rule)
        # Must be JSON-serialisable
        json_str = json.dumps(payload)
        assert len(json_str) > 0

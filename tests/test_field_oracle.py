"""Tests for DS/ field oracle build and resolve_cim2_field()."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from exa.sigma.converter import (
    CIM2_FIELD_MAP,
    _check_oracle_confidence,
    resolve_cim2_field,
)
from exa.update import (
    _extract_activity_type,
    _parse_parser_file,
    build_field_oracle,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

DS_DIR = Path.home() / ".exa" / "cim2" / "DS"
_DS_AVAILABLE = DS_DIR.is_dir()

SYNTHETIC_ORACLE: dict[str, Any] = {
    "by_activity_type": {
        "process-create": {
            "process_name": ["Microsoft/Sysmon"],
            "process_command_line": ["Microsoft/Sysmon"],
            "user": ["Microsoft/Sysmon"],
            "parent_process_name": ["Microsoft/Sysmon"],
            "process_id": ["Microsoft/Sysmon"],
        },
        "file-write": {
            "file_name": ["Code42/Code42 Incydr"],
            "file_path": ["Code42/Code42 Incydr"],
            "file_category": ["Code42/Code42 Incydr"],
            "user": ["Code42/Code42 Incydr"],
        },
        "authentication": {
            "user": ["Microsoft/Windows Security"],
            "src_ip": ["Microsoft/Windows Security"],
            "logon_type": ["Microsoft/Windows Security"],
        },
    },
    "by_vendor": {
        "Microsoft": {
            "process-create": ["process_name", "process_command_line", "user"],
            "authentication": ["user", "src_ip", "logon_type"],
        },
        "Code42": {
            "file-write": ["file_name", "file_path", "file_category", "user"],
        },
    },
    "raw_to_cim2": {
        "computer.hostname": "src_host",
        "hostname": "src_host",
        "file.category": "file_category",
        "risk.severity": "alert_severity",
    },
    "built_at": "2026-01-01T00:00:00+00:00",
    "stats": {"parsers_processed": 10, "parsers_failed": 0},
}


# ---------------------------------------------------------------------------
# _extract_activity_type
# ---------------------------------------------------------------------------


class TestExtractActivityType:
    def test_process_create(self):
        assert _extract_activity_type("microsoft-sysmon-kv-process-create-success-create") == "process-create"

    def test_file_delete(self):
        assert _extract_activity_type("microsoft-sysmon-xml-file-delete-success-23") == "file-delete"

    def test_network_session(self):
        assert _extract_activity_type("cisco-asa-kv-network-session-success-1") == "network-session"

    def test_authentication(self):
        assert _extract_activity_type("microsoft-windows-kv-authentication-success-logon") == "authentication"

    def test_app_activity(self):
        assert _extract_activity_type("code42-incydr-sk4-app-activity-success-appclient") == "app-activity"

    def test_alert_trigger(self):
        assert _extract_activity_type("cisco-secureendpoint-cef-alert-trigger-success-detected") == "alert-trigger"

    def test_code42_file_succes_typo(self):
        # Code42's typo: "file-succes" (missing trailing s) → file-create
        assert _extract_activity_type("code42-incydr-json-file-succes-file") == "file-create"

    def test_unknown_returns_empty(self):
        assert _extract_activity_type("some-vendor-unknown-format-data") == ""

    def test_longest_match_takes_priority(self):
        # "web-activity-allowed" should win over bare "web-activity"
        assert _extract_activity_type("x-web-activity-allowed-y") == "web-activity-allowed"


# ---------------------------------------------------------------------------
# _parse_parser_file
# ---------------------------------------------------------------------------


SYSMON_PARSER_CONTENT = (
    "#### Parser Content\n"
    "```Java\n"
    "{\n"
    'Name = "microsoft-sysmon-kv-process-create-success-processcreate"\n'
    'Vendor = "Microsoft"\n'
    'Product = "Sysmon"\n'
    'TimeFormat = "yyyy-MM-dd HH:mm:ss"\n'
    "Conditions = [\n"
    '"""Microsoft-Windows-Sysmon""",\n'
    '"""Process Create:"""\n'
    "]\n"
    "Fields = [\n"
    '    """ProcessId:\\s*({process_id}\\d+)""",\n'
    '    """Image:\\s*({process_path}({process_dir}.*?[\\\\])?({process_name}.+?))\\s""",\n'
    '    """CommandLine:\\s*({process_command_line}.+?)\\s*CurrentDirectory:""",\n'
    '    """User=({user}[\\w\\.]+)""",\n'
    '    """exa_json_path=$.computer.hostname,exa_field_name=src_host""",\n'
    '    """exa_json_path=$.file.category,exa_field_name=file_category""",\n'
    "]\n"
    'ParserVersion = "v1.0.0"\n'
    "}\n"
    "```\n"
)


class TestParseParserFile:
    def test_extracts_name(self):
        result = _parse_parser_file(SYSMON_PARSER_CONTENT)
        assert result is not None
        assert result["name"] == "microsoft-sysmon-kv-process-create-success-processcreate"

    def test_extracts_vendor(self):
        result = _parse_parser_file(SYSMON_PARSER_CONTENT)
        assert result is not None
        assert result["vendor"] == "Microsoft"

    def test_extracts_product(self):
        result = _parse_parser_file(SYSMON_PARSER_CONTENT)
        assert result is not None
        assert result["product"] == "Sysmon"

    def test_extracts_activity_type(self):
        result = _parse_parser_file(SYSMON_PARSER_CONTENT)
        assert result is not None
        assert result["activity_type"] == "process-create"

    def test_extracts_cim2_fields(self):
        result = _parse_parser_file(SYSMON_PARSER_CONTENT)
        assert result is not None
        fields = result["cim2_fields"]
        assert "process_id" in fields
        assert "process_name" in fields
        assert "process_command_line" in fields
        assert "user" in fields

    def test_extracts_raw_to_cim2_full_path(self):
        result = _parse_parser_file(SYSMON_PARSER_CONTENT)
        assert result is not None
        rtc = result["raw_to_cim2"]
        assert rtc.get("computer.hostname") == "src_host"

    def test_extracts_raw_to_cim2_leaf(self):
        result = _parse_parser_file(SYSMON_PARSER_CONTENT)
        assert result is not None
        rtc = result["raw_to_cim2"]
        assert rtc.get("hostname") == "src_host"

    def test_returns_none_for_empty_content(self):
        assert _parse_parser_file("#### No parser here") is None

    def test_returns_none_for_missing_name(self):
        assert _parse_parser_file("```Java\n{ Vendor = X \n}\n```") is None

    def test_unquoted_name(self):
        content = "```Java\n{ Name = some-parser-name \n Vendor = X \n}\n```"
        result = _parse_parser_file(content)
        assert result is not None
        assert result["name"] == "some-parser-name"


# ---------------------------------------------------------------------------
# build_field_oracle — integration tests against real DS/ directory
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _DS_AVAILABLE, reason="~/.exa/cim2/DS/ not present")
class TestBuildFieldOracle:
    """Integration tests against real DS/ files.

    cache is written to tmp_path; DS files are read from the real location.
    """

    def test_creates_cache_file(self, tmp_path):
        result = build_field_oracle(data_dir=tmp_path, _ds_dir=DS_DIR)
        assert result.error == "", f"build_field_oracle failed: {result.error}"
        oracle_file = tmp_path / "cache" / "field_oracle.json"
        assert oracle_file.exists()

    def test_by_activity_type_populated(self, tmp_path):
        build_field_oracle(data_dir=tmp_path, _ds_dir=DS_DIR)
        oracle = json.loads((tmp_path / "cache" / "field_oracle.json").read_text())
        assert "process-create" in oracle["by_activity_type"]
        pc = oracle["by_activity_type"]["process-create"]
        assert "process_name" in pc, "process_name should be in process-create"
        assert "process_command_line" in pc

    def test_by_vendor_populated(self, tmp_path):
        build_field_oracle(data_dir=tmp_path, _ds_dir=DS_DIR)
        oracle = json.loads((tmp_path / "cache" / "field_oracle.json").read_text())
        assert "Microsoft" in oracle["by_vendor"]
        assert "CrowdStrike" in oracle["by_vendor"]

    def test_raw_to_cim2_populated(self, tmp_path):
        build_field_oracle(data_dir=tmp_path, _ds_dir=DS_DIR)
        oracle = json.loads((tmp_path / "cache" / "field_oracle.json").read_text())
        assert len(oracle["raw_to_cim2"]) > 0

    def test_stats_reasonable(self, tmp_path):
        build_field_oracle(data_dir=tmp_path, _ds_dir=DS_DIR)
        oracle = json.loads((tmp_path / "cache" / "field_oracle.json").read_text())
        stats = oracle["stats"]
        # Expect thousands of parsers processed
        assert stats["parsers_processed"] > 1000
        # Failure rate < 20%
        total = stats["parsers_processed"] + stats["parsers_failed"]
        assert stats["parsers_failed"] / total < 0.2

    def test_built_at_present(self, tmp_path):
        build_field_oracle(data_dir=tmp_path, _ds_dir=DS_DIR)
        oracle = json.loads((tmp_path / "cache" / "field_oracle.json").read_text())
        assert oracle["built_at"]

    def test_missing_ds_dir_returns_error(self, tmp_path):
        result = build_field_oracle(data_dir=tmp_path)
        assert result.error != ""
        assert "DS/" in result.error


# ---------------------------------------------------------------------------
# _check_oracle_confidence
# ---------------------------------------------------------------------------


class TestCheckOracleConfidence:
    def test_known_field_for_activity_type(self):
        conf = _check_oracle_confidence(SYNTHETIC_ORACLE, "process_name", "process-create", None)
        assert conf == "oracle"

    def test_known_field_wrong_activity_type_still_oracle(self):
        # process_name is in process-create; even if we query file-write it's "oracle"
        # because _check_oracle_confidence falls back to "any activity_type"
        conf = _check_oracle_confidence(SYNTHETIC_ORACLE, "process_name", "file-write", None)
        assert conf == "oracle"

    def test_field_not_in_oracle_is_schema(self):
        conf = _check_oracle_confidence(SYNTHETIC_ORACLE, "nonexistent_field_xyz", "process-create", None)
        assert conf == "schema"

    def test_no_activity_type_still_matches(self):
        conf = _check_oracle_confidence(SYNTHETIC_ORACLE, "file_name", None, None)
        assert conf == "oracle"


# ---------------------------------------------------------------------------
# resolve_cim2_field
# ---------------------------------------------------------------------------


class TestResolveCim2Field:
    def test_oracle_confidence_for_known_field(self):
        cim2, conf = resolve_cim2_field("Image", "process-create", _oracle=SYNTHETIC_ORACLE)
        assert cim2 == "process_name"
        assert conf == "oracle"

    def test_oracle_confidence_no_activity_type(self):
        cim2, conf = resolve_cim2_field("Image", _oracle=SYNTHETIC_ORACLE)
        assert cim2 == "process_name"
        assert conf == "oracle"

    def test_schema_confidence_when_oracle_missing_field(self):
        # registry_path is in CIM2_FIELD_MAP but not in SYNTHETIC_ORACLE
        assert "TargetObject" in CIM2_FIELD_MAP
        cim2, conf = resolve_cim2_field("TargetObject", _oracle=SYNTHETIC_ORACLE)
        assert cim2 == "registry_path"
        assert conf == "schema"

    def test_passthrough_for_unknown_field(self):
        cim2, conf = resolve_cim2_field("SomeUnknownSigmaField", _oracle=SYNTHETIC_ORACLE)
        assert cim2 == "SomeUnknownSigmaField"
        assert conf == "passthrough"

    def test_oracle_absent_known_field_returns_schema(self):
        cim2, conf = resolve_cim2_field("Image", _oracle=None)
        assert cim2 == "process_name"
        assert conf == "schema"

    def test_oracle_absent_unknown_field_returns_passthrough(self):
        cim2, conf = resolve_cim2_field("UnknownXYZ", _oracle=None)
        assert cim2 == "UnknownXYZ"
        assert conf == "passthrough"

    def test_raw_to_cim2_lookup(self):
        # "computer.hostname" is in SYNTHETIC_ORACLE raw_to_cim2
        cim2, conf = resolve_cim2_field("computer.hostname", _oracle=SYNTHETIC_ORACLE)
        assert cim2 == "src_host"
        assert conf == "oracle"

    def test_raw_to_cim2_leaf_lookup(self):
        # "hostname" (leaf) also maps via raw_to_cim2
        cim2, conf = resolve_cim2_field("hostname", _oracle=SYNTHETIC_ORACLE)
        assert cim2 == "src_host"
        assert conf == "oracle"

    def test_modifier_stripped_before_lookup(self):
        # "Image|contains" should be treated as "Image"
        cim2, conf = resolve_cim2_field("Image|contains", _oracle=SYNTHETIC_ORACLE)
        assert cim2 == "process_name"
        assert conf == "oracle"

    def test_user_field_oracle(self):
        cim2, conf = resolve_cim2_field("User", "authentication", _oracle=SYNTHETIC_ORACLE)
        assert cim2 == "user"
        assert conf == "oracle"

    def test_logon_type_in_auth(self):
        cim2, conf = resolve_cim2_field("LogonType", "authentication", _oracle=SYNTHETIC_ORACLE)
        assert cim2 == "logon_type"
        assert conf == "oracle"

    def test_graceful_fallback_no_oracle_file(self, monkeypatch, tmp_path):
        """resolve_cim2_field() must not fail if oracle file is absent."""
        import exa.sigma.converter as conv

        original = conv._load_field_oracle

        def _no_oracle():
            return None

        monkeypatch.setattr(conv, "_load_field_oracle", _no_oracle)
        # Should still work via CIM2_FIELD_MAP
        cim2, conf = resolve_cim2_field("Image")
        assert cim2 == "process_name"
        assert conf == "schema"
        monkeypatch.setattr(conv, "_load_field_oracle", original)

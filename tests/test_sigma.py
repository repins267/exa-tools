"""Tests for Sigma parser and converter."""

import pytest

from exa.exceptions import SigmaConversionError
from exa.sigma.converter import (
    CIM2_FIELD_MAP,
    LOGSOURCE_ACTIVITY_MAP,
    _build_field_condition,
    convert_to_exa_rule,
)


class TestProcessCreateActivityType:
    def test_process_creation_maps_to_process_create(self):
        """BUG FIX: process_creation must map to 'process-create', not 'process-created'."""
        assert LOGSOURCE_ACTIVITY_MAP["process_creation"] == "process-create"

    def test_converted_rule_uses_correct_activity_type(self):
        """End-to-end: converted process_creation rule has correct activity_type."""
        sigma = {
            "title": "Test Process Rule",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {"CommandLine|contains": "powershell"},
                "condition": "selection",
            },
            "level": "medium",
        }
        result = convert_to_exa_rule(sigma)
        assert 'activity_type:"process-create"' in result["eql_query"]
        assert "process-created" not in result["eql_query"]


class TestMissingSelectionRaises:
    def test_unmatched_selection_raises_sigma_error(self):
        """Unmatched selection name in condition raises SigmaConversionError."""
        sigma = {
            "title": "Bad Condition Rule",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection_exists": {"CommandLine": "cmd.exe"},
                "condition": "selection_exists and filter_missing",
            },
            "level": "high",
        }
        with pytest.raises(SigmaConversionError, match="filter_missing"):
            convert_to_exa_rule(sigma)

    def test_unmatched_selection_includes_rule_title(self):
        """Error message includes the rule title for context."""
        sigma = {
            "title": "My Specific Rule",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_a": {"Image": "cmd.exe"},
                "condition": "selection_a and selection_nonexistent",
            },
            "level": "medium",
        }
        with pytest.raises(SigmaConversionError, match="My Specific Rule"):
            convert_to_exa_rule(sigma)


class TestProxyFieldMappings:
    def test_c_uri_maps_to_url(self):
        assert CIM2_FIELD_MAP["c-uri"] == "url"

    def test_cs_uri_stem_maps_to_uri_path(self):
        # uri_path verified in new-scale-content-hub correlation rules
        assert CIM2_FIELD_MAP["cs-uri-stem"] == "uri_path"

    def test_r_dns_maps_to_web_domain(self):
        assert CIM2_FIELD_MAP["r-dns"] == "web_domain"

    def test_proxy_fields_in_converted_rule(self):
        """Proxy fields produce correct EQL."""
        sigma = {
            "title": "Proxy Test",
            "logsource": {"category": "proxy"},
            "detection": {
                "selection": {
                    "c-uri|contains": "/malicious",
                    "r-dns": "evil.com",
                },
                "condition": "selection",
            },
            "level": "high",
        }
        result = convert_to_exa_rule(sigma)
        assert "url:" in result["eql_query"]
        assert 'web_domain:"evil.com"' in result["eql_query"]


class TestUnsupportedModifierWarning:
    def test_wide_modifier_emits_warning(self):
        """Unsupported 'wide' modifier emits a warning."""
        warnings: list[str] = []
        _build_field_condition(
            "command", "wide", ["test"],
            sigma_field="CommandLine|wide", warnings=warnings,
        )
        assert len(warnings) == 1
        assert "wide" in warnings[0]
        assert "EQL may be incomplete" in warnings[0]

    def test_base64_modifier_emits_warning(self):
        """Unsupported 'base64' modifier emits a warning."""
        warnings: list[str] = []
        _build_field_condition(
            "command", "base64", ["test"],
            sigma_field="CommandLine|base64", warnings=warnings,
        )
        assert len(warnings) == 1
        assert "base64" in warnings[0]

    def test_unsupported_modifier_still_converts(self):
        """Unsupported modifiers fall back to exact match, not hard fail."""
        warnings: list[str] = []
        result = _build_field_condition(
            "command", "wide", ["test"],
            sigma_field="CommandLine|wide", warnings=warnings,
        )
        # Should produce an exact-match EQL, not crash
        assert 'command:"test"' == result

    def test_unsupported_modifier_in_full_conversion(self):
        """End-to-end: unsupported modifier produces warning in rule output."""
        sigma = {
            "title": "Wide Modifier Rule",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|wide": "encoded"},
                "condition": "selection",
            },
            "level": "medium",
        }
        result = convert_to_exa_rule(sigma)
        assert any("wide" in w for w in result["warnings"])

    def test_supported_modifiers_no_warning(self):
        """Supported modifiers (contains, endswith, etc.) do NOT emit warnings."""
        for mod in ["contains", "endswith", "startswith", "re"]:
            warnings: list[str] = []
            _build_field_condition(
                "command", mod, ["test"],
                sigma_field=f"CommandLine|{mod}", warnings=warnings,
            )
            assert len(warnings) == 0, f"Unexpected warning for modifier '{mod}'"

    def test_all_modifier_uses_and(self):
        """The 'all' modifier joins values with AND instead of OR."""
        warnings: list[str] = []
        result = _build_field_condition(
            "command", "all", ["val1", "val2"],
            sigma_field="CommandLine|all", warnings=warnings,
        )
        assert " AND " in result
        assert " OR " not in result
        assert len(warnings) == 0  # 'all' is supported, no warning


class TestWildcardRegexEscaping:
    r"""WLDi() globs are regex-compiled backend-side, so literal regex
    metacharacters in the Sigma value must be escaped by the converter.

    Verified against sademodev22 2026-07-31: a pattern built from the literal
    text '\WINDOWS\system32' returned 0 hits against data that provably
    contains it, while the doubled-backslash form returned the full sample.
    """

    def test_backslash_is_doubled_in_endswith(self):
        r"""Sigma paths like '\netsh.exe' must not become a regex escape."""
        result = _build_field_condition(
            "process_name", "endswith", [r"\netsh.exe"],
            sigma_field="Image|endswith", warnings=[],
        )
        # Two literal backslashes reach the backend regex as one literal '\'.
        assert result == 'process_name:WLDi("*' + "\\\\" + 'netsh.exe")'

    def test_backslash_doubled_for_all_wildcard_modifiers(self):
        bs2 = "\\\\"  # two literal backslashes
        for mod, expected in [
            ("endswith", f'process_name:WLDi("*{bs2}powershell.exe")'),
            ("startswith", f'process_name:WLDi("{bs2}powershell.exe*")'),
            ("contains", f'process_name:WLDi("*{bs2}powershell.exe*")'),
        ]:
            result = _build_field_condition(
                "process_name", mod, [r"\powershell.exe"],
                sigma_field=f"Image|{mod}", warnings=[],
            )
            assert result == expected, f"{mod}: got {result}"

    def test_regex_metacharacters_escaped(self):
        """Parens/brackets/braces otherwise fail regex compilation entirely."""
        result = _build_field_condition(
            "process_command_line", "contains", ["foo(bar)[baz]{1}+?^$|"],
            sigma_field="CommandLine|contains", warnings=[],
        )
        for ch in "()[]{}+?^$|":
            assert "\\" + ch in result, f"{ch!r} not escaped in {result}"

    def test_dot_and_star_not_escaped(self):
        """'.' is escaped backend-side and '*' is the intended wildcard."""
        result = _build_field_condition(
            "process_name", "endswith", [r"\vssadmin.exe"],
            sigma_field="Image|endswith", warnings=[],
        )
        assert r"\." not in result
        assert result.startswith('process_name:WLDi("*')

    def test_regex_modifier_value_not_escaped(self):
        """RGXi() values are intentional regexes — escaping would break them."""
        result = _build_field_condition(
            "process_command_line", "re", [r"\d+\.exe"],
            sigma_field="CommandLine|re", warnings=[],
        )
        assert result == r'process_command_line:RGXi("\d+\.exe")'

    def test_exact_match_value_not_escaped(self):
        """Exact match is a literal term match backend-side, not a regex."""
        result = _build_field_condition(
            "process_name", None, [r"C:\Windows\netsh.exe"],
            sigma_field="Image", warnings=[],
        )
        assert result == r'process_name:"C:\Windows\netsh.exe"'

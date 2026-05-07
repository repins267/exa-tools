"""Tests for exa/update.py — reference data pipeline."""

import json
from unittest.mock import patch

import pytest

from exa.exceptions import ExaConfigError
from exa.update import (
    _cache_parsed_data,
    _parse_md_table,
    load_cim2_cache,
    update_reference_data,
)


@pytest.fixture()
def data_dir(tmp_path):
    """Isolated data directory."""
    return tmp_path / ".exa"


class TestUpdateClonesRepos:
    def test_clone_called_when_no_dir(self, data_dir):
        """git clone is called when repo directory does not exist."""
        clone_calls: list[str] = []
        pull_calls: list[str] = []

        def mock_clone(repo_url, target_dir):
            clone_calls.append(repo_url)
            target_dir.mkdir(parents=True, exist_ok=True)
            (target_dir / ".git").mkdir()
            return ""

        def mock_pull(repo_dir):
            pull_calls.append(str(repo_dir))
            return ""

        def mock_sha(repo_dir):
            return "abc123def456"

        with (
            patch("exa.update._git_clone", side_effect=mock_clone),
            patch("exa.update._git_pull", side_effect=mock_pull),
            patch("exa.update._git_head_sha", return_value="abc123def456"),
            patch("exa.update._DATA_DIR", data_dir),
        ):
            result = update_reference_data(data_dir=data_dir)

        assert len(clone_calls) == 4  # CIM2 + content-hub + sigma + aillm-domains
        assert len(pull_calls) == 0
        assert result.cim2_action == "cloned"
        assert result.content_hub_action == "cloned"
        assert result.sigma_action == "cloned"
        assert result.aillm_domains_action == "cloned"


class TestUpdatePullsExisting:
    def test_pull_called_when_dir_exists(self, data_dir):
        """git pull is called when repo directory already exists."""
        # Create fake existing repos
        cim2_dir = data_dir / "cim2"
        cim2_dir.mkdir(parents=True)
        (cim2_dir / ".git").mkdir()

        hub_dir = data_dir / "content-hub"
        hub_dir.mkdir(parents=True)
        (hub_dir / ".git").mkdir()

        sigma_dir = data_dir / "sigma"
        sigma_dir.mkdir(parents=True)
        (sigma_dir / ".git").mkdir()

        aillm_dir = data_dir / "aillm-domains"
        aillm_dir.mkdir(parents=True)
        (aillm_dir / ".git").mkdir()

        pull_calls: list[str] = []

        def mock_pull(repo_dir):
            pull_calls.append(str(repo_dir))
            return ""

        with (
            patch("exa.update._git_pull", side_effect=mock_pull),
            patch("exa.update._git_head_sha", return_value="def456abc123"),
        ):
            result = update_reference_data(data_dir=data_dir)

        assert len(pull_calls) == 4  # CIM2 + content-hub + sigma + aillm-domains
        assert result.cim2_action == "pulled"
        assert result.content_hub_action == "pulled"
        assert result.sigma_action == "pulled"
        assert result.aillm_domains_action == "pulled"


class TestLoadCacheMissing:
    def test_raises_config_error(self, data_dir):
        """ExaConfigError raised when cache file does not exist."""
        with pytest.raises(ExaConfigError, match="Run 'exa update' first"):
            load_cim2_cache("data_sources", data_dir=data_dir)

    def test_error_includes_cache_name(self, data_dir):
        """Error message includes the cache name."""
        with pytest.raises(ExaConfigError, match="mitre_map"):
            load_cim2_cache("mitre_map", data_dir=data_dir)


class TestConverterUsesCache:
    def test_known_activity_type_no_warning(self):
        """Known activity_type (from bundled set) produces no warning."""
        from exa.sigma.converter import convert_to_exa_rule

        sigma = {
            "title": "Auth Test",
            "logsource": {"category": "authentication"},
            "detection": {
                "selection": {"User": "admin"},
                "condition": "selection",
            },
            "level": "medium",
        }
        result = convert_to_exa_rule(sigma)
        activity_warnings = [
            w for w in result["warnings"] if "activity_type" in w
        ]
        assert len(activity_warnings) == 0
        assert 'activity_type:"authentication"' in result["eql_query"]

    def test_unknown_activity_type_warns(self):
        """Unknown activity_type emits a warning."""
        from exa.sigma.converter import (
            LOGSOURCE_ACTIVITY_MAP,
            convert_to_exa_rule,
        )

        # Temporarily add a bogus mapping
        original = LOGSOURCE_ACTIVITY_MAP.get("test_bogus")
        LOGSOURCE_ACTIVITY_MAP["test_bogus"] = "bogus-activity-xyz"
        try:
            sigma = {
                "title": "Bogus Test",
                "logsource": {"category": "test_bogus"},
                "detection": {
                    "selection": {"User": "admin"},
                    "condition": "selection",
                },
                "level": "medium",
            }
            result = convert_to_exa_rule(sigma)
            activity_warnings = [
                w for w in result["warnings"]
                if "bogus-activity-xyz" in w
            ]
            assert len(activity_warnings) == 1
            assert "not found in CIM2" in activity_warnings[0]
        finally:
            if original is None:
                del LOGSOURCE_ACTIVITY_MAP["test_bogus"]
            else:
                LOGSOURCE_ACTIVITY_MAP["test_bogus"] = original


class TestConverterFallsBackToBundle:
    def test_fallback_when_cache_missing(self):
        """Converter works without cache — uses bundled snapshot."""
        from exa.sigma.converter import _load_known_activity_types

        # Even without any cache, should return the bundled set
        known = _load_known_activity_types()
        assert "process-create" in known
        assert "authentication" in known
        assert "dns-query" in known
        assert len(known) >= 18  # At least the bundled count

    def test_cache_augments_bundled(self, tmp_path):
        """Cache adds to bundled set, doesn't replace it."""
        # Create a fake cache with extra activity types
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        cache_file = cache_dir / "activity_types.json"
        cache_file.write_text(
            json.dumps(["custom-activity-1", "custom-activity-2"]),
        )

        with patch("exa.update._DATA_DIR", tmp_path):
            from exa.sigma.converter import _load_known_activity_types

            known = _load_known_activity_types()

        # Should have both bundled AND cached
        assert "process-create" in known  # bundled
        assert "custom-activity-1" in known  # from cache
        assert "custom-activity-2" in known  # from cache


class TestMdTableParser:
    def test_simple_table(self):
        """Parses a simple markdown table."""
        md = """\
| Name | Value |
| --- | --- |
| foo | bar |
| baz | qux |
"""
        rows = _parse_md_table(md)
        assert len(rows) == 2
        assert rows[0]["Name"] == "foo"
        assert rows[1]["Value"] == "qux"

    def test_empty_table(self):
        """Returns empty list for no table."""
        assert _parse_md_table("Just some text\nNo table here") == []


class TestCacheParsedData:
    def test_writes_json_cache(self, tmp_path):
        """Parsed data is written as JSON to cache dir."""
        cim2_dir = tmp_path / "cim2"
        cim2_dir.mkdir()

        # Create a minimal data sources file
        ds_file = cim2_dir / "Exabeam Data Sources.md"
        ds_file.write_text("""\
Exabeam Data Sources
====================

| Vendor | Product |
| --- | --- |
| TestVendor | [TestProduct](link) |
""")

        cache_dir = tmp_path / "cache"
        results = _cache_parsed_data(cim2_dir, cache_dir)

        ds_result = next(r for r in results if r.name == "data_sources")
        assert ds_result.records == 1
        assert ds_result.error == ""

        cache_file = cache_dir / "data_sources.json"
        assert cache_file.exists()
        data = json.loads(cache_file.read_text())
        assert data[0]["vendor"] == "TestVendor"
        assert data[0]["product"] == "TestProduct"

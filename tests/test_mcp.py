"""Tests for exa mcp config generation, install logic, and tool definitions."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------


class TestGenerateConfig:
    def test_structure(self):
        from exa.cli.mcp import _generate_config

        cfg = _generate_config(tenant="sademodev22", server_name="exabeam")
        assert "mcpServers" in cfg
        assert "exabeam" in cfg["mcpServers"]
        server = cfg["mcpServers"]["exabeam"]
        assert "command" in server
        assert isinstance(server["args"], list)

    def test_tenant_in_args(self):
        from exa.cli.mcp import _generate_config

        cfg = _generate_config(tenant="sademodev22", server_name="exabeam")
        args = cfg["mcpServers"]["exabeam"]["args"]
        assert "--tenant" in args
        assert "sademodev22" in args

    def test_no_tenant_omits_flag(self):
        from exa.cli.mcp import _generate_config

        cfg = _generate_config(tenant=None, server_name="exabeam")
        args = cfg["mcpServers"]["exabeam"]["args"]
        assert "--tenant" not in args

    def test_custom_server_name_in_key_and_args(self):
        from exa.cli.mcp import _generate_config

        cfg = _generate_config(tenant=None, server_name="my-exa")
        assert "my-exa" in cfg["mcpServers"]
        args = cfg["mcpServers"]["my-exa"]["args"]
        assert "--name" in args
        assert "my-exa" in args

    def test_default_name_not_repeated_in_args(self):
        from exa.cli.mcp import _generate_config

        cfg = _generate_config(tenant=None, server_name="exabeam")
        args = cfg["mcpServers"]["exabeam"]["args"]
        assert "--name" not in args

    def test_docs_config_structure(self):
        from exa.cli.mcp import _generate_docs_config

        cfg = _generate_docs_config()
        assert "mcpServers" in cfg
        server = list(cfg["mcpServers"].values())[0]
        assert server.get("url") == "https://developers.exabeam.com/mcp"
        assert server.get("transport") == "sse"

    def test_docs_config_default_name(self):
        from exa.cli.mcp import _generate_docs_config

        cfg = _generate_docs_config()
        assert "exabeam-docs" in cfg["mcpServers"]


# ---------------------------------------------------------------------------
# Install / merge logic
# ---------------------------------------------------------------------------


class TestInstallConfig:
    def test_merge_preserves_other_servers(self, tmp_path: Path):
        from exa.cli.mcp import _install_config

        config_path = tmp_path / "config.json"
        existing = {"mcpServers": {"other": {"command": "other-cmd", "args": []}}}
        config_path.write_text(json.dumps(existing))

        _install_config("exabeam", {"command": "exa", "args": ["mcp", "serve"]}, config_path)

        result = json.loads(config_path.read_text())
        assert "other" in result["mcpServers"]
        assert "exabeam" in result["mcpServers"]

    def test_creates_file_and_parent_dirs_if_missing(self, tmp_path: Path):
        from exa.cli.mcp import _install_config

        config_path = tmp_path / "Claude" / "config.json"
        assert not config_path.exists()

        _install_config("exabeam", {"command": "exa", "args": []}, config_path)

        assert config_path.exists()
        result = json.loads(config_path.read_text())
        assert "exabeam" in result["mcpServers"]

    def test_overwrites_existing_server_entry(self, tmp_path: Path):
        from exa.cli.mcp import _install_config

        config_path = tmp_path / "config.json"
        existing = {"mcpServers": {"exabeam": {"command": "old-cmd", "args": []}}}
        config_path.write_text(json.dumps(existing))

        _install_config("exabeam", {"command": "new-cmd", "args": ["mcp"]}, config_path)

        result = json.loads(config_path.read_text())
        assert result["mcpServers"]["exabeam"]["command"] == "new-cmd"

    def test_handles_corrupted_json(self, tmp_path: Path):
        from exa.cli.mcp import _install_config

        config_path = tmp_path / "config.json"
        config_path.write_text("not valid json{{")

        _install_config("exabeam", {"command": "exa", "args": []}, config_path)

        result = json.loads(config_path.read_text())
        assert "exabeam" in result["mcpServers"]

    def test_output_is_valid_json(self, tmp_path: Path):
        from exa.cli.mcp import _install_config

        config_path = tmp_path / "config.json"
        _install_config("exabeam", {"command": "x", "args": ["a", "b"]}, config_path)

        content = config_path.read_text()
        parsed = json.loads(content)
        assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


WRITE_TOOLS = {"create_case", "update_case", "update_alert", "add_case_note"}

READ_TOOLS = {
    "search_alerts",
    "get_alert",
    "search_cases",
    "get_case",
    "search_events",
    "get_license_consumption",
    "get_app_status",
    "list_collectors",
    "aillm_sources",
    "aillm_validate",
    "aillm_rules",
    "aillm_risk",
    "aillm_gaps",
    "list_detection_rules",
}


class TestToolDefs:
    def test_all_tools_have_required_fields(self):
        from exa.mcp.tools import TOOL_DEFS

        for tool in TOOL_DEFS:
            assert tool.name, f"Tool missing name"
            assert tool.description, f"Tool {tool.name} missing description"
            assert tool.inputSchema, f"Tool {tool.name} missing inputSchema"
            assert isinstance(tool.inputSchema.get("properties"), dict), (
                f"Tool {tool.name} inputSchema.properties must be a dict"
            )

    def test_write_tools_include_approval_warning(self):
        from exa.mcp.tools import TOOL_DEFS

        write_tools = {"create_case", "update_case", "update_alert", "add_case_note"}
        for tool in TOOL_DEFS:
            if tool.name in write_tools:
                assert "MODIFIES LIVE DATA" in tool.description, (
                    f"Write tool {tool.name} missing approval warning in description"
                )

    def test_expected_tool_set(self):
        from exa.mcp.tools import TOOL_DEFS

        names = {t.name for t in TOOL_DEFS}
        assert names == WRITE_TOOLS | READ_TOOLS

    def test_every_tool_has_a_dispatch_case(self):
        """A tool advertised with no handler fails only when someone calls it.

        The client lists it, the model picks it, and the call returns "Unknown
        tool" at runtime -- so the gap shows up in front of a user rather than
        in CI. Pin the two lists together instead.
        """
        import re
        from pathlib import Path

        from exa.mcp.tools import TOOL_DEFS

        source = Path("exa/mcp/tools.py").read_text(encoding="utf-8")
        cases = set(re.findall(r'case "([a-z_]+)":', source))
        names = {t.name for t in TOOL_DEFS}
        assert names - cases == set(), f"advertised with no handler: {names - cases}"
        assert cases - names == set(), f"handler with no tool: {cases - names}"

    def test_read_tools_not_marked_as_write(self):
        """Derived from WRITE_TOOLS, not a second hand-maintained list.

        The previous version named the five read tools explicitly, so a newly
        added read tool was simply not checked -- the assertion silently covered
        less over time.
        """
        from exa.mcp.tools import TOOL_DEFS

        for tool in TOOL_DEFS:
            if tool.name not in WRITE_TOOLS:
                assert "MODIFIES LIVE DATA" not in tool.description, (
                    f"Read tool {tool.name} should not carry the write warning"
                )

    def test_write_gate_is_imperative_and_honest(self):
        """The gate must instruct the model, and admit it is soft.

        "requires human approval" states a fact about the world. In Claude
        Desktop there is no harness rule behind it, so the wording has to tell
        the model to stop and wait, and say plainly that this is the only lock.
        """
        from exa.mcp.tools import TOOL_DEFS

        for tool in TOOL_DEFS:
            if tool.name in WRITE_TOOLS:
                d = tool.description
                assert "STOP and ask" in d, f"{tool.name} gate is not imperative"
                assert "SOFT gate" in d, f"{tool.name} does not admit it is soft"


# ---------------------------------------------------------------------------
# dispatch_tool
# ---------------------------------------------------------------------------


class TestDispatchTool:
    def test_unknown_tool_returns_error(self):
        from exa.mcp.tools import dispatch_tool

        mock_client = MagicMock()
        result = asyncio.run(dispatch_tool(mock_client, "nonexistent_tool", {}))
        assert len(result) == 1
        payload = json.loads(result[0].text)
        assert "error" in payload
        assert "nonexistent_tool" in payload["error"]

    def test_search_alerts_calls_correct_function(self):
        from exa.mcp.tools import dispatch_tool
        from unittest.mock import patch

        mock_client = MagicMock()
        fake_rows = [{"alertId": "abc", "priority": "HIGH"}]

        with patch("exa.case.alerts.search_alerts", return_value=fake_rows) as mock_fn:
            result = asyncio.run(
                dispatch_tool(mock_client, "search_alerts", {"filter": 'priority:"HIGH"', "lookback_days": 3})
            )

        mock_fn.assert_called_once_with(
            mock_client,
            filter='priority:"HIGH"',
            lookback_days=3,
            limit=50,
        )
        payload = json.loads(result[0].text)
        assert payload == fake_rows

    def test_search_cases_calls_correct_function(self):
        from exa.mcp.tools import dispatch_tool
        from unittest.mock import patch

        mock_client = MagicMock()
        fake_rows = [{"caseId": "xyz", "stage": "OPEN"}]

        with patch("exa.case.cases.search_cases", return_value=fake_rows):
            result = asyncio.run(
                dispatch_tool(mock_client, "search_cases", {"lookback_days": 14})
            )

        payload = json.loads(result[0].text)
        assert payload == fake_rows

    def test_exception_in_tool_returns_error(self):
        from exa.mcp.tools import dispatch_tool
        from unittest.mock import patch

        mock_client = MagicMock()

        with patch("exa.case.alerts.search_alerts", side_effect=RuntimeError("boom")):
            result = asyncio.run(
                dispatch_tool(mock_client, "search_alerts", {})
            )

        payload = json.loads(result[0].text)
        assert "error" in payload
        assert "boom" in payload["error"]

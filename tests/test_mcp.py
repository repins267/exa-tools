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

        # native form is explicit; the default is machine-dependent (3p vs classic)
        cfg = _generate_docs_config(proxy=False)
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
    "get_active_tenant",
    "list_tenants",
    "set_active_tenant",
    "set_tenant_kind",
    "parser_health",
    "render_report",
    "ingest_value",
    "source_detail",
    "render_dashboard",
    "ai_domain_lookup",
    "soc_kpis",
    "tuning_report",
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


# ---------------------------------------------------------------------------
# Read-only / --allow-writes hard gate
# ---------------------------------------------------------------------------


class TestReadOnlyGate:
    def test_visible_tools_hides_writes_when_read_only(self):
        from exa.mcp.tools import visible_tools

        names = {t.name for t in visible_tools(read_only=True)}
        assert names & WRITE_TOOLS == set(), "write tools must not be advertised read-only"
        assert names == READ_TOOLS

    def test_visible_tools_includes_writes_when_allowed(self):
        from exa.mcp.tools import visible_tools

        names = {t.name for t in visible_tools(read_only=False)}
        assert names == WRITE_TOOLS | READ_TOOLS

    @pytest.mark.parametrize("tool", sorted(WRITE_TOOLS))
    def test_dispatch_refuses_writes_in_read_only(self, tool):
        from exa.mcp.tools import dispatch_tool

        mock_client = MagicMock()
        result = asyncio.run(
            dispatch_tool(mock_client, tool, {}, read_only=True)
        )
        payload = json.loads(result[0].text)
        assert "error" in payload
        assert "read-only" in payload["error"].lower()
        # The refusal must short-circuit before touching the client at all.
        mock_client.post.assert_not_called()
        mock_client.get.assert_not_called()

    def test_dispatch_allows_writes_when_not_read_only(self):
        """With writes enabled the gate does not fire -- the call reaches the tool.

        add_case_note posts directly via the client, so a stubbed post proves the
        guard let it through rather than refusing.
        """
        from exa.mcp.tools import dispatch_tool

        mock_client = MagicMock()
        mock_client.post.return_value = {"noteId": "n1"}
        result = asyncio.run(
            dispatch_tool(
                mock_client,
                "add_case_note",
                {"case_id": "c1", "content": "hello"},
                read_only=False,
            )
        )
        mock_client.post.assert_called_once()
        payload = json.loads(result[0].text)
        assert payload == {"noteId": "n1"}

    def test_read_tool_works_in_read_only(self):
        from exa.mcp.tools import dispatch_tool
        from unittest.mock import patch

        mock_client = MagicMock()
        with patch("exa.case.alerts.search_alerts", return_value=[{"alertId": "a"}]):
            result = asyncio.run(
                dispatch_tool(mock_client, "search_alerts", {}, read_only=True)
            )
        payload = json.loads(result[0].text)
        assert payload == [{"alertId": "a"}]


class TestGenerateConfigAllowWrites:
    def test_read_only_by_default_omits_flag(self):
        from exa.cli.mcp import _generate_config

        args = _generate_config(tenant="sademodev22", server_name="exabeam")[
            "mcpServers"
        ]["exabeam"]["args"]
        assert "--allow-writes" not in args

    def test_allow_writes_adds_flag(self):
        from exa.cli.mcp import _generate_config

        args = _generate_config(
            tenant="sademodev22", server_name="exabeam", allow_writes=True
        )["mcpServers"]["exabeam"]["args"]
        assert "--allow-writes" in args



# ---------------------------------------------------------------------------
# Tenant awareness / switching tools
# ---------------------------------------------------------------------------


class _FakeClient:
    def __init__(self, tenant, base_url="https://api.us-west.exabeam.cloud", exp=0.0):
        self.tenant = tenant
        self.base_url = base_url
        self._expires_at = exp

    def close(self):
        pass


class TestTenantTools:
    def test_get_active_tenant_reports_binding(self):
        import time as _t
        from exa.mcp.tools import dispatch_tool

        c = _FakeClient("sademodev22", exp=_t.time() + 1800)
        out = json.loads(
            asyncio.run(dispatch_tool(c, "get_active_tenant", {}, read_only=True))[0].text
        )
        assert out["active_tenant"] == "sademodev22"
        assert out["api_server"] == "https://api.us-west.exabeam.cloud"
        assert out["writes_enabled"] is False
        assert out["token_ttl_seconds"] is not None and out["token_ttl_seconds"] > 0

    def test_get_active_tenant_writes_enabled_flag(self):
        from exa.mcp.tools import dispatch_tool

        c = _FakeClient("csnafusion")
        out = json.loads(
            asyncio.run(dispatch_tool(c, "get_active_tenant", {}, read_only=False))[0].text
        )
        assert out["writes_enabled"] is True

    def test_list_tenants_marks_active_and_default(self):
        from unittest.mock import patch
        from exa.mcp.tools import dispatch_tool

        entries = {
            "sademodev22": {"api_server": "https://api.us-west.exabeam.cloud", "region": "US-West"},
            "lvcva": {"api_server": "https://api.us-west.exabeam.cloud", "region": "US-West"},
        }
        c = _FakeClient("lvcva")
        with patch("exa.config.list_tenants", return_value=entries), patch(
            "exa.config.get_default_tenant", return_value="sademodev22"
        ):
            out = json.loads(
                asyncio.run(dispatch_tool(c, "list_tenants", {}, read_only=True))[0].text
            )
        assert out["active"] == "lvcva"
        assert out["default"] == "sademodev22"
        by_name = {r["tenant"]: r for r in out["tenants"]}
        assert by_name["lvcva"]["active"] is True and by_name["lvcva"]["default"] is False
        assert by_name["sademodev22"]["default"] is True and by_name["sademodev22"]["active"] is False

    def test_set_active_tenant_requires_session(self):
        from exa.mcp.tools import dispatch_tool

        c = _FakeClient("sademodev22")
        out = json.loads(
            asyncio.run(dispatch_tool(c, "set_active_tenant", {"tenant": "lvcva"}))[0].text
        )
        assert "error" in out
        assert "only available" in out["error"].lower()

    def test_set_active_tenant_rejects_unknown_tenant(self):
        from unittest.mock import patch
        from exa.mcp.tools import dispatch_tool

        class _Session:
            def __init__(self):
                self.client = _FakeClient("sademodev22")
                self.read_only = True
                self.switched_to = None

            def switch(self, t):
                self.switched_to = t

        sess = _Session()
        with patch("exa.config.list_tenants", return_value={"sademodev22": {}, "lvcva": {}}):
            out = json.loads(
                asyncio.run(
                    dispatch_tool(
                        sess.client, "set_active_tenant", {"tenant": "not-a-tenant"}, session=sess
                    )
                )[0].text
            )
        assert "error" in out
        assert "unknown tenant" in out["error"].lower()
        assert sess.switched_to is None  # never attempted the switch

    def test_set_active_tenant_switches_and_reports(self):
        from unittest.mock import patch
        from exa.mcp.tools import dispatch_tool

        class _Session:
            def __init__(self):
                self.client = _FakeClient("sademodev22")
                self.read_only = False

            def switch(self, t):
                self.client = _FakeClient(t, base_url="https://api.us-east.exabeam.cloud")

        sess = _Session()
        entries = {"lvcva": {"api_server": "https://api.us-west.exabeam.cloud", "region": "US-West", "kind": "customer"}}
        with patch("exa.config.list_tenants", return_value={"sademodev22": {}, "lvcva": entries["lvcva"]}):
            out = json.loads(
                asyncio.run(
                    dispatch_tool(sess.client, "set_active_tenant", {"tenant": "lvcva"}, session=sess)
                )[0].text
            )
        assert out["active_tenant"] == "lvcva"
        assert out["kind"] == "customer"
        assert out["writes_enabled"] is True

    def test_tenant_tools_visible_in_read_only(self):
        from exa.mcp.tools import visible_tools

        names = {t.name for t in visible_tools(read_only=True)}
        assert {"get_active_tenant", "list_tenants", "set_active_tenant"} <= names


class TestResultSizeGuard:
    def test_small_result_untouched(self):
        from exa.mcp.tools import _ok
        import json as _j

        data = {"a": 1, "b": [1, 2, 3]}
        out = _j.loads(_ok(data)[0].text)
        assert out == data

    def test_oversize_result_is_bounded_and_marked(self):
        from exa.mcp.tools import _ok, _MAX_RESULT_BYTES

        # A payload that dwarfs the cap: computed scalars + a huge raw list.
        data = {"table": "AI Domains", "records": 90000, "overlap": 3,
                "missing": [f"value-{i}-xxxxxxxxxxxxxxxxxxxx" for i in range(200000)]}
        text = _ok(data)[0].text
        assert len(text.encode("utf-8")) <= _MAX_RESULT_BYTES
        # scalar summary survives; the array is truncated with a marker
        assert '"records": 90000' in text or '"records":90000' in text
        assert "_truncated" in text or "_size_capped" in text

    def test_truncate_lists_preserves_scalars_and_counts(self):
        from exa.mcp.tools import _truncate_lists

        out = _truncate_lists({"n": 5, "xs": list(range(100))}, 10)
        assert out["n"] == 5
        assert len(out["xs"]) == 11  # 10 items + 1 marker
        marker = out["xs"][-1]
        assert marker["_truncated"] is True and marker["_omitted"] == 90 and marker["_total"] == 100


class TestSetTenantKind:
    def test_tags_named_tenant(self):
        from unittest.mock import patch
        from exa.mcp.tools import dispatch_tool

        c = _FakeClient("sademodev22")
        captured = {}

        def fake_set(t, k):
            captured["t"], captured["k"] = t, k

        with patch("exa.config.set_tenant_kind", side_effect=fake_set), patch(
            "exa.config.list_tenants", return_value={"lvcva": {"kind": "customer"}}
        ):
            out = json.loads(
                asyncio.run(
                    dispatch_tool(c, "set_tenant_kind", {"tenant": "lvcva", "kind": "customer"})
                )[0].text
            )
        assert captured == {"t": "lvcva", "k": "customer"}
        assert out == {"tenant": "lvcva", "kind": "customer", "updated": True}

    def test_defaults_to_active_tenant(self):
        from unittest.mock import patch
        from exa.mcp.tools import dispatch_tool

        c = _FakeClient("sademodev24")
        captured = {}
        with patch("exa.config.set_tenant_kind", side_effect=lambda t, k: captured.update(t=t, k=k)), patch(
            "exa.config.list_tenants", return_value={"sademodev24": {"kind": "demo"}}
        ):
            out = json.loads(
                asyncio.run(dispatch_tool(c, "set_tenant_kind", {"kind": "demo"}))[0].text
            )
        assert captured["t"] == "sademodev24"
        assert out["tenant"] == "sademodev24" and out["kind"] == "demo"

    def test_invalid_kind_errors(self):
        from exa.mcp.tools import dispatch_tool

        c = _FakeClient("sademodev22")
        out = json.loads(
            asyncio.run(dispatch_tool(c, "set_tenant_kind", {"kind": "prod"}))[0].text
        )
        assert "error" in out


class TestAillmRulesColdGuard:
    def test_cold_profile_fails_fast_with_guidance(self):
        from unittest.mock import patch
        from exa.mcp.tools import dispatch_tool

        c = _FakeClient("sademodev22")
        with patch("exa.aillm.profile.load_cached_profile", return_value=None):
            out = json.loads(
                asyncio.run(dispatch_tool(c, "aillm_rules", {}, read_only=True))[0].text
            )
        assert "error" in out
        assert "exa aillm rules --tenant sademodev22" in out["error"]

    def test_warm_profile_calls_analyzer(self):
        from unittest.mock import patch, MagicMock
        from exa.mcp.tools import dispatch_tool

        c = _FakeClient("sademodev22")
        sentinel = object()
        with patch("exa.aillm.profile.load_cached_profile", return_value=sentinel), patch(
            "exa.aillm.rules.analyze_ai_rules", return_value={"total_rules": 3}
        ) as mock_an:
            out = json.loads(
                asyncio.run(dispatch_tool(c, "aillm_rules", {"lookback_days": 7}, read_only=True))[0].text
            )
        mock_an.assert_called_once()
        # cached profile is passed through, not rebuilt
        assert mock_an.call_args.kwargs.get("profile") is sentinel
        assert out == {"total_rules": 3}


class TestDocsConfig3p:
    def test_proxy_uses_mcp_remote(self):
        from exa.cli.mcp import _generate_docs_config

        cfg = _generate_docs_config(proxy=True)["mcpServers"]["exabeam-docs"]
        assert cfg["command"] == "npx"
        assert "mcp-remote" in cfg["args"]
        assert "transport" not in cfg and "url" not in cfg

    def test_native_uses_sse_url(self):
        from exa.cli.mcp import _generate_docs_config

        cfg = _generate_docs_config(proxy=False)["mcpServers"]["exabeam-docs"]
        assert cfg["transport"] == "sse"
        assert cfg["url"].endswith("/mcp")
        assert "command" not in cfg

    def test_3p_detection_matches_path(self):
        from exa.cli.mcp import _claude_config_path, _is_3p_config

        # _is_3p_config is consistent with the resolved path
        assert _is_3p_config() == ("Claude-3p" in _claude_config_path().parts)


class TestSearchAggregateAndRuleProjection:
    def test_search_events_group_by_omits_filter_fields(self):
        # In aggregate mode, filter fields must NOT be appended to the SELECT
        # (they are neither grouped nor aggregated -> 400). Capture the request body.
        from unittest.mock import MagicMock
        from exa.search.events import search_events

        client = MagicMock()
        client.post.return_value = {"rows": []}
        search_events(
            client, 'vendor:"Check Point"',
            fields=["activity_type", "count(id)"], group_by=["activity_type"],
            lookback_days=7, limit=50,
        )
        body = client.post.call_args.kwargs.get("json") or client.post.call_args.args[-1]
        sel = body.get("fields", [])
        assert "vendor" not in sel  # filter field NOT added in aggregate mode
        assert "approxLogTime" not in sel  # also excluded from group-by

    def test_list_detection_rules_projection(self):
        from unittest.mock import patch
        from exa.mcp.tools import dispatch_tool

        fake = [{
            "name": "R1", "isEnabled": True, "severity": "High", "type": "factFeature",
            "applicableEvents": [{"activity_type": ["process-create"]}],
            "requiredFields": ["process_name"], "families": ["f"],
            "mitre": [{"techniqueKey": "T1059"}],
            "updatedRuleConfig": {"actOnCondition": "x" * 5000},  # huge field must be dropped
        }]
        with patch("exa.detection.rules.get_detection_rules", return_value=fake):
            out = json.loads(asyncio.run(dispatch_tool(MagicMock(), "list_detection_rules", {}))[0].text)
        r = out[0]
        assert r["activity_types"] == ["process-create"] and r["mitre"] == ["T1059"]
        assert "updatedRuleConfig" not in r and "actOnCondition" not in json.dumps(r)

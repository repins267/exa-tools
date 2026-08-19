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
    "render_abv",
    "ai_domain_lookup",
    "soc_kpis",
    "tuning_report",
    "identity_health",
    "context_table",
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
        with patch("exa.config.list_tenants", return_value={"sademodev22": {}, "lvcva": entries["lvcva"]}), \
                patch("exa.config.set_default_tenant") as mock_set_default:
            out = json.loads(
                asyncio.run(
                    dispatch_tool(sess.client, "set_active_tenant", {"tenant": "lvcva"}, session=sess)
                )[0].text
            )
        assert out["active_tenant"] == "lvcva"
        assert out["kind"] == "customer"
        assert out["writes_enabled"] is True
        # the switch must PERSIST so a server respawn doesn't revert to the launch tenant
        mock_set_default.assert_called_once_with("lvcva")
        assert out["persisted_as_default"] is True

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


class TestGuardrails:
    def test_ok_canonicalizes_result_strings(self):
        from exa.mcp.tools import _ok
        import json as _j

        # a zero-width space (U+200B) smuggled into an alert field
        out = _j.loads(_ok({"user": "ad\u200bmin", "risk": 90})[0].text)
        assert out["user"] == "admin"  # smuggling stripped
        assert out["risk"] == 90       # scalars untouched

    def test_ok_leaves_legitimate_text_intact(self):
        from exa.mcp.tools import _ok
        import json as _j

        out = _j.loads(_ok({"path": r"C:\reports\customer\baystate\x.html", "n": 5})[0].text)
        assert out["path"] == r"C:\reports\customer\baystate\x.html"
        assert out["n"] == 5

    def test_neutralize_write_args_defangs_note_and_spares_ids(self):
        from exa.mcp.guardrails import neutralize_write_args

        args = {"case_id": "abc-123", "content": '=HYPERLINK("http://evil.com","x") password=hunter2secret'}
        clean, notes = neutralize_write_args(args)
        assert clean["case_id"] == "abc-123"                 # id untouched
        assert clean["content"].startswith("'=")             # formula inert
        assert "hxxp" in clean["content"] and "evil[.]com" in clean["content"]
        assert "[REDACTED" in clean["content"]               # secret redacted
        assert notes and all("field" in n for n in notes)

    def test_neutralize_write_args_noop_on_clean_text(self):
        from exa.mcp.guardrails import neutralize_write_args

        args = {"case_id": "x", "content": "confirmed benign, user on PTO"}
        clean, notes = neutralize_write_args(args)
        assert clean == args and notes == []

    def test_neutralize_write_args_covers_tags_list(self):
        # ABV-004: list-valued write fields (tags) must be neutralized too.
        from exa.mcp.guardrails import neutralize_write_args

        args = {"alert_id": "a1", "tags": ["benign", '=HYPERLINK("http://evil.com","x")']}
        clean, notes = neutralize_write_args(args)
        assert clean["tags"][0] == "benign"                       # clean tag untouched
        assert clean["tags"][1].startswith("'=")                  # formula neutralized
        assert notes and any(n["field"] == "tags" for n in notes)


class TestAuditLog:
    def _sess(self, monkeypatch, tenant="baystate", kind="customer", read_only=False):
        import exa.config as C
        monkeypatch.setattr(C, "list_tenants", lambda: {tenant: {"kind": kind}})
        client = MagicMock(); client.tenant = tenant
        sess = MagicMock(); sess.client = client; sess.read_only = read_only
        return sess

    def test_records_metadata_never_payload(self, tmp_path, monkeypatch):
        import json as _j, time
        from exa.mcp import audit

        monkeypatch.setenv("EXA_AUDIT_PATH", str(tmp_path / "a.jsonl"))
        monkeypatch.delenv("EXA_AUDIT", raising=False)
        result = [MagicMock(text='{"saved":"x"}')]
        audit.record_tool_call(
            "add_case_note",
            {"case_id": "c-1", "content": "SECRET password=hunter2 planted"},
            result, self._sess(monkeypatch), started=time.time() - 0.02,
        )
        raw = (tmp_path / "a.jsonl").read_text(encoding="utf-8")
        assert "hunter2" not in raw and "planted" not in raw and "content" not in raw
        ev = _j.loads(raw.strip())
        assert ev["tool"] == "add_case_note" and ev["write"] is True
        assert ev["action"] == {"case_id": "c-1"}          # only the safe id
        assert ev["kind"] == "customer" and ev["status"] == "ok"
        assert isinstance(ev["duration_ms"], (int, float)) and ev["result_bytes"] > 0

    def test_error_status_from_error_result(self, tmp_path, monkeypatch):
        import json as _j, time
        from exa.mcp import audit

        monkeypatch.setenv("EXA_AUDIT_PATH", str(tmp_path / "a.jsonl"))
        monkeypatch.delenv("EXA_AUDIT", raising=False)
        audit.record_tool_call("get_alert", {"alert_id": "z"}, [MagicMock(text='{"error": "not found"}')],
                               self._sess(monkeypatch), started=time.time())
        ev = _j.loads((tmp_path / "a.jsonl").read_text().strip())
        assert ev["status"] == "error"

    def test_off_switch_disables(self, tmp_path, monkeypatch):
        from exa.mcp import audit

        p = tmp_path / "a.jsonl"
        monkeypatch.setenv("EXA_AUDIT_PATH", str(p))
        monkeypatch.setenv("EXA_AUDIT", "off")
        audit.record({"event": "x"})
        assert not p.exists()

    def test_fail_open_on_bad_path(self, tmp_path, monkeypatch):
        from exa.mcp import audit

        # point the log at an existing DIRECTORY — open-for-append will fail; must not raise
        monkeypatch.setenv("EXA_AUDIT_PATH", str(tmp_path))
        monkeypatch.delenv("EXA_AUDIT", raising=False)
        audit.record({"event": "x"})  # no exception = pass (fail-open)


class TestReportPath:
    def test_path_is_kind_tenant_scoped_and_created(self, tmp_path, monkeypatch):
        import exa.config as C
        from exa.mcp import tools as T

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(C, "list_tenants", lambda: {"baystate": {"kind": "customer"}})
        client = MagicMock()
        client.tenant = "baystate"
        p = T._report_path(client, "ingest-value.html")
        assert p.parts[-3:] == ("customer", "baystate", "ingest-value.html")
        assert p.parent.is_dir()  # intermediate dirs created, so save never fails

    def test_untagged_tenant_falls_back(self, tmp_path, monkeypatch):
        import exa.config as C
        from exa.mcp import tools as T

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(C, "list_tenants", lambda: {"sadem20": {}})
        client = MagicMock()
        client.tenant = "sadem20"
        p = T._report_path(client, "x.html")
        assert p.parts[-3:] == ("untagged", "sadem20", "x.html")

    def test_safe_seg_blocks_traversal_and_separators(self):
        from exa.mcp.tools import _safe_seg

        assert _safe_seg("../etc") == "etc"
        assert "/" not in _safe_seg("a/b") and "\\" not in _safe_seg("a\\b")
        assert _safe_seg("") == "x"


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

"""Tests for the simulate module: scenarios, EQL matching, webhook transport."""

from __future__ import annotations

import gzip
import json

import pytest

from exa.simulate.eqlmatch import EQLMatchError, matches_eql
from exa.simulate.scenarios import (
    SCENARIOS,
    build_events,
    get_scenario,
    list_behaviors,
)
from exa.simulate.webhook import resolve_ingest_url, send_events


class _FakeClient:
    """Minimal stand-in for ExaClient — only base_url is used by webhook.py."""

    def __init__(self, base_url: str = "https://api.us-west.exabeam.cloud") -> None:
        self.base_url = base_url


# -- Scenario generation ------------------------------------------------------

class TestScenarios:
    def test_known_scenarios_present(self):
        assert "healthcare" in SCENARIOS
        assert "insurance" in SCENARIOS

    def test_unknown_scenario_lists_valid_keys(self):
        with pytest.raises(ValueError, match="healthcare"):
            get_scenario("nope")

    def test_healthcare_covers_five_stages(self):
        stages = [b.stage for b in list_behaviors("healthcare")]
        assert len(stages) == 5
        assert "Impact" in stages
        assert "Credential Access" in stages

    def test_every_behavior_names_a_rule(self):
        for behavior in list_behaviors():
            assert behavior.rule_name, f"{behavior.key} has no rule_name"
            assert behavior.attack.startswith("T")

    def test_events_satisfy_sysmon_parser_conditions(self):
        """All four parser match conditions must appear in the raw JSON."""
        for event in build_events("healthcare"):
            raw = json.dumps(event)
            assert "Microsoft-Windows-Sysmon" in raw
            assert "Process Create:" in raw
            assert '"ParentProcessId":' in raw
            assert '"Image":' in raw

    def test_process_name_resolves_to_basename(self):
        """Exabeam's parser stores process_name as a basename, not a path."""
        events = build_events("healthcare", behavior_key="netsh-rdp-forward")
        assert events[0]["OriginalFileName"] == "netsh.exe"
        assert "\\" in events[0]["Image"]

    def test_events_are_ordered_in_time(self):
        events = build_events("healthcare")
        times = [e["UtcTime"] for e in events]
        assert times == sorted(times)

    def test_marker_is_present_for_traceability(self):
        events = build_events("healthcare", marker="MY-TEST-TAG")
        assert all(e["RuleName"] == "MY-TEST-TAG" for e in events)

    def test_unknown_behavior_raises(self):
        with pytest.raises(ValueError, match="Unknown behavior"):
            build_events("healthcare", behavior_key="does-not-exist")


# -- Offline EQL evaluation ---------------------------------------------------

class TestEqlMatch:
    def test_exact_match_is_case_insensitive(self):
        """Confirmed against the live tenant: exact match ignores case."""
        event = {"Image": r"C:\Windows\System32\netsh.exe"}
        assert matches_eql(event, 'process_name:"NETSH.EXE"')

    def test_wldi_doubled_backslash_matches_single_literal(self):
        event = {"Image": r"C:\Windows\System32\netsh.exe"}
        assert matches_eql(event, r'process_name:WLDi("*\\netsh.exe")')

    def test_and_or_not_and_parens(self):
        event = {"Image": r"C:\W\netsh.exe", "CommandLine": "netsh portproxy add"}
        assert matches_eql(
            event,
            'process_name:"netsh.exe" AND process_command_line:WLDi("*portproxy*")',
        )
        assert matches_eql(event, 'process_name:"nope.exe" OR process_name:"netsh.exe"')
        assert not matches_eql(event, 'NOT process_name:"netsh.exe"')
        assert matches_eql(
            event,
            '(process_name:"nope.exe" OR process_name:"netsh.exe") '
            'AND process_command_line:WLDi("*add*")',
        )

    def test_activity_type_is_process_create(self):
        assert matches_eql({"Image": "x"}, 'activity_type:"process-create"')

    def test_missing_field_does_not_match(self):
        assert not matches_eql({"Image": "x.exe"}, 'user:"anyone"')

    def test_unparseable_eql_raises_rather_than_returning_false(self):
        """A silent False would misreport a rule as 'would not fire'."""
        with pytest.raises(EQLMatchError):
            matches_eql({"Image": "x"}, "process_name ~~ broken")
        with pytest.raises(EQLMatchError):
            matches_eql({"Image": "x"}, "")

    def test_generated_events_match_representative_rule_eql(self):
        """End-to-end: the bcdedit event satisfies that rule's real EQL shape."""
        event = build_events("healthcare", behavior_key="bcdedit-recovery-off")[0]
        eql = (
            'activity_type:"process-create" AND '
            r'((process_name:WLDi("*\\bcdedit.exe") OR process_name:"bcdedit.exe") '
            'AND process_command_line:WLDi("*set*") AND '
            '((process_command_line:WLDi("*bootstatuspolicy*") OR '
            'process_command_line:WLDi("*ignoreallfailures*")) OR '
            '(process_command_line:WLDi("*recoveryenabled*") OR '
            'process_command_line:WLDi("*no*"))))'
        )
        assert matches_eql(event, eql)


# -- Webhook transport --------------------------------------------------------

class TestWebhook:
    def test_ingest_url_uses_api2_host(self):
        url = resolve_ingest_url(_FakeClient())
        assert url == (
            "https://api2.us-west.exabeam.cloud/cloud-collectors/v1/logs/json"
        )

    def test_ingest_url_raw_format(self):
        assert resolve_ingest_url(_FakeClient(), fmt="raw").endswith("/logs/raw")

    def test_ingest_url_preserves_region(self):
        client = _FakeClient("https://api.eu.exabeam.cloud")
        assert "api2.eu.exabeam.cloud" in resolve_ingest_url(client)

    def test_already_api2_url_is_not_double_rewritten(self):
        client = _FakeClient("https://api2.us-west.exabeam.cloud")
        assert resolve_ingest_url(client).count("api2") == 1

    def test_bad_base_url_raises(self):
        with pytest.raises(ValueError, match="Cannot derive ingest host"):
            resolve_ingest_url(_FakeClient("https://example.com"))

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError, match="fmt must be"):
            resolve_ingest_url(_FakeClient(), fmt="xml")

    def test_dry_run_sends_nothing(self, httpx_mock):
        events = build_events("healthcare")
        result = send_events(_FakeClient(), events, token="unused", dry_run=True)
        assert result["dry_run"] is True
        assert result["sent"] == 0
        assert result["events"] == len(events)
        assert len(httpx_mock.get_requests()) == 0

    def test_send_posts_gzipped_json_with_bearer(self, httpx_mock):
        httpx_mock.add_response(status_code=200)
        events = build_events("healthcare")
        result = send_events(_FakeClient(), events, token="tok-123")

        assert result["sent"] == len(events)
        request = httpx_mock.get_requests()[0]
        assert request.headers["Authorization"] == "Bearer tok-123"
        assert request.headers["Content-Encoding"] == "gzip"
        decoded = json.loads(gzip.decompress(request.content))
        assert len(decoded) == len(events)
        assert decoded[0]["SourceName"] == "Microsoft-Windows-Sysmon"

    def test_raw_format_is_newline_delimited(self, httpx_mock):
        httpx_mock.add_response(status_code=200)
        events = build_events("healthcare")
        send_events(_FakeClient(), events, token="tok", fmt="raw")
        body = gzip.decompress(httpx_mock.get_requests()[0].content).decode()
        assert len(body.strip().splitlines()) == len(events)

    def test_send_without_token_raises(self):
        with pytest.raises(ValueError, match="token is required"):
            send_events(_FakeClient(), build_events("healthcare"), token="")

    def test_api_error_is_surfaced(self, httpx_mock):
        from exa.exceptions import ExaAPIError

        httpx_mock.add_response(status_code=401, text="Jwt issuer is not configured")
        with pytest.raises(ExaAPIError) as exc:
            send_events(_FakeClient(), build_events("healthcare"), token="bad")
        assert exc.value.status_code == 401


class TestAbaScenarios:
    """ABA / Observra agent-telemetry generation.

    The whole point of this module is emitting the SENSOR wire schema directly,
    so no transform is needed. Observra's own library output fails the parser's
    match conditions; these tests guard against regressing to that shape.
    """

    def test_all_events_satisfy_parser_match_conditions(self):
        """All three conditions are ANDed and checked before any extraction."""
        import json as _json
        import re as _re

        from exa.simulate.aba import ABA_SCENARIOS, build_aba_events

        for key in ABA_SCENARIOS:
            for event in build_aba_events(key):
                raw = _json.dumps(event)
                assert _re.search(r'"type"\s*:', raw), f"{key}: no type"
                assert _re.search(r'"framework"\s*:\s*"', raw), f"{key}: no framework"
                assert _re.search(r'"schema"\s*:', raw), f"{key}: no schema"

    def test_does_not_emit_library_schema_keys(self):
        """Regression guard: library keys are what fails to parse."""
        from exa.simulate.aba import build_aba_events

        for event in build_aba_events():
            for bad in ("event_type", "session_id", "agent_name", "timestamp",
                        "library_version"):
                assert bad not in event, f"{bad} is library shape and will not parse"

    def test_cost_is_top_level_not_nested(self):
        """Parser reads $.cost_usd; nesting it in data silently drops the field."""
        from exa.simulate.aba import build_aba_events

        priced = [e for e in build_aba_events("aba-activity") if "cost_usd" in e]
        assert priced, "expected at least one priced event"
        for event in priced:
            assert isinstance(event["cost_usd"], float)
            assert "cost_usd" not in (event.get("data") or {})

    def test_injection_text_is_in_request_not_response(self):
        """Injection rules key on llm_request ($.text). $.response maps to
        llm_response and will NOT fire them."""
        from exa.simulate.aba import build_aba_events

        for event in build_aba_events("aba-injection"):
            assert event.get("text"), "injection payload must be in text"
            assert not event.get("response")

    def test_guardrail_events_carry_violation_result(self):
        from exa.simulate.aba import build_aba_events

        results = {e["data"]["result"] for e in build_aba_events("aba-guardrail")}
        assert "guardrail_violation" in results

    def test_lifecycle_covers_all_four_agent_actions(self):
        from exa.simulate.aba import build_aba_events

        actions = {e["data"]["action"] for e in build_aba_events("aba-lifecycle")}
        assert actions == {"create_agent", "modify_agent", "share_agent",
                           "delete_agent"}

    def test_events_share_one_session(self):
        """Events must correlate on conversation_id within a run."""
        from exa.simulate.aba import build_aba_events

        events = build_aba_events("aba-activity")
        assert len({e["session"] for e in events}) == 1
        assert len({e["data"]["session_key"] for e in events}) == 1

    def test_events_ordered_in_time(self):
        from exa.simulate.aba import build_aba_events

        stamps = [e["ts"] for e in build_aba_events("aba-activity")]
        assert stamps == sorted(stamps)

    def test_schema_marker_is_configurable(self):
        from exa.simulate.aba import SCHEMA_ABA, build_aba_events

        events = build_aba_events("aba-injection", schema=SCHEMA_ABA)
        assert all(e["schema"] == "aba-1.0" for e in events)

    def test_marker_present_for_traceability(self):
        from exa.simulate.aba import build_aba_events

        events = build_aba_events("aba-lifecycle", marker="MY-TAG")
        assert all(e["sim_marker"] == "MY-TAG" for e in events)

    def test_unknown_scenario_and_event_raise(self):
        import pytest as _pytest

        from exa.simulate.aba import build_aba_events, get_aba_scenario

        with _pytest.raises(ValueError, match="aba-injection"):
            get_aba_scenario("nope")
        with _pytest.raises(ValueError, match="Unknown ABA event"):
            build_aba_events("aba-injection", event_key="nope")


class TestAbaSupplyChain:
    """Skill provenance and the signals the published parser discards.

    This scenario is deliberately built around fields that have no CIM2
    destination today. It exists to validate an extended parser against real
    payloads, and to quantify the extraction gap — so these tests assert the
    gap is reported honestly, not that the fields land.
    """

    def test_supply_chain_events_still_satisfy_match_conditions(self):
        """Extra fields must not break parsing — the event still has to match."""
        import json as _json

        from exa.simulate.aba import build_aba_events

        for ev in build_aba_events("aba-supplychain"):
            raw = _json.dumps(ev, separators=(",", ":"))
            for cond in ('"type":', '"framework":"', '"schema":"'):
                assert cond in raw, f"{ev.get('type')} lost match condition {cond}"

    def test_skill_provenance_is_emitted(self):
        from exa.simulate.aba import build_aba_events

        first = build_aba_events("aba-supplychain", event_key="supply-skill-first-seen")[0]
        assert first["skill"] == "invoice-normaliser"
        assert first["skill_source"] == "clawhub"
        assert first["skill_publisher"] == "acme-invoice-tools"
        assert first["skill_version"] == "0.1.4"
        assert first["skill_digest"].startswith("sha256:")

    def test_provenance_fields_are_reported_as_dropped(self):
        """The point of the scenario: these parse, then get discarded."""
        from exa.simulate.aba import build_aba_events, dropped_at_extraction

        dropped = dropped_at_extraction(build_aba_events("aba-supplychain"))
        for key in ("skill", "skill_source", "skill_publisher", "skill_digest",
                    "current_depth", "max_depth", "source_agent", "target_agent",
                    "triggered_rules", "max_severity"):
            assert key in dropped, f"{key} should be reported as dropped"

    def test_no_mapped_field_is_also_reported_dropped(self):
        """A field cannot be both extracted and discarded — guards the tables."""
        from exa.simulate.aba import PARSER_TOP_LEVEL, UNMAPPED

        assert not (set(PARSER_TOP_LEVEL) & set(UNMAPPED))

    def test_events_without_security_signals_report_nothing_spurious(self):
        """Scenarios that set no signals should not appear to lose provenance."""
        from exa.simulate.aba import build_aba_events, dropped_at_extraction

        dropped = dropped_at_extraction(build_aba_events("aba-lifecycle"))
        assert "skill" not in dropped
        assert "current_depth" not in dropped

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

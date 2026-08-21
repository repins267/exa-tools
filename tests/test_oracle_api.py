"""Build the Field Oracle live from the Log Stream API (mocked client)."""

from __future__ import annotations

from exa.oracle import api_source
from exa.oracle.api_source import build_oracle_from_api, fetch_parsers
from exa.update import _extract_activity_type


class _Resp:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


class _FakeClient:
    """Returns canned Log Stream API payloads by path."""

    def __init__(self, parsers, event_builders):
        self._parsers = parsers
        self._eb = event_builders
        self.calls: list[str] = []

    def get(self, path):
        self.calls.append(path)
        if "event-builders" in path:
            return _Resp(self._eb)
        return _Resp(self._parsers)


# Parser fields mirror the live API: capture-group regex + explicit exa_json_path.
_PARSERS = [
    {
        "parserName": "okta-system-json-endpoint-authentication-success",
        "vendor": "Okta",
        "product": "Okta Identity",
        "state": "Enabled",
        "fields": [
            "exa_json_path=$.actor.alternateId,exa_field_name=user",
            "\\Wsrc=({src_ip}[0-9.]+)",
        ],
    },
    {
        "parserName": "cisco-asa-cef-dns-query-success",
        "vendor": "Cisco",
        "product": "Cisco ASA",
        "state": "Enabled",
        "fields": ["\\Wqname=({domain}[^\\s]+)"],
    },
]
_EBS = [{"eventBuilderId": "x", "eventName": "e", "eventType": "authentication:success"}]

_OKTA_AT = _extract_activity_type("okta-system-json-endpoint-authentication-success")


def test_fetch_parsers_uses_state_filter():
    c = _FakeClient(_PARSERS, _EBS)
    fetch_parsers(c, state="Enabled")
    assert c.calls[0] == "/log-stream/v1/parsers?state=Enabled"


def test_fetch_parsers_no_state():
    c = _FakeClient(_PARSERS, _EBS)
    fetch_parsers(c, state=None)
    assert c.calls[0] == "/log-stream/v1/parsers"


def test_build_from_api_schema_and_counts():
    c = _FakeClient(_PARSERS, _EBS)
    o = build_oracle_from_api(c)
    assert set(o) == {"by_activity_type", "by_vendor", "raw_to_cim2", "built_at", "stats"}
    assert o["stats"]["parsers_processed"] == 2
    assert o["stats"]["source"] == "log-stream-api"
    assert o["stats"]["event_builders"] == 1
    assert set(o["by_vendor"]) == {"Okta", "Cisco"}


def test_build_from_api_explicit_raw_mapping_wins():
    """The explicit exa_json_path mapping yields the high-quality raw->CIM2 entry."""
    c = _FakeClient(_PARSERS, _EBS)
    o = build_oracle_from_api(c)
    # both the full path and the leaf resolve to the CIM field
    assert o["raw_to_cim2"].get("$.actor.alternateId") == "user"
    assert o["raw_to_cim2"].get("alternateId") == "user"
    # capture-group field lands under the parser's activity_type
    assert "src_ip" in o["by_vendor"]["Okta"][_OKTA_AT]


def test_build_from_api_tolerates_wrapped_payload():
    c = _FakeClient({"parsers": _PARSERS}, {"items": _EBS})
    o = build_oracle_from_api(c)
    assert o["stats"]["parsers_processed"] == 2


def test_as_list_handles_shapes():
    assert api_source._as_list(_Resp([1, 2])) == [1, 2]
    assert api_source._as_list(_Resp({"data": [1]})) == [1]
    assert api_source._as_list(_Resp({"nope": 1})) == []

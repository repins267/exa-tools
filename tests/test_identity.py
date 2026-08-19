"""Identity-merge / GUID-ghost detection logic."""

from __future__ import annotations

from unittest.mock import MagicMock


def test_guid_username_detection():
    from exa.health.identity import is_guid_username

    assert is_guid_username("DCCAEC1D-9C67-40C5-AC8C-3DA1EC9065AD")
    assert is_guid_username("aaaaaaaa-1111-2222-3333-444444444444")
    assert not is_guid_username("adam.reckamp")
    assert not is_guid_username("DELL-MA14250-MU$")
    assert not is_guid_username("")


def _client_with(records, tables=None):
    tables = tables or [{
        "id": "t1", "name": "User Entity Links", "contextType": "User",
        "attributes": [{"id": "user", "isKey": True},
                       {"id": "email", "displayName": "Email"},
                       {"id": "upn", "displayName": "UPN"}],
    }]
    c = MagicMock()
    c.tenant = "acme"

    def _get(path, params=None):
        if path == "/context-management/v1/tables":
            return tables
        if path.startswith("/context-management/v1/tables/") and not path.endswith("/records"):
            return tables[0]
        if path.endswith("/records"):
            return {"records": records}
        return {}

    c.get.side_effect = _get
    return c


def test_finds_recycled_email_merge():
    from exa.health.identity import find_merged_identifiers

    records = [
        {"user": "adam.reckamp", "email": "areckamp@acme.com", "upn": "adam.reckamp@acme.com"},
        {"user": "ryan.siebel", "email": "areckamp@acme.com", "upn": "ryan.siebel@acme.com"},  # recycled
        {"user": "jane.doe", "email": "jdoe@acme.com", "upn": "jane.doe@acme.com"},
    ]
    merged, scanned, note = find_merged_identifiers(_client_with(records))
    assert scanned == ["User Entity Links"]
    assert len(merged) == 1
    m = merged[0]
    assert m.value == "areckamp@acme.com" and m.attribute == "email"
    assert m.users == ["adam.reckamp", "ryan.siebel"]


def test_no_merge_when_identifiers_unique():
    from exa.health.identity import find_merged_identifiers

    records = [
        {"user": "a", "email": "a@x.com"},
        {"user": "b", "email": "b@x.com"},
    ]
    merged, scanned, _ = find_merged_identifiers(_client_with(records))
    assert merged == [] and scanned == ["User Entity Links"]


def test_summary_shape():
    from exa.health.identity import collect_identity_health, identity_summary

    records = [{"user": "a", "email": "shared@x.com"}, {"user": "b", "email": "shared@x.com"}]
    c = _client_with(records)
    import exa.search.events as ev
    orig = ev.search_events
    ev.search_events = lambda *a, **k: []  # no GUID users
    try:
        out = identity_summary(collect_identity_health(c))
    finally:
        ev.search_events = orig
    assert out["merged_entities"] == 1
    assert out["merged"][0]["shared_value"] == "shared@x.com"
    assert out["guid_ghost_users"] == 0

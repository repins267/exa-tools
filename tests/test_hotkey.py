"""Tests for exa.hotkey — pure-unit and HTTP-mocked."""

from __future__ import annotations

import ipaddress
import json

import pytest

from exa.hotkey.analyze import (
    ZoneEntry,
    ZoneRisk,
    _classify_zone,
    _detect_schema,
    analyze_zones,
)
from exa.hotkey.expand import (
    _gen_slash24_records,
    _to_slash24,
    _zone_name_from_network,
    expand_zones,
)
from exa.hotkey.rollback import (
    RollbackManifest,
    apply_rollback,
    load_manifest,
    write_manifest,
)
from exa.hotkey.scan import _ip_in_zone, _parse_grouped_rows

BASE_URL = "https://api.us-west.exabeam.cloud"


# ---------------------------------------------------------------------------
# Pure-unit: _classify_zone
# ---------------------------------------------------------------------------


class TestClassifyZone:
    def test_slash8_is_critical(self):
        risk, prefix, cardinality = _classify_zone("10.0.0.0/8")
        assert risk == "CRITICAL"
        assert prefix == 8
        assert cardinality == 16_777_216

    def test_slash16_is_critical(self):
        risk, prefix, cardinality = _classify_zone("192.168.0.0/16")
        assert risk == "CRITICAL"
        assert prefix == 16
        assert cardinality == 65_536

    def test_slash12_is_critical(self):
        risk, prefix, _ = _classify_zone("10.0.0.0/12")
        assert risk == "CRITICAL"
        assert prefix == 12

    def test_slash17_is_coarse(self):
        risk, prefix, _ = _classify_zone("10.0.0.0/17")
        assert risk == "COARSE"
        assert prefix == 17

    def test_slash23_is_coarse(self):
        risk, prefix, _ = _classify_zone("10.0.0.0/23")
        assert risk == "COARSE"
        assert prefix == 23

    def test_slash24_is_fine(self):
        # /24 is the expand target itself — classified FINE
        risk, prefix, cardinality = _classify_zone("10.5.42.0/24")
        assert risk == "FINE"
        assert prefix == 24
        assert cardinality == 256

    def test_slash32_is_fine(self):
        risk, prefix, cardinality = _classify_zone("10.0.0.1/32")
        assert risk == "FINE"
        assert prefix == 32
        assert cardinality == 1

    def test_slash25_is_fine(self):
        risk, prefix, _ = _classify_zone("10.0.0.0/25")
        assert risk == "FINE"
        assert prefix == 25

    def test_hostname_is_unknown(self):
        risk, prefix, cardinality = _classify_zone("myhost.example.com")
        assert risk == "UNKNOWN"
        assert prefix is None
        assert cardinality is None

    def test_zone_label_string_is_unknown(self):
        risk, _, _ = _classify_zone("Net_10_0_0_0")
        assert risk == "UNKNOWN"

    def test_empty_string_is_unknown(self):
        risk, _, _ = _classify_zone("")
        assert risk == "UNKNOWN"

    def test_ip_without_prefix_parses_as_host(self):
        # ipaddress treats bare IPs as /32 — FINE
        risk, prefix, _ = _classify_zone("10.0.0.1")
        assert risk == "FINE"
        assert prefix == 32


# ---------------------------------------------------------------------------
# Pure-unit: _detect_schema
# ---------------------------------------------------------------------------


_MINIMAL_TABLE = {
    "columns": [
        {"id": "ipRange", "displayName": "IP Range", "isKey": True},
        {"id": "zoneName", "displayName": "Zone Name"},
    ]
}

_WRAPPED_TABLE = {
    "table": {
        "columns": [
            {"id": "network", "displayName": "Network", "isKey": True},
            {"id": "label", "displayName": "Label"},
        ]
    }
}


class TestDetectSchema:
    def test_detects_key_and_name_from_iskey(self):
        ip_col, name_col = _detect_schema(_MINIMAL_TABLE)
        assert ip_col == "ipRange"
        assert name_col == "zoneName"

    def test_unwraps_nested_table(self):
        ip_col, name_col = _detect_schema(_WRAPPED_TABLE)
        assert ip_col == "network"
        assert name_col == "label"

    def test_overrides_bypass_detection(self):
        ip_col, name_col = _detect_schema(_MINIMAL_TABLE, ip_field="myip", name_field="myname")
        assert ip_col == "myip"
        assert name_col == "myname"

    def test_single_non_key_column_used_as_name(self):
        table = {
            "columns": [
                {"id": "subnet", "isKey": True},
                {"id": "weird_col_name"},
            ]
        }
        ip_col, name_col = _detect_schema(table)
        assert ip_col == "subnet"
        assert name_col == "weird_col_name"

    def test_raises_on_ambiguous_schema(self):
        table = {
            "columns": [
                {"id": "colA"},
                {"id": "colB"},
                {"id": "colC"},
            ]
        }
        with pytest.raises(ValueError, match="--ip-field"):
            _detect_schema(table)


# ---------------------------------------------------------------------------
# Pure-unit: IP helpers
# ---------------------------------------------------------------------------


class TestToSlash24:
    def test_maps_ip_to_slash24(self):
        net = _to_slash24("10.5.42.87")
        assert str(net) == "10.5.42.0/24"

    def test_maps_boundary_ip(self):
        net = _to_slash24("192.168.1.255")
        assert str(net) == "192.168.1.0/24"

    def test_invalid_ip_raises(self):
        with pytest.raises(ValueError):
            _to_slash24("not-an-ip")


class TestZoneNameFromNetwork:
    def test_formats_correctly(self):
        net = ipaddress.ip_network("10.5.42.0/24")
        assert _zone_name_from_network(net) == "Net_10_5_42_0"

    def test_formats_192_168(self):
        net = ipaddress.ip_network("192.168.1.0/24")
        assert _zone_name_from_network(net) == "Net_192_168_1_0"


class TestIpInZone:
    def _make_zone(self, cidr: str) -> ZoneRisk:
        entry = ZoneEntry(
            key=cidr,
            zone_name="test",
            ip_field="ip",
            name_field="name",
            table_id="t1",
            table_display_name="Network Zones",
            raw={},
        )
        return ZoneRisk(entry=entry, risk="CRITICAL", prefix_len=8, cardinality=None)

    def test_ip_in_cidr_returns_true(self):
        assert _ip_in_zone("10.5.42.1", self._make_zone("10.0.0.0/8")) is True

    def test_ip_outside_cidr_returns_false(self):
        assert _ip_in_zone("192.168.1.1", self._make_zone("10.0.0.0/8")) is False

    def test_invalid_ip_returns_false(self):
        assert _ip_in_zone("not-an-ip", self._make_zone("10.0.0.0/8")) is False

    def test_invalid_cidr_returns_false(self):
        assert _ip_in_zone("10.0.0.1", self._make_zone("not-a-cidr")) is False


# ---------------------------------------------------------------------------
# Pure-unit: _parse_grouped_rows
# ---------------------------------------------------------------------------


class TestParseGroupedRows:
    def test_extracts_src_ips(self):
        rows = [{"src_ip": "10.0.0.1"}, {"src_ip": "10.0.0.2"}]
        assert _parse_grouped_rows(rows) == ["10.0.0.1", "10.0.0.2"]

    def test_skips_rows_without_src_ip(self):
        rows = [{"src_ip": "10.0.0.1"}, {"other": "x"}, {"src_ip": ""}]
        assert _parse_grouped_rows(rows) == ["10.0.0.1"]

    def test_empty_rows_returns_empty(self):
        assert _parse_grouped_rows([]) == []

    def test_ip_count_equals_row_count(self):
        # groupBy returns one row per distinct IP with no count field.
        # Verified 2026-05-08 against sademodev22: no _count or event_count field.
        # ip_count is purely the number of matching rows.
        rows = [{"src_ip": f"10.0.0.{i}"} for i in range(1, 6)]
        ips = _parse_grouped_rows(rows)
        assert len(ips) == 5  # ip_count = len(rows), not a sum of any field


# ---------------------------------------------------------------------------
# Pure-unit: scan_zones uses groupBy (not a plain search)
# ---------------------------------------------------------------------------


class TestScanZonesUsesGroupBy:
    """Verify scan_zones passes group_by=["src_ip"] to search_events.

    groupBy bypasses the 3000-row API result cap (one row per distinct IP).
    A plain search over 7 days would be truncated at 3000 rows, giving
    inaccurate distinct-IP counts. groupBy returns accurate cardinality.
    """

    def test_scan_calls_group_by(self, exa, mock_auth):
        from exa.hotkey.analyze import ZoneEntry, ZoneRisk
        from exa.hotkey.scan import scan_zones

        # Stub the search endpoint — return two distinct IPs in a /16 zone
        mock_auth.add_response(
            method="POST",
            json={"rows": [{"src_ip": "10.0.0.1"}, {"src_ip": "10.0.0.2"}]},
        )

        zone_entry = ZoneEntry(
            key="10.0.0.0/20",
            zone_name="Net_10_0_0_0",
            ip_field="ipRange",
            name_field="zoneName",
            table_id="t1",
            table_display_name="Network Zones",
            raw={},
        )
        zone = ZoneRisk(entry=zone_entry, risk="COARSE", prefix_len=20, cardinality=4096)

        results = scan_zones(exa, [zone], threshold=1)

        # Confirm groupBy response was parsed: ip_count = number of rows (2)
        assert len(results) == 1
        assert results[0].ip_count == 2
        assert results[0].risk == "HOT_KEY_RISK"

        # Verify the request used groupBy, not a plain search
        request = mock_auth.get_request(url=f"{BASE_URL}/search/v2/events", method="POST")
        body = json.loads(request.content)
        assert body.get("groupBy") == ["src_ip"], "scan must use groupBy to avoid 3000-row cap"
        assert "src_ip" in body.get("fields", [])

    def test_ip_count_is_len_of_matched_rows_not_a_sum(self, exa, mock_auth):
        from exa.hotkey.analyze import ZoneEntry, ZoneRisk
        from exa.hotkey.scan import scan_zones

        # 3 rows returned — there is no count field; ip_count must be 3, not some other value
        mock_auth.add_response(
            method="POST",
            json={"rows": [{"src_ip": "10.1.2.3"}, {"src_ip": "10.1.2.4"}, {"src_ip": "10.1.2.5"}]},
        )

        entry = ZoneEntry(
            key="10.0.0.0/8", zone_name="Net_10", ip_field="ip",
            name_field="name", table_id="t1", table_display_name="NZ", raw={},
        )
        zone = ZoneRisk(entry=entry, risk="CRITICAL", prefix_len=8, cardinality=16_777_216)

        results = scan_zones(exa, [zone], threshold=1)
        assert results[0].ip_count == 3  # exactly len(rows that matched this zone)


# ---------------------------------------------------------------------------
# Pure-unit: _gen_slash24_records
# ---------------------------------------------------------------------------


def _coarse_zone(cidr: str = "10.0.0.0/8") -> ZoneRisk:
    entry = ZoneEntry(
        key=cidr,
        zone_name="Net_10_0_0_0",
        ip_field="ipRange",
        name_field="zoneName",
        table_id="nz-table-1",
        table_display_name="Network Zones",
        raw={},
    )
    # /8 is CRITICAL in the new tier system; helper name kept for test readability
    return ZoneRisk(entry=entry, risk="CRITICAL", prefix_len=8, cardinality=16_777_216)


class TestGenSlash24Records:
    def test_observed_ips_produce_only_matching_slash24s(self):
        zone = _coarse_zone("10.0.0.0/8")
        observed = ["10.5.42.1", "10.5.42.200", "10.6.1.1"]
        records = _gen_slash24_records(zone, observed, enumerate_all=False)
        keys = {r["ipRange"] for r in records}
        assert "10.5.42.0/24" in keys
        assert "10.6.1.0/24" in keys
        assert len(records) == 2  # two distinct /24s

    def test_observed_ips_outside_zone_are_excluded(self):
        zone = _coarse_zone("10.0.0.0/8")
        observed = ["192.168.1.1"]  # not in 10.0.0.0/8
        records = _gen_slash24_records(zone, observed, enumerate_all=False)
        # Falls back to full enumeration when no IPs match
        assert len(records) == 256 * 256  # all /24s in /8

    def test_enumerate_all_produces_all_slash24s_in_slash16(self):
        zone = _coarse_zone("192.168.0.0/16")
        records = _gen_slash24_records(zone, None, enumerate_all=True)
        assert len(records) == 256
        assert records[0]["ipRange"] == "192.168.0.0/24"
        assert records[255]["ipRange"] == "192.168.255.0/24"

    def test_zone_name_format_in_records(self):
        zone = _coarse_zone("192.168.0.0/16")
        records = _gen_slash24_records(zone, None, enumerate_all=True)
        assert records[0]["zoneName"] == "Net_192_168_0_0"
        assert records[1]["zoneName"] == "Net_192_168_1_0"


# ---------------------------------------------------------------------------
# Pure-unit: rollback manifest round-trip
# ---------------------------------------------------------------------------


class TestRollbackManifest:
    def test_write_and_load_roundtrip(self, tmp_path, monkeypatch):
        import exa.hotkey.rollback as rb

        monkeypatch.setattr(rb, "_MANIFEST_DIR", tmp_path / "hotkey-rollback")

        original = [{"ipRange": "10.0.0.0/8", "zoneName": "Net_10_0_0_0"}]
        added = ["10.0.0.0/24", "10.0.1.0/24"]

        path = write_manifest(
            tenant="test-tenant",
            table_id="tbl-123",
            table_display_name="Network Zones",
            zone_name="Net_10_0_0_0",
            original_records=original,
            added_keys=added,
        )

        assert path.exists()
        m = load_manifest(path)
        assert m.tenant == "test-tenant"
        assert m.table_id == "tbl-123"
        assert m.zone_name == "Net_10_0_0_0"
        assert m.original_records == original
        assert m.added_keys == added

    def test_latest_manifest_returns_most_recent(self, tmp_path, monkeypatch):
        import exa.hotkey.rollback as rb

        monkeypatch.setattr(rb, "_MANIFEST_DIR", tmp_path / "hotkey-rollback")

        write_manifest("t1", "id1", "Network Zones", "zone1", [], ["a"])
        path2 = write_manifest("t1", "id1", "Network Zones", "zone2", [], ["b"])

        from exa.hotkey.rollback import latest_manifest

        latest = latest_manifest("t1")
        assert latest == path2


# ---------------------------------------------------------------------------
# HTTP-mocked: analyze_zones
# ---------------------------------------------------------------------------


_TABLES_RESPONSE = [
    {"id": "nz-table-1", "name": "NetworkZones", "displayName": "Network Zones", "totalItems": 3},
    {"id": "other-1", "name": "Other", "displayName": "Other Table", "totalItems": 0},
]

_TABLE_DETAIL = {
    "id": "nz-table-1",
    "displayName": "Network Zones",
    "columns": [
        {"id": "ipRange", "displayName": "IP Range", "isKey": True},
        {"id": "zoneName", "displayName": "Zone Name"},
    ],
}

_RECORDS_PAGE1 = {
    "records": [
        {"ipRange": "10.0.0.0/8", "zoneName": "Net_10_0_0_0"},
        {"ipRange": "192.168.0.0/16", "zoneName": "Net_192_168_0_0"},
        {"ipRange": "10.5.42.0/24", "zoneName": "Net_10_5_42_0"},
    ]
}


class TestAnalyzeZones:
    def test_happy_path(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=_TABLES_RESPONSE,
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/nz-table-1",
            method="GET",
            json=_TABLE_DETAIL,
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/nz-table-1/records?limit=100000&offset=0",
            method="GET",
            json=_RECORDS_PAGE1,
        )

        zones = analyze_zones(exa)

        assert len(zones) == 3
        critical = [z for z in zones if z.risk == "CRITICAL"]
        fine = [z for z in zones if z.risk == "FINE"]
        assert len(critical) == 2  # /8 and /16
        assert len(fine) == 1      # /24 is the expand target — FINE

    def test_table_not_found_raises(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=[{"id": "x", "name": "Other", "displayName": "Other Table"}],
        )
        with pytest.raises(ValueError, match="Network Zones table not found"):
            analyze_zones(exa)


# ---------------------------------------------------------------------------
# HTTP-mocked: expand_zones dry-run (no writes)
# ---------------------------------------------------------------------------


class TestExpandZonesDryRun:
    def test_dry_run_makes_no_api_writes(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=_TABLES_RESPONSE,
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/nz-table-1",
            method="GET",
            json=_TABLE_DETAIL,
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/nz-table-1/records?limit=100000&offset=0",
            method="GET",
            json=_RECORDS_PAGE1,
        )

        zones = analyze_zones(exa)
        # expand_zones uses table_id from ZoneEntry — no second /tables fetch
        summary = expand_zones(exa, zones, dry_run=True, tenant="test")

        assert all(r["status"] == "dry-run" for r in summary)
        # httpx_mock raises on any unexpected network call, so reaching here
        # confirms no DELETE or addRecords requests were made.


# ---------------------------------------------------------------------------
# HTTP-mocked: expand_zones delete-then-add
# ---------------------------------------------------------------------------


class TestExpandZonesWrites:
    def test_replaces_table_with_slash24s(self, exa, mock_auth, tmp_path, monkeypatch):
        """expand_zones snapshots all records, removes coarse entry, adds /24s, replaces table."""
        import exa.hotkey.rollback as rb

        monkeypatch.setattr(rb, "_MANIFEST_DIR", tmp_path / "hotkey-rollback")

        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=_TABLES_RESPONSE,
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/nz-table-1",
            method="GET",
            json=_TABLE_DETAIL,
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/nz-table-1/records?limit=100000&offset=0",
            method="GET",
            json=_RECORDS_PAGE1,
        )
        # Second get_all_records call inside expand_zones (snapshot)
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/nz-table-1/records?limit=100000&offset=0",
            method="GET",
            json=_RECORDS_PAGE1,
        )
        # addRecords with operation="replace"
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/nz-table-1/addRecords",
            method="POST",
            json={"status": "ok"},
        )

        zones = analyze_zones(exa)
        summary = expand_zones(
            exa, zones,
            zone_name="Net_10_0_0_0",
            observed_ips=["10.5.42.1"],
            dry_run=False,
            tenant="test",
        )

        assert len(summary) == 1
        assert summary[0]["status"] == "expanded"
        assert summary[0]["new_key_count"] == 1  # only 10.5.42.0/24 observed


# ---------------------------------------------------------------------------
# HTTP-mocked: apply_rollback
# ---------------------------------------------------------------------------


class TestApplyRollback:
    def test_restores_via_full_replace(self, exa, mock_auth):
        """apply_rollback calls addRecords(replace) with the original snapshot — no delete."""
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/nz-table-1/addRecords",
            method="POST",
            json={"status": "ok"},
        )

        manifest = RollbackManifest(
            tenant="test",
            timestamp="20260508T000000Z",
            table_id="nz-table-1",
            table_display_name="Network Zones",
            zone_name="Net_10_0_0_0",
            original_records=[{"ipRange": "10.0.0.0/8", "zoneName": "Net_10_0_0_0"}],
            added_keys=[],
        )

        apply_rollback(exa, manifest, table_id="nz-table-1")
        # Passes if the single addRecords call completes without error

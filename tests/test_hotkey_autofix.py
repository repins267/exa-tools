"""Tests for exa hotkey autofix CLI command."""

from __future__ import annotations

from unittest.mock import MagicMock

from typer.testing import CliRunner

from exa.cli.app import app
from exa.hotkey.analyze import ZoneEntry, ZoneRisk
from exa.hotkey.scan import ZoneScan

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_zone(
    key: str,
    zone_name: str,
    risk: str,
    *,
    prefix_len: int | None = None,
    cardinality: int | None = None,
    table_id: str = "nz-table-1",
) -> ZoneRisk:
    entry = ZoneEntry(
        key=key,
        zone_name=zone_name,
        ip_field="ipRange",
        name_field="zoneName",
        table_id=table_id,
        table_display_name="Network Zones",
        raw={},
    )
    return ZoneRisk(entry=entry, risk=risk, prefix_len=prefix_len, cardinality=cardinality)


def _make_scan(zone_name: str, ip_count: int, risk: str) -> ZoneScan:
    return ZoneScan(zone_name=zone_name, ip_count=ip_count, event_count=0, risk=risk)


def _mock_client() -> MagicMock:
    client = MagicMock()
    client.close.return_value = None
    return client


# ---------------------------------------------------------------------------
# test_autofix_no_coarse_exits_clean
# ---------------------------------------------------------------------------


def test_autofix_no_coarse_exits_clean(monkeypatch):
    """analyze returns no COARSE zones → exits 0, scan and expand never called."""
    import exa.cli.hotkey as hotkey_cli
    import exa.hotkey.analyze as analyze_mod
    import exa.hotkey.expand as expand_mod
    import exa.hotkey.scan as scan_mod

    monkeypatch.setattr(hotkey_cli, "_make_client", lambda tenant=None: _mock_client())

    fine_zones = [_make_zone("10.5.42.0/24", "Net_10_5_42_0", "MEDIUM", prefix_len=24)]
    monkeypatch.setattr(analyze_mod, "analyze_zones", lambda *a, **kw: fine_zones)

    scan_called: list[bool] = []
    expand_called: list[bool] = []

    def _no_scan(*a: object, **kw: object) -> list:
        scan_called.append(True)
        return []

    def _no_expand(*a: object, **kw: object) -> list:
        expand_called.append(True)
        return []

    monkeypatch.setattr(scan_mod, "scan_zones", _no_scan)
    monkeypatch.setattr(expand_mod, "expand_zones", _no_expand)

    result = runner.invoke(app, ["hotkey", "autofix"])

    assert result.exit_code == 0
    assert "Nothing to do" in result.output
    assert not scan_called
    assert not expand_called


# ---------------------------------------------------------------------------
# test_autofix_no_hot_zones_exits_clean
# ---------------------------------------------------------------------------


def test_autofix_no_hot_zones_exits_clean(monkeypatch):
    """scan returns no HOT_KEY_RISK zones → exits 0, expand never called."""
    import exa.cli.hotkey as hotkey_cli
    import exa.hotkey.analyze as analyze_mod
    import exa.hotkey.expand as expand_mod
    import exa.hotkey.scan as scan_mod

    monkeypatch.setattr(hotkey_cli, "_make_client", lambda tenant=None: _mock_client())

    coarse_zones = [_make_zone("10.0.0.0/8", "Net_10_0_0_0", "COARSE", prefix_len=8)]
    monkeypatch.setattr(analyze_mod, "analyze_zones", lambda *a, **kw: coarse_zones)

    ok_scan = [_make_scan("Net_10_0_0_0", ip_count=3, risk="OK")]
    monkeypatch.setattr(scan_mod, "scan_zones", lambda *a, **kw: ok_scan)

    expand_called: list[bool] = []

    def _no_expand(*a: object, **kw: object) -> list:
        expand_called.append(True)
        return []

    monkeypatch.setattr(expand_mod, "expand_zones", _no_expand)

    result = runner.invoke(app, ["hotkey", "autofix", "--threshold", "500"])

    assert result.exit_code == 0
    assert not expand_called


# ---------------------------------------------------------------------------
# test_autofix_safety_cap
# ---------------------------------------------------------------------------


def test_autofix_safety_cap(monkeypatch):
    """11 HOT_KEY_RISK zones with --max-zones=10 → exit 1, expand never called."""
    import exa.cli.hotkey as hotkey_cli
    import exa.hotkey.analyze as analyze_mod
    import exa.hotkey.expand as expand_mod
    import exa.hotkey.scan as scan_mod

    monkeypatch.setattr(hotkey_cli, "_make_client", lambda tenant=None: _mock_client())

    # 11 COARSE zones
    coarse_zones = [
        _make_zone(f"10.{i}.0.0/16", f"Zone_{i}", "COARSE", prefix_len=16)
        for i in range(11)
    ]
    monkeypatch.setattr(analyze_mod, "analyze_zones", lambda *a, **kw: coarse_zones)

    # 11 HOT_KEY_RISK scans
    hot_scans = [
        _make_scan(f"Zone_{i}", ip_count=1000, risk="HOT_KEY_RISK") for i in range(11)
    ]
    monkeypatch.setattr(scan_mod, "scan_zones", lambda *a, **kw: hot_scans)

    expand_called: list[bool] = []

    def _no_expand(*a: object, **kw: object) -> list:
        expand_called.append(True)
        return []

    monkeypatch.setattr(expand_mod, "expand_zones", _no_expand)

    result = runner.invoke(app, ["hotkey", "autofix", "--max-zones", "10"])

    assert result.exit_code == 1
    assert "11" in result.output
    assert not expand_called


# ---------------------------------------------------------------------------
# test_autofix_dry_run_no_writes
# ---------------------------------------------------------------------------


def test_autofix_dry_run_no_writes(monkeypatch):
    """--dry-run=True → expand_zones called with dry_run=True, no API mutations."""
    import exa.cli.hotkey as hotkey_cli
    import exa.hotkey.analyze as analyze_mod
    import exa.hotkey.expand as expand_mod
    import exa.hotkey.scan as scan_mod
    from exa.search import events as events_mod

    monkeypatch.setattr(hotkey_cli, "_make_client", lambda tenant=None: _mock_client())

    coarse = [_make_zone("10.0.0.0/16", "Net_10_0_0_0", "COARSE", prefix_len=16)]
    monkeypatch.setattr(analyze_mod, "analyze_zones", lambda *a, **kw: coarse)

    hot = [_make_scan("Net_10_0_0_0", ip_count=600, risk="HOT_KEY_RISK")]
    monkeypatch.setattr(scan_mod, "scan_zones", lambda *a, **kw: hot)

    monkeypatch.setattr(
        events_mod, "search_events", lambda *a, **kw: [{"src_ip": "10.0.0.5"}]
    )

    expand_calls: list[dict] = []

    def fake_expand(
        client: object,
        zones: object,
        *,
        observed_ips: object = None,
        enumerate_all: bool = False,
        dry_run: bool = False,
        tenant: str = "default",
        **kw: object,
    ) -> list:
        expand_calls.append({"dry_run": dry_run})
        return [{"zone_name": "Net_10_0_0_0", "old_key": "10.0.0.0/16",
                 "new_key_count": 1, "status": "dry-run"}]

    monkeypatch.setattr(expand_mod, "expand_zones", fake_expand)

    result = runner.invoke(app, ["hotkey", "autofix", "--dry-run"])

    assert result.exit_code == 0
    assert len(expand_calls) == 1
    assert expand_calls[0]["dry_run"] is True
    assert "dry-run" in result.output


# ---------------------------------------------------------------------------
# test_autofix_happy_path
# ---------------------------------------------------------------------------


def test_autofix_happy_path(monkeypatch, tmp_path):
    """Full chain: analyze → scan → expand fires in order, exit 0."""
    import exa.cli.hotkey as hotkey_cli
    import exa.hotkey.analyze as analyze_mod
    import exa.hotkey.expand as expand_mod
    import exa.hotkey.rollback as rollback_mod
    import exa.hotkey.scan as scan_mod
    from exa.search import events as events_mod

    monkeypatch.setattr(hotkey_cli, "_make_client", lambda tenant=None: _mock_client())
    monkeypatch.setattr(rollback_mod, "_MANIFEST_DIR", tmp_path / "hotkey-rollback")

    coarse = [_make_zone("10.0.0.0/16", "Net_10_0_0_0", "COARSE", prefix_len=16)]
    monkeypatch.setattr(analyze_mod, "analyze_zones", lambda *a, **kw: coarse)

    hot = [_make_scan("Net_10_0_0_0", ip_count=800, risk="HOT_KEY_RISK")]
    monkeypatch.setattr(scan_mod, "scan_zones", lambda *a, **kw: hot)

    monkeypatch.setattr(
        events_mod, "search_events", lambda *a, **kw: [{"src_ip": "10.0.0.5"}]
    )

    expand_calls: list[dict] = []

    def fake_expand(
        client: object,
        zones: list,
        *,
        observed_ips: object = None,
        enumerate_all: bool = False,
        dry_run: bool = False,
        tenant: str = "default",
        **kw: object,
    ) -> list:
        expand_calls.append({"zones": zones, "dry_run": dry_run, "tenant": tenant})
        return [{"zone_name": "Net_10_0_0_0", "old_key": "10.0.0.0/16",
                 "new_key_count": 256, "status": "expanded"}]

    monkeypatch.setattr(expand_mod, "expand_zones", fake_expand)

    result = runner.invoke(app, ["hotkey", "autofix"])

    assert result.exit_code == 0, result.output
    assert len(expand_calls) == 1
    assert expand_calls[0]["dry_run"] is False
    # Only the HOT_KEY_RISK COARSE zone should be passed to expand
    assert len(expand_calls[0]["zones"]) == 1
    assert expand_calls[0]["zones"][0].entry.zone_name == "Net_10_0_0_0"
    assert "expanded" in result.output

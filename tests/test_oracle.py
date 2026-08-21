"""Field Oracle built from a tenant parser export (parsers.conf)."""

from __future__ import annotations

import json
import zipfile

import pytest

from exa.oracle import export_builder as eb
from exa.oracle import paths
from exa.update import _extract_activity_type  # parity: same activity-type derivation

# Two parsers in the real parsers.conf triple-quoted format. Names contain known
# CIM2 activity_types so _extract_activity_type resolves them.
_PARSERS_CONF = '''"""Parsers""" = [
    {
        """Name""" = """okta-system-json-endpoint-authentication-success"""
        """Vendor""" = """Okta"""
        """Product""" = """Okta Identity"""
        """Fields""" = [ """"actor":\\{"alternateId":"({user}[^"]+)""",
        """\\Wsrc=({src_ip}[0-9.]+)""" ]
    },
    {
        """Name""" = """cisco-asa-cef-dns-query-success"""
        """Vendor""" = """Cisco"""
        """Product""" = """Cisco ASA"""
        """Fields""" = [ """\\Wqname=({domain}[^\\s]+)""" ]
    }
]'''

_OKTA_AT = _extract_activity_type("okta-system-json-endpoint-authentication-success")
_CISCO_AT = _extract_activity_type("cisco-asa-cef-dns-query-success")


def test_schema_matches_pc_build():
    o = eb.build_oracle_from_export(_PARSERS_CONF)
    assert set(o) == {"by_activity_type", "by_vendor", "raw_to_cim2", "built_at", "stats"}
    assert o["stats"]["parsers_processed"] == 2
    assert o["stats"]["source"] == "tenant-export"


def test_by_vendor_and_fields():
    o = eb.build_oracle_from_export(_PARSERS_CONF)
    assert set(o["by_vendor"]) == {"Okta", "Cisco"}
    # Okta parser's captured CIM2 fields land under its activity_type.
    assert _OKTA_AT  # sanity: the name resolved to an activity_type
    assert set(o["by_vendor"]["Okta"][_OKTA_AT]) == {"user", "src_ip"}


def test_by_activity_type_lists_vendor_product():
    o = eb.build_oracle_from_export(_PARSERS_CONF)
    assert "Okta/Okta Identity" in o["by_activity_type"][_OKTA_AT]["user"]


def test_raw_to_cim2_json_extraction():
    o = eb.build_oracle_from_export(_PARSERS_CONF)
    # JSON key immediately before the capture -> raw:cim mapping.
    assert o["raw_to_cim2"].get("alternateId") == "user"


def test_build_from_zip(tmp_path):
    z = tmp_path / "export.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("Parser_Update/parsers.conf", _PARSERS_CONF)
    o = eb.build_oracle_from_zip(z)
    assert o["stats"]["parsers_processed"] == 2


def test_build_from_zip_missing_parsers(tmp_path):
    z = tmp_path / "empty.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("readme.txt", "nothing here")
    with pytest.raises(FileNotFoundError):
        eb.build_oracle_from_zip(z)


def test_write_oracle_roundtrip(tmp_path):
    o = eb.build_oracle_from_export(_PARSERS_CONF)
    p = eb.write_oracle(o, tmp_path / "sub" / "field_oracle-x.json")
    assert json.loads(p.read_text(encoding="utf-8"))["stats"]["parsers_processed"] == 2


# --- path resolution --------------------------------------------------------


def test_oracle_path_resolution_order(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    # nothing yet -> bundled base (ships with the package)
    assert paths.oracle_path("acme", cache_dir=cache) == paths._BUNDLED_BASE
    # base pack beats bundled
    (cache / "field_oracle-base.json").write_text("{}", encoding="utf-8")
    assert paths.oracle_path("acme", cache_dir=cache) == cache / "field_oracle-base.json"
    # active (field_oracle.json) beats base
    (cache / "field_oracle.json").write_text("{}", encoding="utf-8")
    assert paths.oracle_path("acme", cache_dir=cache) == cache / "field_oracle.json"
    # tenant-specific beats everything
    (cache / "field_oracle-acme.json").write_text("{}", encoding="utf-8")
    assert paths.oracle_path("acme", cache_dir=cache) == cache / "field_oracle-acme.json"
    # a different tenant still falls back to active
    assert paths.oracle_path("other", cache_dir=cache) == cache / "field_oracle.json"


def test_bundled_base_exists_and_is_valid():
    assert paths._BUNDLED_BASE.exists(), "the base pack must ship with the package"
    o = json.loads(paths._BUNDLED_BASE.read_text(encoding="utf-8"))
    assert o["by_vendor"] and o["by_activity_type"]
    assert o["stats"]["source"] == "tenant-export"


# --- config parsers_path ----------------------------------------------------


def test_config_parsers_path(monkeypatch, tmp_path):
    import exa.config as cfg

    store = {"tenants": {"acme": {"api_server": "x"}}}
    monkeypatch.setattr(cfg, "_read_config_file", lambda: store)
    monkeypatch.setattr(cfg, "_write_config_file", lambda d: store.update(d))
    export = tmp_path / "p.zip"
    export.write_bytes(b"PK\x03\x04")  # just needs to exist for the path check
    cfg.set_tenant_parsers_path("acme", str(export))
    assert cfg.get_tenant_parsers_path("acme") == str(export)


def test_config_parsers_path_rejects_missing(monkeypatch):
    import exa.config as cfg

    monkeypatch.setattr(cfg, "_read_config_file", lambda: {"tenants": {"acme": {}}})
    with pytest.raises(cfg.ExaConfigError):
        cfg.set_tenant_parsers_path("acme", "/no/such/file.zip")

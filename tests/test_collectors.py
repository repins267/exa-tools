"""Webhook Cloud Collector registry: metadata on disk, token in keyring only."""

from __future__ import annotations

from datetime import UTC, datetime

import keyring
import pytest

from exa.simulate import collectors as col


@pytest.fixture
def store(monkeypatch, tmp_path):
    """Isolate the registry file and an in-memory keyring."""
    path = tmp_path / "collectors.json"
    monkeypatch.setattr(col, "COLLECTORS_PATH", path)
    kv: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(keyring, "set_password", lambda s, u, p: kv.__setitem__((s, u), p))
    monkeypatch.setattr(keyring, "get_password", lambda s, u: kv.get((s, u)))
    return {"path": path, "kv": kv}


def test_keyring_user_matches_simulate_lookup():
    # Must equal what exa.cli.simulate._token_users tries first, or simulate
    # would not find a token registered here.
    assert col.keyring_user("sademodev22", "raw") == "sademodev22-raw"


def test_store_token_writes_to_keyring_not_file(store):
    user = col.store_token("sademodev22", "json", "  s3cr3t  ")
    assert user == "sademodev22-json"
    assert store["kv"][(col.KEYRING_SERVICE, "sademodev22-json")] == "s3cr3t"
    # collectors.json is untouched by token storage.
    assert not store["path"].exists()


def test_store_token_rejects_empty(store):
    with pytest.raises(ValueError):
        col.store_token("t", "json", "   ")


def test_store_token_rejects_bad_format(store):
    with pytest.raises(ValueError):
        col.store_token("t", "csv", "tok")


def test_save_collector_persists_no_secret(store):
    fixed = datetime(2026, 8, 21, 12, 0, 0, tzinfo=UTC)
    rec = col.save_collector(
        name="Zscaler raw", tenant="sademodev22", fmt="raw", note="prod", now=fixed
    )
    assert rec.keyring_user == "sademodev22-raw"
    assert rec.created == "2026-08-21T12:00:00Z"
    text = store["path"].read_text(encoding="utf-8")
    assert "Zscaler raw" in text and "sademodev22" in text
    # A token must never leak into the metadata file.
    col.store_token("sademodev22", "raw", "TOPSECRET")
    assert "TOPSECRET" not in store["path"].read_text(encoding="utf-8")


def test_save_collector_upserts_by_tenant_and_format(store):
    first = col.save_collector(name="old", tenant="t", fmt="json", note="a")
    col.save_collector(name="new", tenant="t", fmt="json", note="b")
    loaded = col.load_collectors(store["path"])
    assert len(loaded) == 1
    assert loaded[0].name == "new" and loaded[0].note == "b"
    # created is preserved across the update.
    assert loaded[0].created == first.created


def test_load_collectors_missing_file_is_empty(store):
    assert col.load_collectors(store["path"]) == []


def test_load_collectors_ignores_corrupt_file(store):
    store["path"].write_text("{not json", encoding="utf-8")
    assert col.load_collectors(store["path"]) == []


def test_token_present_reflects_keyring(store):
    assert col.token_present("t", "json") is False
    col.store_token("t", "json", "tok")
    assert col.token_present("t", "json") is True
    # Different format is a different collector/token.
    assert col.token_present("t", "raw") is False


def test_default_name_when_omitted(store):
    rec = col.save_collector(name="", tenant="sademodev22", fmt="json")
    assert rec.name == "sademodev22 json"

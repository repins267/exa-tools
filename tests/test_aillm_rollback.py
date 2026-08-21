"""AI/LLM snapshot + rollback guardrail — manifest round-trip and restore logic."""

from __future__ import annotations

import exa.aillm.rollback as rb


def test_is_aillm_table():
    assert rb.is_aillm_table("AI/LLM Web Domains")
    assert rb.is_aillm_table("AI/LLM DLP Rulesets")
    assert rb.is_aillm_table("Public AI Domains and Risk")
    assert rb.is_aillm_table("public ai domains and risks")  # case-insensitive
    assert not rb.is_aillm_table("Compliance - Privileged Users")
    assert not rb.is_aillm_table("Network Zones")
    assert not rb.is_aillm_table("")


def test_manifest_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(rb, "_MANIFEST_DIR", tmp_path)
    m = rb.AillmRollbackManifest(
        tenant="demo1",
        timestamp="20260101T000000Z",
        tables=[{"table_id": "a", "name": "AI/LLM Web Domains",
                 "record_count": 2, "records": [{"key": "x"}, {"key": "y"}]}],
    )
    path = rb.write_manifest(m)
    assert path.exists()
    loaded = rb.load_manifest(path)
    assert loaded.tenant == "demo1"
    assert loaded.tables[0]["records"] == [{"key": "x"}, {"key": "y"}]
    # latest_manifest finds it
    assert rb.latest_manifest("demo1") == path


def test_snapshot_captures_only_aillm_tables(tmp_path, monkeypatch):
    monkeypatch.setattr(rb, "_MANIFEST_DIR", tmp_path)
    monkeypatch.setattr(rb, "get_tables", lambda client: [
        {"id": "t1", "name": "AI/LLM Web Domains"},
        {"id": "t2", "name": "Compliance - Privileged Users"},   # not AI/LLM -> skipped
        {"id": "t3", "name": "Public AI Domains and Risk"},
    ])
    recs = {"t1": [{"key": "openai.com"}], "t3": [{"key": "claude.ai", "risk": "low"}]}
    monkeypatch.setattr(rb, "get_all_records", lambda client, tid: recs.get(tid, []))

    path = rb.snapshot(client=object(), tenant="demo1")
    m = rb.load_manifest(path)
    names = {t["name"] for t in m.tables}
    assert names == {"AI/LLM Web Domains", "Public AI Domains and Risk"}
    assert all("Compliance" not in n for n in names)


def test_restore_dry_run_plans_no_write(monkeypatch):
    calls: list = []
    monkeypatch.setattr(rb, "get_all_records", lambda client, tid: [{"key": "a"}, {"key": "b"}])
    monkeypatch.setattr(rb, "add_records", lambda *a, **k: calls.append(("add", a, k)))
    m = rb.AillmRollbackManifest(tenant="d", timestamp="t", tables=[
        {"table_id": "t1", "name": "AI/LLM Web Domains", "record_count": 2,
         "records": [{"key": "a"}, {"key": "b"}]},
    ])
    plan = rb.restore(client=object(), manifest=m, dry_run=True)
    assert plan[0]["snapshot_count"] == 2
    assert plan[0]["current_count"] == 2
    assert plan[0]["action"] == "no change"
    assert calls == []  # dry run writes nothing


def test_restore_replaces_via_add_records(monkeypatch):
    calls: list = []
    monkeypatch.setattr(rb, "get_all_records", lambda client, tid: [])  # currently empty
    monkeypatch.setattr(rb, "add_records",
                        lambda client, tid, data, *, operation: calls.append((tid, operation, len(data))))
    m = rb.AillmRollbackManifest(tenant="d", timestamp="t", tables=[
        {"table_id": "t1", "name": "AI/LLM Applications", "record_count": 2,
         "records": [{"key": "a"}, {"key": "b"}]},
    ])
    results = rb.restore(client=object(), manifest=m, dry_run=False)
    assert results[0]["action"] == "restored"
    assert calls == [("t1", "replace", 2)]  # full-table replace with the 2 snapshot records

"""The AI/LLM populate->audit->rollback stability cycle."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from exa.aillm import cycle as cyc
from exa.aillm.rollback import AillmRollbackManifest
from exa.aillm.validate import STATUS_DEAD

# Snapshot the six tables at these retrievable counts.
_COUNTS = {"t1": 5, "t2": 3}


def _manifest() -> AillmRollbackManifest:
    return AillmRollbackManifest(
        tenant="demo",
        timestamp="20260821T000000Z",
        tables=[
            {"table_id": "t1", "name": "AI/LLM Web Domains",
             "record_count": 5, "records": [{"k": i} for i in range(5)]},
            {"table_id": "t2", "name": "AI/LLM Applications",
             "record_count": 3, "records": [{"k": i} for i in range(3)]},
        ],
    )


@pytest.fixture
def wired(monkeypatch):
    """Patch every leaf the cycle calls; default happy path. Returns a state dict
    the test can mutate to inject failures."""
    state = {
        "restored_counts": dict(_COUNTS),  # what get_all_records reports post-restore
        "dashboard_skipped": [],
        "dashboard_panels": 8,
        "validations": [
            SimpleNamespace(table_name="AI/LLM Web Domains", status="OK", read_by_rules=True),
            SimpleNamespace(table_name="AI Agent Process Names", status="OK", read_by_rules=True),
        ],
        "search_rows": [{"web_domain": "chatgpt.com"}],
    }

    monkeypatch.setattr(cyc, "snapshot", lambda client, tenant: Path("dummy.json"))
    monkeypatch.setattr(cyc, "load_manifest", lambda path: _manifest())
    monkeypatch.setattr(cyc, "restore", lambda client, m, dry_run=False: [])
    monkeypatch.setattr(
        cyc, "sync_aillm_context_tables", lambda client, **kw: [1, 2, 3, 4, 5, 6]
    )
    monkeypatch.setattr(
        cyc, "build_dashboard",
        lambda client, **kw: SimpleNamespace(
            skipped=state["dashboard_skipped"], panel_count=state["dashboard_panels"]
        ),
    )
    monkeypatch.setattr(
        cyc, "validate_aillm_tables", lambda client, **kw: state["validations"]
    )
    monkeypatch.setattr(
        cyc, "search_events", lambda client, f, **kw: state["search_rows"]
    )
    monkeypatch.setattr(
        cyc, "get_all_records",
        lambda client, tid: [0] * state["restored_counts"].get(tid, 0),
    )
    return state


def test_green_iteration_passes_and_rolls_back(wired):
    it = cyc.run_cycle_iteration(object(), "demo", 1)
    assert it.status == "ok"
    names = [s.name for s in it.steps]
    assert names == [
        "snapshot", "sync", "audit-dashboard",
        "audit-tables", "confirm-search", "rollback",
    ]
    assert all(s.status == "ok" for s in it.steps)


def test_from_empty_adds_clear_step(wired):
    it = cyc.run_cycle_iteration(object(), "demo", 1, from_empty=True)
    names = [s.name for s in it.steps]
    assert "clear" in names and names[1] == "clear"
    assert it.status == "ok"


def test_dead_table_fails_iteration_but_still_rolls_back(wired):
    wired["validations"] = [
        SimpleNamespace(table_name="AI/LLM Web Domains", status=STATUS_DEAD, read_by_rules=True),
    ]
    it = cyc.run_cycle_iteration(object(), "demo", 1)
    assert it.status == "fail"
    assert "audit-tables" in it.failed_steps
    # confirm-search never ran (short-circuited), but rollback DID.
    step_names = [s.name for s in it.steps]
    assert "confirm-search" not in step_names
    assert "rollback" in step_names
    assert next(s for s in it.steps if s.name == "rollback").status == "ok"


def test_no_data_fails_confirm_search(wired):
    wired["search_rows"] = []
    it = cyc.run_cycle_iteration(object(), "demo", 1)
    assert it.status == "fail"
    assert "confirm-search" in it.failed_steps


def test_skipped_panel_fails_dashboard_audit(wired):
    wired["dashboard_skipped"] = ["AI DLP Alerts"]
    it = cyc.run_cycle_iteration(object(), "demo", 1)
    assert it.status == "fail"
    assert "audit-dashboard" in it.failed_steps


def test_restore_drift_fails_rollback(wired):
    # Table t2 comes back with the wrong count -> restore verification fails.
    wired["restored_counts"] = {"t1": 5, "t2": 999}
    it = cyc.run_cycle_iteration(object(), "demo", 1)
    assert it.status == "fail"
    assert "rollback" in it.failed_steps


def test_run_cycles_aggregates_and_verdict(wired):
    report = cyc.run_cycles(object(), "demo", iterations=3)
    assert len(report.iterations) == 3
    assert report.verdict == "PASS"
    assert report.counts["ok"] == 3
    assert report.clean_iterations == 3
    d = report.to_dict()
    assert d["verdict"] == "PASS" and d["total_iterations"] == 3


def test_run_cycles_fail_verdict_completes_all_iterations(wired):
    # Every iteration fails confirm-search; the run must still attempt all 3
    # (no early stop) and report a FAIL verdict.
    wired["search_rows"] = []
    report = cyc.run_cycles(object(), "demo", iterations=3)
    assert len(report.iterations) == 3
    assert report.verdict == "FAIL"
    assert report.counts["fail"] == 3
    assert report.clean_iterations == 0

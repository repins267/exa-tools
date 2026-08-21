"""Simulation run ledger: expected-detection extraction and persistence."""

from __future__ import annotations

from exa.simulate import ledger as led


def test_expected_for_healthcare_carries_named_rules():
    exp = led.expected_for_scenario("healthcare")
    assert exp, "healthcare should have behaviors"
    rules = [e.rule_name for e in exp if e.rule_name]
    # Every healthcare behavior maps to a named Sigma rule.
    assert any("RDP Port Forwarding" in r for r in rules)
    assert any("Comsvcs" in r for r in rules)
    assert all(e.kind in {"rule", "table"} for e in exp)


def test_expected_for_ai_tooling_feeds_tables_not_rules():
    exp = led.expected_for_scenario("ai-tooling")
    assert exp
    # ai-tooling behaviors populate context tables; none fire a named rule.
    assert all(not e.rule_name for e in exp)


def test_expected_for_unknown_scenario_is_empty():
    assert led.expected_for_scenario("does-not-exist") == []


def test_run_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(led, "_LEDGER_DIR", tmp_path)
    run = led.new_run(
        tenant="sademodev22",
        kind="scenario",
        marker="EXA-TIMING-123",
        scenario="healthcare",
        host="SIM-CLINICAL-01",
        user="HOSPITAL\\svc_imaging",
        event_count=5,
    )
    assert run.expected  # auto-filled from the scenario
    assert run.expected_rules  # healthcare has rule-firing behaviors

    path = led.write_run(run)
    assert path.exists()

    loaded = led.load_run(path)
    assert loaded.run_id == run.run_id
    assert loaded.tenant == "sademodev22"
    assert loaded.marker == "EXA-TIMING-123"
    assert loaded.event_count == 5
    assert [e.rule_name for e in loaded.expected] == [e.rule_name for e in run.expected]


def test_latest_run_returns_most_recent(tmp_path, monkeypatch):
    monkeypatch.setattr(led, "_LEDGER_DIR", tmp_path)
    assert led.latest_run("t") is None
    r1 = led.new_run(tenant="t", kind="scenario", marker="m", scenario="healthcare")
    r1.run_id = "20260101T000000Z-scenario-healthcare"
    led.write_run(r1)
    r2 = led.new_run(tenant="t", kind="scenario", marker="m", scenario="insurance")
    r2.run_id = "20260102T000000Z-scenario-insurance"
    led.write_run(r2)
    latest = led.latest_run("t")
    assert latest is not None and latest.stem == r2.run_id
    assert len(led.list_runs("t")) == 2

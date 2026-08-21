"""End-to-end detection timing (MTTD) math and polling."""

from __future__ import annotations

from datetime import datetime

from exa.simulate.ledger import ExpectedDetection, SimRun
from exa.simulate.timing import compute_timing, poll_detections

_SENT = "2026-08-21T00:00:00+00:00"
_RULE = "[Sigma] RDP Port Forwarding Rule Added Via Netsh.EXE"


def _run(host: str = "SIM-CLINICAL-01") -> SimRun:
    return SimRun(
        run_id="r1",
        marker="EXA-SIMULATION",
        tenant="t",
        sent_at=_SENT,
        kind="scenario",
        scenario="healthcare",
        host=host,
        expected=[
            ExpectedDetection(
                behavior="netsh-rdp-forward",
                title="RDP forward",
                attack="T1090",
                stage="Lateral Movement",
                rule_name=_RULE,
            ),
            # A table-feeding behavior with no rule -- must be ignored by timing.
            ExpectedDetection(
                behavior="ollama-serve", title="Ollama", attack="T1059",
                stage="Local Model Runtime", feeds_table="AI Dev Framework Process Names",
            ),
        ],
    )


def _epoch_ms(offset_s: int) -> int:
    base = datetime.fromisoformat(_SENT).timestamp()
    return int((base + offset_s) * 1000)


def test_compute_timing_measures_alert_and_case_mttd():
    alerts = [{"ruleName": _RULE, "host": "SIM-CLINICAL-01",
               "alertCreationTimestamp": _epoch_ms(120)}]
    cases = [{"ruleName": _RULE, "host": "SIM-CLINICAL-01",
              "caseCreationTimestamp": _epoch_ms(300)}]
    outcomes = compute_timing(_run(), alerts, cases)
    assert len(outcomes) == 1  # only the rule-firing behavior
    o = outcomes[0]
    assert o.detected
    assert o.mttd_alert_seconds == 120.0
    assert o.mttd_case_seconds == 300.0


def test_compute_timing_uses_earliest_matching_alert():
    alerts = [
        {"ruleName": _RULE, "alertCreationTimestamp": _epoch_ms(600)},
        {"ruleName": _RULE, "alertCreationTimestamp": _epoch_ms(90)},
    ]
    o = compute_timing(_run(host=""), alerts, [])[0]
    assert o.mttd_alert_seconds == 90.0


def test_compute_timing_no_match_is_undetected():
    alerts = [{"ruleName": "[Sigma] Some Other Rule",
               "alertCreationTimestamp": _epoch_ms(60)}]
    o = compute_timing(_run(host=""), alerts, [])[0]
    assert not o.detected
    assert o.mttd_alert_seconds is None


def test_compute_timing_wrong_host_is_undetected():
    alerts = [{"ruleName": _RULE, "host": "OTHER-HOST",
               "alertCreationTimestamp": _epoch_ms(60)}]
    o = compute_timing(_run(host="SIM-CLINICAL-01"), alerts, [])[0]
    assert not o.detected


def test_poll_detections_stops_when_all_detected():
    calls = {"n": 0}

    def alerts_fn(client, **kw):
        calls["n"] += 1
        return [{"ruleName": _RULE, "alertCreationTimestamp": _epoch_ms(45)}]

    def cases_fn(client, **kw):
        return []

    slept = []
    report = poll_detections(
        None, _run(host=""),
        deadline_seconds=900, interval_seconds=30,
        alerts_fn=alerts_fn, cases_fn=cases_fn,
        sleep=slept.append, clock=lambda: 0.0,
    )
    assert report.all_detected
    assert calls["n"] == 1  # detected on first poll, no re-poll
    assert slept == []  # never waited


def test_poll_detections_gives_up_at_deadline():
    def alerts_fn(client, **kw):
        return []  # never detects

    ticks = {"t": 0.0}

    def clock():
        v = ticks["t"]
        ticks["t"] += 1000.0  # each call jumps past the deadline
        return v

    slept = []
    report = poll_detections(
        None, _run(host=""),
        deadline_seconds=900, interval_seconds=30,
        alerts_fn=alerts_fn, cases_fn=lambda c, **k: [],
        sleep=slept.append, clock=clock,
    )
    assert not report.all_detected
    assert report.detected_count == 0
    assert slept == []  # deadline hit on the first post-poll check, no sleep

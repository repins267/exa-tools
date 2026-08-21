"""Simulation run ledger -- what synthetic data was sent, and what it should detect.

Every ``simulate`` send that we want to time is recorded here: a run manifest
naming the tenant, the marker, the scenario/vendor mix, and -- crucially -- the
*expected detections* (which behaviors should fire which named rules). That
expected-outcome list is what turns "we sent some events" into a measurable
question: did each expected rule fire, and how long did it take (MTTD)?

The expected detections come straight from the scenario definitions in
``exa/simulate/scenarios.py``, where every ``Behavior`` carries either the named
rule it should trigger (``rule_name``) or the context table it should populate
(``feeds_table``). We never invent an expectation the generator did not encode.

Manifests live at ``~/.exa/sim-runs/<tenant>/<run_id>.json`` -- internal record,
never customer-facing.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from exa.simulate.scenarios import SCENARIOS

_LEDGER_DIR = Path.home() / ".exa" / "sim-runs"


@dataclass
class ExpectedDetection:
    """One behavior and the outcome it is supposed to produce."""

    behavior: str
    title: str
    attack: str
    stage: str
    rule_name: str = ""     # the named rule it should fire (correlation/Sigma)
    feeds_table: str = ""   # or the context table its value should populate

    @property
    def kind(self) -> str:
        return "rule" if self.rule_name else ("table" if self.feeds_table else "none")


@dataclass
class SimRun:
    """A single recorded simulate send."""

    run_id: str
    marker: str
    tenant: str
    sent_at: str                       # ISO-8601 UTC of the send
    kind: str                          # scenario | vendor | aba
    scenario: str = ""
    host: str = ""
    user: str = ""
    event_count: int = 0
    expected: list[ExpectedDetection] = field(default_factory=list)

    @property
    def expected_rules(self) -> list[str]:
        return [e.rule_name for e in self.expected if e.rule_name]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def expected_for_scenario(scenario_key: str) -> list[ExpectedDetection]:
    """The expected detections for a named scenario, from its behavior chain."""
    scenario = SCENARIOS.get(scenario_key)
    if scenario is None:
        return []
    out: list[ExpectedDetection] = []
    for b in scenario.behaviors:
        out.append(ExpectedDetection(
            behavior=b.key,
            title=b.title,
            attack=b.attack,
            stage=b.stage,
            rule_name=b.rule_name,
            feeds_table=b.feeds_table,
        ))
    return out


def make_run_id(kind: str, key: str) -> str:
    """A sortable, human-readable run id: <utc-compact>-<kind>-<key>."""
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    slug = (key or kind).replace("/", "-").replace(" ", "-")
    return f"{ts}-{kind}-{slug}"


def new_run(
    *,
    tenant: str,
    kind: str,
    marker: str,
    scenario: str = "",
    host: str = "",
    user: str = "",
    event_count: int = 0,
    expected: list[ExpectedDetection] | None = None,
) -> SimRun:
    """Build a SimRun stamped with the current time (not yet persisted)."""
    if expected is None:
        expected = expected_for_scenario(scenario) if scenario else []
    return SimRun(
        run_id=make_run_id(kind, scenario or kind),
        marker=marker,
        tenant=tenant,
        sent_at=datetime.now(UTC).isoformat(timespec="seconds"),
        kind=kind,
        scenario=scenario,
        host=host,
        user=user,
        event_count=event_count,
        expected=expected,
    )


def _run_dir(tenant: str) -> Path:
    return _LEDGER_DIR / tenant


def write_run(run: SimRun) -> Path:
    """Persist a run manifest and return its path."""
    d = _run_dir(run.tenant)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{run.run_id}.json"
    path.write_text(json.dumps(run.to_dict(), indent=2), encoding="utf-8")
    return path


def load_run(path: str | Path) -> SimRun:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    expected = [ExpectedDetection(**e) for e in data.get("expected", [])]
    data = {**data, "expected": expected}
    return SimRun(**data)


def list_runs(tenant: str) -> list[Path]:
    d = _run_dir(tenant)
    if not d.exists():
        return []
    return sorted(d.glob("*.json"))


def latest_run(tenant: str) -> Path | None:
    runs = list_runs(tenant)
    return runs[-1] if runs else None


def default_marker(prefix: str = "EXA-TIMING") -> str:
    """A unique-enough marker so one run's detections don't count for another."""
    return f"{prefix}-{int(time.time())}"

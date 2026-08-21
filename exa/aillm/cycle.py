"""Repeatable audit cycle for the AI/LLM OOTB dashboards.

One iteration proves the whole demo path end to end against a live tenant:

    snapshot -> [clear] -> sync (populate) -> audit dashboard -> audit tables
    -> confirm data via search -> rollback -> verify restored

and classifies the iteration ok / slow / fail. Running N iterations shows the
populate -> audit -> revert machinery is stable and returns the tenant to its
exact baseline every time (no drift accumulates). Timing/classification mirrors
``exa/cli/selftest.py``.

The rollback in step 7 runs in a ``finally`` so a failure in any middle step
still restores the tenant to its snapshot -- an aborted iteration never leaves
the demo tenant dirty. With ``from_empty=True`` the iteration also clears the
tables after snapshotting, so ``sync`` populates from empty and the run
exercises the exact empty->populated arc the demo shows on stage.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from exa.aillm.dashboard import build_dashboard
from exa.aillm.rollback import (
    AillmRollbackManifest,
    load_manifest,
    restore,
    snapshot,
)
from exa.aillm.sync import sync_aillm_context_tables
from exa.aillm.validate import STATUS_DEAD, validate_aillm_tables
from exa.context.tables import get_all_records
from exa.search.events import search_events

if TYPE_CHECKING:
    from exa.client import ExaClient

# Default confirm filter: a GenAI domain the bundled reference data + the
# `simulate vendor` Zscaler pack both carry, so a populated tenant returns rows.
DEFAULT_CONFIRM_FILTER = 'web_domain:"chatgpt.com"'


class CycleError(RuntimeError):
    """A cycle step's post-condition was not met (dead table, no data, drift)."""


@dataclass
class CycleStep:
    name: str
    seconds: float = 0.0
    status: str = "ok"  # ok | slow | fail
    detail: str = ""


@dataclass
class CycleIteration:
    index: int
    status: str = "ok"  # ok | slow | fail
    seconds: float = 0.0
    steps: list[CycleStep] = field(default_factory=list)

    @property
    def failed_steps(self) -> list[str]:
        return [s.name for s in self.steps if s.status == "fail"]


@dataclass
class CycleReport:
    tenant: str
    started_at: str
    from_empty: bool
    confirm_filter: str
    iterations: list[CycleIteration] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        c = {"ok": 0, "slow": 0, "fail": 0}
        for it in self.iterations:
            c[it.status] = c.get(it.status, 0) + 1
        return c

    @property
    def clean_iterations(self) -> int:
        """ok + slow both pass; only fail breaks the streak."""
        return sum(1 for it in self.iterations if it.status != "fail")

    @property
    def verdict(self) -> str:
        return "PASS" if self.counts["fail"] == 0 and self.iterations else "FAIL"

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant": self.tenant,
            "started_at": self.started_at,
            "from_empty": self.from_empty,
            "confirm_filter": self.confirm_filter,
            "verdict": self.verdict,
            "clean_iterations": self.clean_iterations,
            "total_iterations": len(self.iterations),
            "counts": self.counts,
            "iterations": [asdict(it) for it in self.iterations],
        }


@contextmanager
def _step(steps: list[CycleStep], name: str, *, slow_seconds: float) -> Iterator[CycleStep]:
    """Time one step, record it, and re-raise so the iteration short-circuits."""
    rec = CycleStep(name=name)
    start = time.perf_counter()
    try:
        yield rec
    except Exception as exc:  # noqa: BLE001 -- recorded then re-raised
        rec.status = "fail"
        if not rec.detail:
            rec.detail = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        rec.seconds = round(time.perf_counter() - start, 3)
        if rec.status == "ok" and rec.seconds > slow_seconds:
            rec.status = "slow"
        steps.append(rec)


def _empty_manifest(base: AillmRollbackManifest) -> AillmRollbackManifest:
    """A manifest identical to `base` but with every table's records emptied."""
    tables = [
        {**t, "record_count": 0, "records": []} for t in base.tables
    ]
    return AillmRollbackManifest(tenant=base.tenant, timestamp=base.timestamp, tables=tables)


def _verify_restore(client: ExaClient, manifest: AillmRollbackManifest) -> str:
    """Confirm each table's retrievable count matches the snapshot; raise on drift."""
    drifted: list[str] = []
    for tbl in manifest.tables:
        tid = tbl.get("table_id")
        want = tbl.get("record_count", 0)
        try:
            got = len(get_all_records(client, tid))
        except Exception:  # noqa: BLE001 -- a read failure is a verification failure
            got = -1
        if got != want:
            drifted.append(f"{tbl.get('name')}: {got}!={want}")
    if drifted:
        raise CycleError("restore drift -- " + "; ".join(drifted))
    return f"{len(manifest.tables)} tables back to baseline"


def run_cycle_iteration(
    client: ExaClient,
    tenant: str,
    index: int,
    *,
    confirm_filter: str = DEFAULT_CONFIRM_FILTER,
    lookback_days: int = 30,
    from_empty: bool = False,
    slow_seconds: float = 45.0,
) -> CycleIteration:
    """Run one snapshot->populate->audit->verify->rollback iteration."""
    steps: list[CycleStep] = []
    manifest: AillmRollbackManifest | None = None
    failed = False

    try:
        with _step(steps, "snapshot", slow_seconds=slow_seconds) as rec:
            path = snapshot(client, tenant)
            manifest = load_manifest(path)
            captured = sum(t.get("record_count", 0) for t in manifest.tables)
            rec.detail = f"{captured} records captured"

        if from_empty and manifest is not None:
            with _step(steps, "clear", slow_seconds=slow_seconds) as rec:
                restore(client, _empty_manifest(manifest), dry_run=False)
                rec.detail = "tables cleared to empty"

        with _step(steps, "sync", slow_seconds=slow_seconds) as rec:
            results = sync_aillm_context_tables(client)
            rec.detail = f"{len(results)} tables synced"

        with _step(steps, "audit-dashboard", slow_seconds=slow_seconds) as rec:
            build = build_dashboard(client)
            rec.detail = f"{build.panel_count} panels, {len(build.skipped)} skipped"
            if build.skipped:
                raise CycleError(f"panels skipped (tables absent): {build.skipped}")
            if build.panel_count < 1:
                raise CycleError("dashboard produced no panels")

        with _step(steps, "audit-tables", slow_seconds=slow_seconds) as rec:
            validations = validate_aillm_tables(client, lookback_days=lookback_days)
            dead = [
                v.table_name for v in validations
                if v.status == STATUS_DEAD and v.read_by_rules
            ]
            rec.detail = f"{len(validations)} tables validated, {len(dead)} dead"
            if dead:
                raise CycleError(f"rule-backed tables DEAD: {dead}")

        with _step(steps, "confirm-search", slow_seconds=slow_seconds) as rec:
            rows = search_events(
                client, confirm_filter, lookback_days=lookback_days, limit=50
            )
            n = len(rows) if isinstance(rows, list) else 0
            rec.detail = f"{n} rows match {confirm_filter}"
            if n < 1:
                raise CycleError(f"no events match confirm filter {confirm_filter}")
    except Exception:  # noqa: BLE001 -- classified below; rollback still runs
        failed = True
    finally:
        if manifest is not None:
            try:
                with _step(steps, "rollback", slow_seconds=slow_seconds) as rec:
                    restore(client, manifest, dry_run=False)
                    rec.detail = _verify_restore(client, manifest)
            except Exception:  # noqa: BLE001
                failed = True

    if failed:
        status = "fail"
    elif any(s.status == "slow" for s in steps):
        status = "slow"
    else:
        status = "ok"
    return CycleIteration(
        index=index,
        status=status,
        seconds=round(sum(s.seconds for s in steps), 3),
        steps=steps,
    )


def run_cycles(
    client: ExaClient,
    tenant: str,
    *,
    iterations: int = 15,
    confirm_filter: str = DEFAULT_CONFIRM_FILTER,
    lookback_days: int = 30,
    from_empty: bool = False,
    slow_seconds: float = 45.0,
    on_iteration: Any = None,
) -> CycleReport:
    """Run `iterations` cycles, collecting a CycleReport.

    `on_iteration(it)` is called after each iteration for live progress. The run
    does not stop early on failure -- every iteration is attempted so the report
    shows the full pass/fail distribution, not just up to the first break.
    """
    report = CycleReport(
        tenant=tenant,
        started_at=datetime.now(UTC).isoformat(timespec="seconds"),
        from_empty=from_empty,
        confirm_filter=confirm_filter,
    )
    for i in range(1, iterations + 1):
        it = run_cycle_iteration(
            client,
            tenant,
            i,
            confirm_filter=confirm_filter,
            lookback_days=lookback_days,
            from_empty=from_empty,
            slow_seconds=slow_seconds,
        )
        report.iterations.append(it)
        if on_iteration is not None:
            on_iteration(it)
    return report

"""Compliance framework audit engine for Exabeam.

Runs per-control evidence queries against the Search API and produces
an auditor-ready report with pass/fail status, evidence counts, and
coverage summary.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.console import Console

from exa.compliance.frameworks import (
    load_control_queries,
    load_framework,
)
from exa.search.events import search_events

if TYPE_CHECKING:
    from exa.client import ExaClient

console = Console()


@dataclass
class ControlResult:
    control_id: str
    family: str
    description: str
    status: str  # Pass, Fail
    evidence_count: int = 0
    minimum_evidence: int = 10
    sample_events: list[dict[str, Any]] = field(default_factory=list)
    queries_used: list[str] = field(default_factory=list)


@dataclass
class AuditReport:
    timestamp: str
    framework: str
    framework_name: str
    lookback_days: int
    minimum_evidence: int
    total_leaf_controls: int
    siem_testable_count: int
    manual_control_count: int
    controls_pass: int
    controls_fail: int
    coverage_pct: float
    total_evidence: int
    unique_queries: int
    control_results: list[ControlResult] = field(default_factory=list)
    manual_controls: list[dict[str, str]] = field(default_factory=list)
    active_activity_types: list[str] = field(default_factory=list)
    oracle_version: str = ""
    query_mode: str = "static"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save_json(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2, default=str), encoding="utf-8")


def run_compliance_audit(
    client: ExaClient,
    framework_id: str,
    *,
    lookback_days: int = 30,
    minimum_evidence: int = 10,
    output_report: str | Path | None = None,
    tenant_aware: bool = True,
) -> AuditReport:
    """Run a full compliance framework audit.

    Args:
        client: Authenticated ExaClient.
        framework_id: Framework to audit (e.g. NIST_CSF, CMMC_L2).
        lookback_days: Days to search back for evidence.
        minimum_evidence: Min events to pass a control.
        output_report: Path to save JSON report.
        tenant_aware: Discover active activity_types and build dynamic EQL
            queries via Field Oracle. Disable with --no-tenant-aware to use
            static fallback filters from ControlQueries JSON.
    """
    from exa.compliance.query_builder import ComplianceQueryBuilder
    from exa.compliance.resolver import ConceptResolver

    # Load framework and queries
    fw = load_framework(framework_id)
    queries = load_control_queries(framework_id)
    testable = fw.testable_controls
    manual = fw.manual_controls

    console.rule(f"Compliance Audit: {fw.name}")
    console.print(f"  Lookback: {lookback_days} days")
    console.print(
        f"  Total Controls: {len(fw.controls)} "
        f"({len(fw.leaf_controls)} leaf, {len(fw.header_controls)} headers)"
    )
    console.print(
        f"  SIEM-Testable: {len(testable)}  |  Manual: {len(manual)}"
    )
    console.print(f"  Min Evidence Threshold: {minimum_evidence}")

    # Tenant-aware setup: discover active activity_types via Field Oracle
    resolver = ConceptResolver()
    builder = ComplianceQueryBuilder(resolver)
    active_types: set[str] | None = None
    oracle_ver = resolver.oracle_version()
    query_mode = "static"

    if tenant_aware:
        active_types = resolver.active_activity_types(client, lookback_days=lookback_days)
        if active_types:
            query_mode = "tenant-aware"
            console.print(
                f"  Tenant: {len(active_types)} active activity types | "
                f"Oracle: {oracle_ver[:24]}"
            )
        else:
            query_mode = "static-fallback"
            console.print(
                "  Tenant discovery returned no types — using static filters",
                style="yellow",
            )

    # Run per-control evidence queries
    console.print(
        f"\nRunning per-control evidence queries ({len(testable)} controls)...",
        style="yellow",
    )

    control_results: list[ControlResult] = []
    query_group_cache: dict[str, tuple[int, list[dict]]] = {}
    pass_count = 0
    fail_count = 0
    total_evidence = 0
    queries_executed = 0

    for control in testable:
        cid = control.control_id
        qg = queries.get(cid)

        control_evidence = 0
        sample_events: list[dict] = []
        queries_used: list[str] = []
        control_min = minimum_evidence

        if qg:
            control_min = qg.minimum_evidence or minimum_evidence

            for q in qg.queries:
                # Build dynamic EQL from concepts when available; else use static filter
                if qg.concepts and tenant_aware:
                    effective_filter = builder.build(
                        qg.concepts,
                        fallback_filter=q.filter,
                        active_types=active_types,
                    ) or q.filter
                else:
                    effective_filter = q.filter

                cache_key = (
                    f"{qg.shared_query_group}|{effective_filter}"
                    if qg.shared_query_group
                    else f"{cid}|{effective_filter}"
                )

                if cache_key in query_group_cache:
                    count, samples = query_group_cache[cache_key]
                    control_evidence += count
                    sample_events.extend(samples)
                    queries_used.append(f"{q.name} (cached)")
                else:
                    try:
                        events = search_events(
                            client,
                            effective_filter,
                            fields=q.fields,
                            lookback_days=lookback_days,
                            limit=100,
                        )
                        count = len(events) if isinstance(events, list) else 0
                        samples = events[:5] if isinstance(events, list) else []
                        control_evidence += count
                        sample_events.extend(samples)
                        query_group_cache[cache_key] = (count, samples)
                        queries_executed += 1
                        queries_used.append(q.name)
                    except Exception:
                        queries_used.append(f"{q.name} (FAILED)")

        total_evidence += control_evidence
        status = "Pass" if control_evidence >= control_min else "Fail"
        if status == "Pass":
            pass_count += 1
        else:
            fail_count += 1

        style = "green" if status == "Pass" else "red"
        console.print(
            f"  [{status.upper()}] {cid:<12} {control_evidence} events (min: {control_min})",
            style=style,
        )

        control_results.append(ControlResult(
            control_id=cid,
            family=control.family,
            description=control.description,
            status=status,
            evidence_count=control_evidence,
            minimum_evidence=control_min,
            sample_events=sample_events[:5],
            queries_used=queries_used,
        ))

    # Summary
    testable_count = len(testable)
    coverage_pct = round((pass_count / testable_count) * 100, 1) if testable_count else 0.0

    console.print()
    style = "green" if coverage_pct >= 80 else ("yellow" if coverage_pct >= 60 else "red")
    console.rule(f"{fw.name} — {coverage_pct}% Coverage", style=style)
    console.print(f"  Pass: {pass_count}  |  Fail: {fail_count}")
    console.print(f"  Total Evidence: {total_evidence} events")
    console.print(f"  Unique Queries: {queries_executed}")

    manual_entries = [
        {
            "control_id": c.control_id,
            "family": c.family,
            "description": c.description,
            "status": "Not SIEM-Testable",
        }
        for c in manual
    ]

    report = AuditReport(
        timestamp=datetime.now(UTC).isoformat(),
        framework=framework_id,
        framework_name=fw.name,
        lookback_days=lookback_days,
        minimum_evidence=minimum_evidence,
        total_leaf_controls=len(fw.leaf_controls),
        siem_testable_count=testable_count,
        manual_control_count=len(manual),
        controls_pass=pass_count,
        controls_fail=fail_count,
        coverage_pct=coverage_pct,
        total_evidence=total_evidence,
        unique_queries=queries_executed,
        control_results=control_results,
        manual_controls=manual_entries,
        active_activity_types=sorted(active_types) if active_types else [],
        oracle_version=oracle_ver,
        query_mode=query_mode,
    )

    if output_report:
        report.save_json(output_report)
        console.print(f"\n  Report saved: {output_report}", style="green")

    return report

"""Case qualification engine for analyst triage.

Assembles data from multiple Threat Center and correlation rule APIs to produce
a structured QualificationReport with a verdict and recommended action.

Verdict logic is driven by:
  - Rule structure (first_seen vs threshold) from the actual rule definition
  - Entity context table membership (known-good actor?)
  - Score trend relative to entity's own prior cases (not absolute thresholds)

IP classification is display annotation only — it does not influence the verdict.

API endpoints used:
  POST /threat-center/v1/search/cases   — resolve case number, prior entity cases
  GET  /threat-center/v1/cases/{id}     — full case details + threatSummary
  GET  /correlation-rules/v2/rules      — rule definition (trigger type, groupBy, EQL)
  GET  /context-management/v1/tables    — list tables (via get_tables())
  GET  /context-management/v1/tables/{id}/records — entity membership check
  POST /search/v2/events                — event context around trigger time
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

_COMPLIANCE_TABLE_PREFIXES = ("Compliance -",)


# ---------------------------------------------------------------------------
# Report dataclass
# ---------------------------------------------------------------------------


@dataclass
class QualificationReport:
    case_number: str
    case_id: str
    title: str
    risk_score: int
    rule_name: str
    rule_trigger_type: str        # "first_seen" | "threshold_above" | "threshold_below" | "unknown"
    rule_group_by: list[str]      # fields used for grouping in the rule condition
    rule_eql: str                 # raw EQL query from the rule definition
    rule_threshold_desc: str | None  # human-readable threshold, e.g. "> 5 events in 10m"
    entity_name: str
    entity_type: str              # "user" | "device" | "unknown"
    entity_in_context_tables: list[str]
    prior_cases_30d: int
    prior_scores: list[int]       # riskScore of prior cases, chronological
    score_is_new_high: bool
    score_trend: str              # "escalating" | "consistent" | "spike" | "first_appearance"
    score_delta: int | None       # current score minus median of prior scores
    nova_summary: str | None
    event_context_count: int
    external_ips: list[dict[str, Any]]  # display annotation: ip, classification, label, port_count
    verdict: str
    verdict_reasons: list[str]
    recommended_action: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_rule_trigger(
    condition: dict[str, Any],
    query: str,
) -> tuple[str, list[str], str, str | None]:
    """Parse a sequence condition dict into (trigger_type, group_by, eql, threshold_desc)."""
    group_by: list[str] = condition.get("groupBy") or []
    if condition.get("triggerOnAnyMatch"):
        return "first_seen", group_by, query, None

    op = condition.get("operator", "")
    val = condition.get("value", "")
    time_val = condition.get("time", "")
    unit = condition.get("unit", "")
    desc = None
    if op == "more_than":
        trigger_type = "threshold_above"
        desc = f"> {val} events in {time_val}{unit}"
    elif op == "less_than":
        trigger_type = "threshold_below"
        desc = f"< {val} events in {time_val}{unit}"
    else:
        trigger_type = "unknown"
    return trigger_type, group_by, query, desc


def _fetch_rule_definition(
    client: ExaClient,
    rule_name: str,
) -> tuple[str, list[str], str, str | None]:
    """Fetch rule from correlation-rules API and parse trigger structure.

    Returns (trigger_type, group_by, eql, threshold_desc).
    Falls back to ("unknown", [], "", None) on any error.
    """
    try:
        resp = client.get(
            "/correlation-rules/v2/rules",
            params={"nameContains": rule_name, "limit": 5},
        )
        rules = resp.get("rules", [])
        if not rules:
            return "unknown", [], "", None

        # Find best match (exact name preferred)
        rule = next((r for r in rules if r.get("name") == rule_name), rules[0])
        sequences = (
            rule.get("sequencesConfig", {}).get("sequences", [])
        )
        if not sequences:
            return "unknown", [], "", None

        seq = sequences[0]
        query = seq.get("query", "")
        condition = seq.get("condition", {})
        return _parse_rule_trigger(condition, query)
    except Exception:
        return "unknown", [], "", None


def _compute_score_trend(
    current: int,
    prior: list[int],
) -> tuple[bool, str, int | None]:
    """Return (is_new_high, trend, delta_vs_median) from current and prior scores."""
    if not prior:
        return True, "first_appearance", None

    sorted_prior = sorted(prior)
    median_prior = sorted_prior[len(sorted_prior) // 2]
    delta = current - median_prior
    is_new_high = current > max(prior)

    # Escalating: every prior score <= next, and current > last
    if len(prior) >= 2 and all(
        prior[i] <= prior[i + 1] for i in range(len(prior) - 1)
    ) and current > prior[-1]:
        return is_new_high, "escalating", delta

    if abs(delta) <= 10:
        return is_new_high, "consistent", delta

    return is_new_high, "spike", delta


def _check_entity_context(
    client: ExaClient,
    entity_name: str,
) -> list[str]:
    """Return displayNames of Compliance context tables containing this entity."""
    from exa.context.tables import get_tables

    try:
        tables = get_tables(client)
    except Exception:
        return []

    matched: list[str] = []
    entity_lower = entity_name.lower()

    for tbl in tables:
        display_name = tbl.get("displayName", "")
        if not any(display_name.startswith(p) for p in _COMPLIANCE_TABLE_PREFIXES):
            continue
        try:
            records = client.get(
                f"/context-management/v1/tables/{tbl['id']}/records",
                params={"limit": 5000},
            ).get("records", [])
            if any(entity_lower in str(r).lower() for r in records):
                matched.append(display_name)
        except Exception:
            continue

    return matched


def _fetch_event_context(
    client: ExaClient,
    entity_name: str,
    trigger_time: str,
    window_minutes: int = 30,
) -> tuple[int, list[dict[str, Any]]]:
    """Search events ±window minutes around trigger. Return (count, external_ips_info)."""
    from exa.case.ip_classify import classify_ip_with_label
    from exa.search.events import search_events

    try:
        t = datetime.fromisoformat(trigger_time.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        t = datetime.now(UTC)

    start = t - timedelta(minutes=window_minutes)
    end = t + timedelta(minutes=window_minutes)

    try:
        rows = search_events(
            client,
            f'user:"{entity_name}" OR src_user:"{entity_name}" OR host:"{entity_name}"',
            fields=["user", "src_ip", "dest_ip", "dest_port", "activity_type"],
            start_time=start,
            end_time=end,
            limit=500,
        )
    except Exception:
        return 0, []

    if not isinstance(rows, list):
        return 0, []

    # Collect external IPs with port counts
    ip_ports: dict[str, set[str]] = {}
    for row in rows:
        for field_name in ("dest_ip", "src_ip"):
            ip = str(row.get(field_name, "")).strip()
            if not ip or ip in ("", "None"):
                continue
            classification, _ = classify_ip_with_label(ip)
            if classification in ("private", "loopback"):
                continue
            port = str(row.get("dest_port", ""))
            if ip not in ip_ports:
                ip_ports[ip] = set()
            if port:
                ip_ports[ip].add(port)

    external_ips: list[dict[str, Any]] = []
    for ip, ports in sorted(ip_ports.items()):
        classification, label = classify_ip_with_label(ip)
        external_ips.append({
            "ip": ip,
            "classification": classification,
            "label": label,
            "port_count": len(ports),
        })

    return len(rows), external_ips


def _determine_verdict(report: QualificationReport) -> tuple[str, list[str], str]:
    """Apply verdict logic driven by rule structure, entity context, and score trend.

    No hardcoded score thresholds — risk score is only compared against the
    entity's own prior case history.
    """
    reasons: list[str] = []
    is_first_seen = report.rule_trigger_type == "first_seen"
    has_context = bool(report.entity_in_context_tables)
    first_appearance = report.score_trend == "first_appearance"
    escalating = report.score_trend == "escalating"

    # SUSPECTED_INCIDENT:
    # First-seen rule fired on an entity with no context table match,
    # AND this is either their first appearance or an escalating score trend.
    if is_first_seen and not has_context and (first_appearance or escalating):
        reasons.append("First-seen rule — one event is sufficient to trigger")
        if first_appearance:
            reasons.append("Entity has no prior cases — first appearance in 30 days")
        if escalating:
            reasons.append(
                f"Score trend: escalating across {len(report.prior_scores)} prior cases"
            )
        reasons.append("Entity not in any compliance context tables — unrecognized actor")
        if report.nova_summary:
            reasons.append(f"Nova: {report.nova_summary[:120]}")
        return (
            "SUSPECTED_INCIDENT",
            reasons,
            "Do NOT tune this rule. Escalate for investigation.",
        )

    # LIKELY_FP:
    # Entity is in a known-good compliance context table,
    # AND the current score is not a new high (no escalation).
    if has_context and not report.score_is_new_high:
        reasons.append(f"Entity in: {', '.join(report.entity_in_context_tables)}")
        reasons.append(f"Score ({report.risk_score}) is not a new high for this entity")
        if not is_first_seen and report.rule_threshold_desc:
            reasons.append(
                f"Threshold rule ({report.rule_threshold_desc}) — volume-dependent, not behavioral"
            )
        return (
            "LIKELY_FP",
            reasons,
            "Consider adding entity to allowlist or adjusting rule scope.",
        )

    # LEARNING_PHASE_NOISE:
    # Threshold-based rule with consistent score across 3+ prior cases —
    # entity is a chronic baseline offender, not escalating.
    if (
        not is_first_seen
        and report.score_trend == "consistent"
        and len(report.prior_scores) >= 3
    ):
        reasons.append(
            f"Threshold rule ({report.rule_threshold_desc}) — volume-dependent trigger"
        )
        reasons.append(
            f"Score consistent across {len(report.prior_scores)} prior cases — chronic baseline"
        )
        if report.rule_group_by:
            reasons.append(f"Rule groups by: {', '.join(report.rule_group_by)}")
        return (
            "LEARNING_PHASE_NOISE",
            reasons,
            "Monitor for 2 weeks. Tune threshold if pattern persists.",
        )

    # NEEDS_INVESTIGATION — insufficient signal for clear classification
    reasons.append(f"Score trend: {report.score_trend}")
    if report.score_delta is not None:
        reasons.append(f"Score delta vs prior median: {report.score_delta:+d}")
    reasons.append(f"Rule trigger type: {report.rule_trigger_type}")
    if has_context:
        reasons.append(f"Entity in context tables: {', '.join(report.entity_in_context_tables)}")
    return (
        "NEEDS_INVESTIGATION",
        reasons,
        "Manually review event context. Escalate if unsure.",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_qualification(
    client: ExaClient,
    case_number: str,
    *,
    lookback_days: int = 30,
    event_window_minutes: int = 30,
) -> QualificationReport:
    """Run full qualification analysis on a Threat Center case.

    Args:
        client: Authenticated ExaClient.
        case_number: Human-readable case number (e.g. "221").
        lookback_days: Days to look back for prior entity cases.
        event_window_minutes: ±minutes around trigger time to search events.

    Returns:
        QualificationReport with verdict and reasons.

    Raises:
        ValueError: If no case with the given number exists.
    """
    from exa.case.cases import search_cases
    from exa.case.entities import get_entity_cases

    # Step 1: Resolve case number → full case dict
    rows = search_cases(client, filter=f'caseNumber:"{case_number}"', limit=1)
    if not rows:
        raise ValueError(f"No case found with number {case_number!r}")
    case = rows[0]

    case_id = case.get("caseId", "")
    rule_name = case.get("alertName", "")
    risk_score = int(case.get("riskScore") or 0)
    trigger_time = case.get("caseCreationTimestamp", "")
    nova_summary: str | None = case.get("threatSummary") or case.get("threat_summary") or None

    # Determine entity name and type from case fields
    users: list[str] = case.get("users") or []
    endpoints: list[str] = case.get("endpoints") or []
    if users:
        entity_name = users[0]
        entity_type = "user"
    elif endpoints:
        entity_name = endpoints[0]
        entity_type = "device"
    else:
        entity_name = ""
        entity_type = "unknown"

    # Step 2: Fetch rule definition to anchor triage
    rule_trigger_type, rule_group_by, rule_eql, rule_threshold_desc = _fetch_rule_definition(
        client, rule_name
    )

    # Step 3: Check entity against Compliance context tables
    entity_in_context_tables = (
        _check_entity_context(client, entity_name) if entity_name else []
    )

    # Step 4: Prior cases for same entity
    prior_cases = get_entity_cases(
        client, entity_name, lookback_days=lookback_days, exclude_case_id=case_id
    ) if entity_name else []

    prior_scores = [
        int(c.get("riskScore") or 0)
        for c in sorted(prior_cases, key=lambda c: c.get("caseCreationTimestamp", ""))
    ]

    score_is_new_high, score_trend, score_delta = _compute_score_trend(risk_score, prior_scores)

    # Step 5 & 6: Event context + IP annotation
    event_context_count, external_ips = _fetch_event_context(
        client, entity_name, trigger_time, window_minutes=event_window_minutes
    ) if entity_name else (0, [])

    # Build partial report for verdict function
    report = QualificationReport(
        case_number=case_number,
        case_id=case_id,
        title=rule_name,
        risk_score=risk_score,
        rule_name=rule_name,
        rule_trigger_type=rule_trigger_type,
        rule_group_by=rule_group_by,
        rule_eql=rule_eql,
        rule_threshold_desc=rule_threshold_desc,
        entity_name=entity_name,
        entity_type=entity_type,
        entity_in_context_tables=entity_in_context_tables,
        prior_cases_30d=len(prior_cases),
        prior_scores=prior_scores,
        score_is_new_high=score_is_new_high,
        score_trend=score_trend,
        score_delta=score_delta,
        nova_summary=nova_summary,
        event_context_count=event_context_count,
        external_ips=external_ips,
        verdict="",
        verdict_reasons=[],
        recommended_action="",
    )

    # Step 7: Apply verdict logic
    verdict, verdict_reasons, recommended_action = _determine_verdict(report)
    report.verdict = verdict
    report.verdict_reasons = verdict_reasons
    report.recommended_action = recommended_action

    return report

"""AI analytics rule reachability — what can fire today, and what is blocked.

Every analytics rule declares `requiredFields`. A rule whose required fields are
absent or unpopulated in a tenant is enabled, Active, and silently incapable of
firing. Comparing declared requirements against the observed field inventory
turns "we should send more telemetry" into a specific, countable claim.

Measured at geha.use1 (2026-08-11): 75 AI-scoped rules, all enabled,
**62 reachable / 13 blocked** — every blocker one of `llm_request`,
`llm_response`, `ai_token_in_count`, `ai_token_out_count`, `ai_token_count`,
`ai_function_name`. All six come only from agent-level telemetry; no proxy, DLP
or context table populates them. That is the Observra case, generated rather
than asserted.

Note the field name is `isEnabled`, not `enabled` (EXA-RULE-ISENABLED-FIELD).
Reading `enabled` returns None for every rule and reports the entire estate as
disabled.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from exa.aillm.profile import TenantProfile, collect_tenant_profile, ensure_fields

if TYPE_CHECKING:
    from exa.client import ExaClient

# Activity types and text that scope a rule to AI/agent behaviour.
_AI_ACTIVITY = re.compile(r"ai_agent|tool-call|tool-return|ai_|llm", re.I)
_AI_TEXT = re.compile(r"\bAI\b|LLM|Generative|Copilot|GenAI|chatbot|prompt", re.I)

# Fields only agent-level telemetry produces. Used to attribute a blocked rule
# to the telemetry gap rather than to a misconfiguration.
AGENT_ONLY_FIELDS: set[str] = {
    "llm_request", "llm_response", "ai_token_in_count", "ai_token_out_count",
    "ai_token_count", "ai_function_name",
}

_CONTEXT_CALL = re.compile(r"ContextListContains\(\s*'([^']+)'", re.I)


@dataclass
class RuleStatus:
    """Reachability verdict for one analytics rule."""

    rule_id: str
    name: str
    enabled: bool
    rule_type: str
    severity: str
    activity_types: list[str] = field(default_factory=list)
    required_fields: list[str] = field(default_factory=list)
    missing_fields: list[str] = field(default_factory=list)
    context_tables: list[str] = field(default_factory=list)
    reachable: bool = False

    @property
    def blocked_by_agent_telemetry(self) -> bool:
        """True when every blocker is a field only an agent sensor emits."""
        return bool(self.missing_fields) and set(self.missing_fields) <= AGENT_ONLY_FIELDS


@dataclass
class RuleReport:
    """Aggregate reachability across a tenant's AI-scoped rules."""

    total_rules: int = 0
    ai_rules: int = 0
    enabled: int = 0
    disabled: int = 0
    reachable: list[RuleStatus] = field(default_factory=list)
    blocked: list[RuleStatus] = field(default_factory=list)
    # missing field -> rule names gated behind it
    blockers: dict[str, list[str]] = field(default_factory=dict)
    # context table -> rule names that read it
    context_consumers: dict[str, list[str]] = field(default_factory=dict)
    activity_types: dict[str, int] = field(default_factory=dict)

    @property
    def agent_blocked(self) -> list[RuleStatus]:
        """Rules blocked solely by agent-only telemetry — the Observra case."""
        return [r for r in self.blocked if r.blocked_by_agent_telemetry]


def _is_ai_rule(rule: dict[str, Any], activities: list[str]) -> bool:
    if any(_AI_ACTIVITY.search(a) for a in activities):
        return True
    return bool(_AI_TEXT.search(f"{rule.get('name', '')} {rule.get('description', '')}"))


def analyze_ai_rules(
    client: ExaClient,
    *,
    profile: TenantProfile | None = None,
    lookback_days: int = 30,
    refresh: bool = False,
) -> RuleReport:
    """Determine which AI analytics rules can fire against this tenant's data.

    Args:
        client: Authenticated ExaClient.
        profile: Reuse an existing TenantProfile. Collected if omitted.
        lookback_days: Lookback used when collecting a profile.
        refresh: Force profile re-collection.

    Returns:
        RuleReport. One API call for the rule list; field data comes from the
        profile, so a warm profile makes this a single-request operation.
    """
    from exa.detection.rules import get_detection_rules

    profile = profile or collect_tenant_profile(
        client, lookback_days=lookback_days, refresh=refresh
    )

    rules = get_detection_rules(client)
    report = RuleReport(total_rules=len(rules))

    # Verify every field the AI rules require before judging reachability.
    # The profile enumerates a fixed set; a field outside it is UNMEASURED, not
    # absent. Skipping this step reported 52 of 75 rules blocked when the true
    # figure was 13 — "not in the profile" silently became "not in the tenant".
    needed: set[str] = set()
    for rule in rules:
        activities: list[str] = []
        for ev in rule.get("applicableEvents") or []:
            activities += list(ev.get("activity_type") or [])
        if _is_ai_rule(rule, activities):
            needed.update(rule.get("requiredFields") or [])
    if needed:
        ensure_fields(client, profile, sorted(needed))

    blockers: dict[str, list[str]] = defaultdict(list)
    consumers: dict[str, list[str]] = defaultdict(list)
    activity_counter: Counter[str] = Counter()

    for rule in rules:
        activities: list[str] = []
        for ev in rule.get("applicableEvents") or []:
            activities += list(ev.get("activity_type") or [])

        conditions = f"{rule.get('actOnCondition') or ''} {rule.get('trainOnCondition') or ''}"
        tables = sorted(set(_CONTEXT_CALL.findall(conditions)))

        if not _is_ai_rule(rule, activities):
            # Still record context-table consumers outside the AI scope — a
            # table may be read by rules we would not otherwise surface.
            for t in tables:
                consumers[t].append(str(rule.get("name")))
            continue

        report.ai_rules += 1
        enabled = rule.get("isEnabled") is True
        if enabled:
            report.enabled += 1
        else:
            report.disabled += 1

        required = list(rule.get("requiredFields") or [])
        missing = [f for f in required if not profile.exists(f)]

        status = RuleStatus(
            rule_id=str(rule.get("id")),
            name=str(rule.get("name")),
            enabled=enabled,
            rule_type=str(rule.get("type")),
            severity=str(rule.get("severity") or "-"),
            activity_types=activities,
            required_fields=required,
            missing_fields=missing,
            context_tables=tables,
            reachable=not missing,
        )

        for a in activities:
            activity_counter[a] += 1
        for t in tables:
            consumers[t].append(status.name)
        for f in missing:
            blockers[f].append(status.name)

        (report.reachable if status.reachable else report.blocked).append(status)

    report.blockers = {
        k: sorted(v) for k, v in sorted(blockers.items(), key=lambda x: -len(x[1]))
    }
    report.context_consumers = {k: sorted(v) for k, v in sorted(consumers.items())}
    report.activity_types = dict(activity_counter.most_common())
    return report

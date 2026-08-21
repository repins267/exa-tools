"""Consumer-driven requirement derivation: rules + dashboard context_rule reading."""

from __future__ import annotations

from exa.aillm.consumers import (
    dashboard_context_pairs,
    parse_context_rule,
    rule_context_pairs,
)
from exa.aillm.dashboard import build_context_rule
from exa.aillm.requirements import DASHBOARD, derive_requirements

# The real encoding seen in AI_LLM_Category_Usage.config (category IN vi4yCUrkuL).
_REAL_CR = (
    "categoryContextRuleSeparatorinContextRuleSeparatorcustom"
    "ContextRuleSeparatorraw_entity_other_customContextRuleSeparatorvi4yCUrkuL"
)


def test_rule_context_pairs_captures_table_and_field():
    cond = (
        "ContextListContains('AI/LLM Web Domains', event.web_domain) AND "
        "ContextListContains('AI Agent Process Names', parent_process_name)"
    )
    pairs = rule_context_pairs(cond)
    assert ("AI/LLM Web Domains", "web_domain") in pairs
    assert ("AI Agent Process Names", "parent_process_name") in pairs


def test_parse_context_rule_roundtrips_build():
    encoded = build_context_rule("web_domain", "JfPvofJzKB")
    assert parse_context_rule(encoded) == ("web_domain", "JfPvofJzKB")


def test_parse_real_context_rule():
    assert parse_context_rule(_REAL_CR) == ("category", "vi4yCUrkuL")


def test_parse_context_rule_rejects_garbage():
    assert parse_context_rule("") is None
    assert parse_context_rule("not a rule") is None


def test_dashboard_context_pairs_resolves_table_id():
    cfg = {"dashboardElements": [
        {"type": "vis", "filters": {"event.context_rule": _REAL_CR}},
        {"type": "vis", "filters": {}},  # no context rule -> ignored
    ]}
    pairs = dashboard_context_pairs(cfg, {"vi4yCUrkuL": "AI/LLM Proxy Categories"})
    assert pairs == [("AI/LLM Proxy Categories", "category")]


def test_dashboard_context_pairs_keeps_unresolved_id():
    cfg = {"dashboardElements": [
        {"type": "vis", "filters": {"event.context_rule": _REAL_CR}}]}
    pairs = dashboard_context_pairs(cfg, {})  # id not resolvable
    assert pairs == [("vi4yCUrkuL", "category")]


def test_derive_requirements_unions_rules_and_dashboards():
    rules = [{
        "name": "AI Web rule",
        "actOnCondition": "ContextListContains('AI/LLM Web Domains', web_domain)",
        "trainOnCondition": "",
    }]
    dash = [{"dashboardElements": [
        {"type": "vis", "filters": {"event.context_rule": _REAL_CR}}]}]
    tables = [{"id": "vi4yCUrkuL", "displayName": "AI/LLM Proxy Categories"}]

    reqs = derive_requirements(
        rules=rules, dashboard_configs=dash, tables=tables, seed_fallback=False
    )
    # rule-derived table
    assert "web_domain" in reqs["AI/LLM Web Domains"].fields
    assert reqs["AI/LLM Web Domains"].read_by_rules
    # dashboard-derived table (dashboard-only -> Proxy Categories)
    assert "category" in reqs["AI/LLM Proxy Categories"].fields
    assert DASHBOARD in reqs["AI/LLM Proxy Categories"].consumers
    assert reqs["AI/LLM Proxy Categories"].resolved


def test_seed_fallback_fills_ai_tables_when_no_consumers():
    reqs = derive_requirements(rules=[], dashboard_configs=None, seed_fallback=True)
    # TABLE_SPECS seeds the known AI tables so they still resolve
    assert any("AI/LLM" in t for t in reqs)
    dlp = reqs.get("AI/LLM DLP Rulesets")
    assert dlp and "alert_name" in dlp.fields

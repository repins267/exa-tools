"""Threat Center case and alert management for Exabeam New-Scale."""

from exa.case.alerts import (
    get_alert,
    search_alerts,
    update_alert,
)
from exa.case.baseline import CalibrationReport, run_baseline
from exa.case.cases import (
    create_case,
    get_case,
    search_cases,
    update_case,
)
from exa.case.entities import get_entity_cases, get_entity_profile
from exa.case.ip_classify import classify_ip, classify_ip_with_label
from exa.case.outcomes import (
    OutcomeRecord,
    append_outcome,
    auto_fill_outcomes,
    load_outcomes,
    resolve_outcome,
)
from exa.case.qualify import QualificationReport, run_qualification

__all__ = [
    "create_case",
    "get_case",
    "search_cases",
    "update_case",
    "get_alert",
    "search_alerts",
    "update_alert",
    "get_entity_cases",
    "get_entity_profile",
    "classify_ip",
    "classify_ip_with_label",
    "OutcomeRecord",
    "append_outcome",
    "load_outcomes",
    "resolve_outcome",
    "auto_fill_outcomes",
    "QualificationReport",
    "run_qualification",
    "CalibrationReport",
    "run_baseline",
]

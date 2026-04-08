"""Compliance framework automation for Exabeam."""

from exa.compliance.audit import AuditReport, run_compliance_audit
from exa.compliance.frameworks import (
    AVAILABLE_FRAMEWORKS,
    Framework,
    load_control_queries,
    load_framework,
)
from exa.compliance.identity import sync_compliance_identity_tables
from exa.compliance.mapping import (
    classify_records,
    discover_source_mappings,
    extract_keys,
)

__all__ = [
    "AVAILABLE_FRAMEWORKS",
    "AuditReport",
    "Framework",
    "classify_records",
    "discover_source_mappings",
    "extract_keys",
    "load_control_queries",
    "load_framework",
    "run_compliance_audit",
    "sync_compliance_identity_tables",
]

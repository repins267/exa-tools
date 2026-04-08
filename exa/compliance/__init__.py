"""Compliance framework automation for Exabeam."""

from exa.compliance.identity import sync_compliance_identity_tables
from exa.compliance.mapping import (
    discover_source_mappings,
    extract_keys,
    classify_records,
)

__all__ = [
    "sync_compliance_identity_tables",
    "discover_source_mappings",
    "extract_keys",
    "classify_records",
]

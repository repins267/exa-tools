"""Correlation rule management for Exabeam."""

from exa.correlation.rules import (
    create_rule,
    delete_rule,
    get_rule,
    get_rules,
    set_rule_state,
    update_rule,
)
from exa.correlation.validate import validate_eql

__all__ = [
    "create_rule",
    "delete_rule",
    "get_rule",
    "get_rules",
    "set_rule_state",
    "update_rule",
    "validate_eql",
]

"""Detection rule management for Exabeam."""

from exa.detection.diff import diff_rules
from exa.detection.rules import (
    export_rules,
    get_detection_rule,
    get_detection_rules,
    import_rules,
    set_detection_rule_state,
)
from exa.detection.snapshot import create_snapshot_table, snapshot_rules_to_table

__all__ = [
    "create_snapshot_table",
    "diff_rules",
    "export_rules",
    "get_detection_rule",
    "get_detection_rules",
    "import_rules",
    "set_detection_rule_state",
    "snapshot_rules_to_table",
]

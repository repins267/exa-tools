"""Detection content validation via synthetic log generation.

Generates Sysmon-shaped events that exercise deployed correlation rules, and
ships them to a tenant through a Webhook Cloud Collector. Lets a customer prove
detection content actually fires without waiting for real attacker activity.
"""

from exa.simulate.scenarios import (
    SCENARIOS,
    Behavior,
    build_events,
    get_scenario,
    list_behaviors,
)
from exa.simulate.webhook import resolve_ingest_url, send_events

__all__ = [
    "SCENARIOS",
    "Behavior",
    "build_events",
    "get_scenario",
    "list_behaviors",
    "resolve_ingest_url",
    "send_events",
]

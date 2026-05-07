"""Load compliance framework definitions and control queries from bundled data."""

from __future__ import annotations

import importlib.resources
import json
import re
from dataclasses import dataclass, field

AVAILABLE_FRAMEWORKS = [
    "CMMC_L2", "CMMC_L3", "FedRAMP_Moderate", "HIPAA",
    "PCI_DSS", "ISO_27001", "NIST_CSF", "GDPR", "SOX", "CJIS", "CIS_V8",
]


@dataclass
class Control:
    control_id: str
    family: str
    description: str
    level: str = "Required"
    siem_validatable: bool = False

    @property
    def is_leaf(self) -> bool:
        """Leaf controls end with -NN (digits after hyphen)."""
        return bool(re.search(r"-\d+$", self.control_id))


@dataclass
class ControlQuery:
    name: str
    filter: str
    fields: list[str] = field(default_factory=list)
    evidence_description: str = ""


@dataclass
class ControlQueryGroup:
    name: str
    queries: list[ControlQuery] = field(default_factory=list)
    context_tables: list[str] = field(default_factory=list)
    minimum_evidence: int = 10
    shared_query_group: str | None = None
    concepts: list[str] = field(default_factory=list)


@dataclass
class Framework:
    name: str
    framework: str
    version: str = ""
    source_url: str = ""
    controls: list[Control] = field(default_factory=list)

    @property
    def leaf_controls(self) -> list[Control]:
        return [c for c in self.controls if c.is_leaf]

    @property
    def testable_controls(self) -> list[Control]:
        return [c for c in self.leaf_controls if c.siem_validatable]

    @property
    def manual_controls(self) -> list[Control]:
        return [c for c in self.leaf_controls if not c.siem_validatable]

    @property
    def header_controls(self) -> list[Control]:
        return [c for c in self.controls if not c.is_leaf]


def _validate_framework_id(framework_id: str) -> None:
    """Validate framework ID — no path traversal or injection."""
    from exa.exceptions import ExaConfigError

    if any(c in framework_id for c in ("/", "\\", "..", "\x00", ";", " ")):
        available = ", ".join(AVAILABLE_FRAMEWORKS)
        raise ExaConfigError(
            f"Invalid framework ID: {framework_id!r}. "
            f"Available: {available}"
        )


def load_framework(framework_id: str) -> Framework:
    """Load a framework definition from bundled data."""
    _validate_framework_id(framework_id)
    data_dir = importlib.resources.files("exa.compliance.data")
    text = (data_dir / f"{framework_id}.json").read_text(encoding="utf-8-sig")
    raw = json.loads(text)

    controls = [
        Control(
            control_id=c["ControlId"],
            family=c["Family"],
            description=c.get("Description", c.get("ControlName", "")),
            level=c.get("Level", "Required"),
            siem_validatable=c.get("SiemValidatable", False),
        )
        for c in raw.get("Controls", [])
    ]

    return Framework(
        name=raw.get("Name", framework_id),
        framework=raw.get("Framework", framework_id),
        version=raw.get("Version", ""),
        source_url=raw.get("SourceUrl", ""),
        controls=controls,
    )


def load_control_queries(framework_id: str) -> dict[str, ControlQueryGroup]:
    """Load per-control evidence queries for a framework."""
    data_dir = importlib.resources.files("exa.compliance.data")
    query_file = data_dir / "ControlQueries" / f"{framework_id}.json"

    try:
        text = query_file.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return {}

    raw = json.loads(text)
    result: dict[str, ControlQueryGroup] = {}

    for control_id, group_data in raw.get("queries", {}).items():
        queries = [
            ControlQuery(
                name=q.get("name", ""),
                filter=q.get("filter", ""),
                fields=q.get("fields", []),
                evidence_description=q.get("evidenceDescription", ""),
            )
            for q in group_data.get("queries", [])
        ]
        result[control_id] = ControlQueryGroup(
            name=group_data.get("name", ""),
            queries=queries,
            context_tables=group_data.get("contextTables", []),
            minimum_evidence=group_data.get("minimumEvidence", 10),
            shared_query_group=group_data.get("sharedQueryGroup"),
            concepts=group_data.get("concepts", []),
        )

    return result

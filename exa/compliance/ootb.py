"""Sync OOTB compliance control and mapping tables to Exabeam.

Creates context tables containing framework controls and rule-to-control
mappings, enabling compliance dashboards and enrichment rules.

Ported from SIEM.Tools Public/Compliance/ cmdlets:
  Sync-ExaComplianceFrameworkControls.ps1
  Sync-ExaComplianceMapping.ps1

Key implementation detail (from PS1 lines 298-312):
  The addRecords API requires attribute IDs as record field keys,
  NOT display names. After creating a table, resolve displayName → id
  via GET /tables/{id}, then use those IDs as record keys.
  The built-in "key" attribute always uses literal "key" as its ID.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from exa.compliance.frameworks import load_framework
from exa.context.tables import (
    add_records,
    create_table,
    get_table,
    get_tables,
)

if TYPE_CHECKING:
    from exa.client import ExaClient


@dataclass
class OOTBSyncResult:
    """Result of syncing a framework's controls to a context table."""

    table_name: str
    framework: str
    records_written: int = 0
    records_skipped: int = 0
    created: bool = False
    errors: list[str] = field(default_factory=list)


# EXA-CONTEXT-SCHEMA-35 workaround: column displayNames are globally
# scoped. All columns use prefixed names to avoid collisions.
# Key column uses id="key" (built-in) per PS1 line 270.

_CONTROLS_COLUMNS = [
    "Control Title",
    "Control Family",
    "Control Description",
    "MITRE Techniques",
    "SIEM Testable",
    "Compliance Framework",
]

_MAPPING_COLUMNS = [
    "Control Title",
    "Control Family",
    "Rule Name",
    "Rule Type",
    "MITRE Techniques",
    "Compliance Framework",
]


def _build_attributes(
    columns: list[str],
) -> list[dict[str, Any]]:
    """Build attribute list for table creation.

    Key column always uses built-in id="key".
    Custom columns use displayName (API assigns IDs).
    """
    attrs: list[dict[str, Any]] = [
        {"id": "key", "isKey": True},
    ]
    for col in columns:
        attrs.append({"displayName": col, "isKey": False})
    return attrs


def _resolve_attr_ids(
    client: ExaClient,
    table_id: str,
) -> dict[str, str]:
    """Resolve displayName → attribute ID for a table.

    Ported from PS1 lines 298-308:
      $TableDetail = Get-ExaContextTable -Id $ExistingTable.id
      foreach ($Attr in $TableDetail.attributes) {
          $AttrMap[$Attr.displayName] = $Attr.id
      }

    Returns dict mapping display name to attribute ID.
    """
    detail = get_table(client, table_id)
    attr_map: dict[str, str] = {}

    # Response may nest under "table" or be flat
    attrs = None
    if isinstance(detail, dict):
        if "table" in detail and isinstance(detail["table"], dict):
            attrs = detail["table"].get("attributes", [])
        else:
            attrs = detail.get("attributes", [])

    if attrs:
        for a in attrs:
            dn = a.get("displayName", "")
            aid = a.get("id", "")
            if dn and aid:
                attr_map[dn] = aid

    return attr_map


def _find_or_create_table(
    client: ExaClient,
    table_name: str,
    columns: list[str],
) -> tuple[str, bool, str]:
    """Find existing table or create new one.

    Returns (table_id, created, error).
    """
    existing = get_tables(client, name=table_name, exact=True)
    if existing:
        return existing[0]["id"], False, ""

    try:
        attrs = _build_attributes(columns)
        resp = create_table(
            client, table_name, attributes=attrs,
        )
        table_id = (
            resp.get("id")
            or resp.get("table", {}).get("id", "")
        )
        if not table_id:
            return "", False, f"No ID in response: {resp}"
        client.batch_write_sleep()
        return table_id, True, ""
    except Exception as e:
        return "", False, str(e)


def _build_control_records(
    fw_name: str,
    controls: list[Any],
    attr_map: dict[str, str],
) -> list[dict[str, str]]:
    """Build context table records for framework controls.

    Record field keys use resolved attribute IDs (not display names).
    Ported from PS1 lines 335-361.
    """
    # Resolve attribute IDs for each column
    title_id = attr_map.get("Control Title", "Control Title")
    family_id = attr_map.get("Control Family", "Control Family")
    desc_id = attr_map.get(
        "Control Description", "Control Description",
    )
    mitre_id = attr_map.get(
        "MITRE Techniques", "MITRE Techniques",
    )
    testable_id = attr_map.get("SIEM Testable", "SIEM Testable")
    fw_id = attr_map.get(
        "Compliance Framework", "Compliance Framework",
    )

    records: list[dict[str, str]] = []
    for c in controls:
        desc = (
            c.description[:497] + "..."
            if len(c.description) > 500
            else c.description
        )
        records.append({
            "key": c.control_id,
            title_id: c.description[:80],
            family_id: c.family,
            desc_id: desc,
            mitre_id: "",
            testable_id: "Yes" if c.siem_validatable else "No",
            fw_id: fw_name,
        })
    return records


def sync_ootb_tables(
    client: ExaClient,
    framework: str = "NIST_CSF",
    *,
    dry_run: bool = False,
) -> list[OOTBSyncResult]:
    """Sync framework controls and mapping tables.

    Creates two tables per framework:
      1. "Compliance - <Name> Controls" — all leaf controls
      2. "Compliance - <Name> Mapping" — rule-to-control mappings

    Args:
        client: Authenticated ExaClient.
        framework: Framework ID (e.g. "NIST_CSF").
        dry_run: Report what would be written without API calls.
    """
    fw = load_framework(framework)
    results: list[OOTBSyncResult] = []

    # --- Controls table ---
    controls_name = f"Compliance - {fw.name} Controls"
    controls_result = OOTBSyncResult(
        table_name=controls_name, framework=fw.name,
    )

    leaf = fw.leaf_controls

    if dry_run:
        controls_result.records_written = len(leaf)
        results.append(controls_result)
        mapping_result = OOTBSyncResult(
            table_name=f"Compliance - {fw.name} Mapping",
            framework=fw.name,
        )
        results.append(mapping_result)
        return results

    # Create/find controls table
    table_id, created, err = _find_or_create_table(
        client, controls_name, _CONTROLS_COLUMNS,
    )
    if err:
        controls_result.errors.append(f"Table: {err}")
        results.append(controls_result)
        return results
    controls_result.created = created

    # Resolve attribute IDs from table schema
    attr_map = _resolve_attr_ids(client, table_id)

    # Build and write control records using attribute IDs
    records = _build_control_records(fw.name, leaf, attr_map)
    try:
        add_records(client, table_id, records, operation="replace")
        controls_result.records_written = len(records)
    except Exception as e:
        controls_result.errors.append(f"Write: {e}")
    results.append(controls_result)

    # --- Mapping table ---
    mapping_result = _sync_mapping_table(client, fw)
    results.append(mapping_result)

    return results


def _sync_mapping_table(
    client: ExaClient,
    fw: Any,
) -> OOTBSyncResult:
    """Sync rule-to-control mapping table.

    Ported from Sync-ExaComplianceMapping.ps1:
    1. GET all correlation rules
    2. Extract MITRE techniques from rule descriptions
    3. Create mapping table with resolved attribute IDs
    4. Write one record per rule
    """
    from exa.correlation.rules import get_rules

    mapping_name = f"Compliance - {fw.name} Mapping"
    result = OOTBSyncResult(
        table_name=mapping_name, framework=fw.name,
    )

    # Create/find mapping table
    table_id, created, err = _find_or_create_table(
        client, mapping_name, _MAPPING_COLUMNS,
    )
    if err:
        result.errors.append(f"Table: {err}")
        return result
    result.created = created

    # Resolve attribute IDs
    attr_map = _resolve_attr_ids(client, table_id)
    title_id = attr_map.get("Control Title", "Control Title")
    family_id = attr_map.get(
        "Control Family", "Control Family",
    )
    rule_name_id = attr_map.get("Rule Name", "Rule Name")
    rule_type_id = attr_map.get("Rule Type", "Rule Type")
    mitre_id = attr_map.get(
        "MITRE Techniques", "MITRE Techniques",
    )
    fw_id = attr_map.get(
        "Compliance Framework", "Compliance Framework",
    )

    # Get correlation rules — don't fail if none exist
    try:
        rules = get_rules(client)
    except Exception:
        rules = []

    if not rules:
        result.records_written = 0
        return result

    # Build mapping records
    records: list[dict[str, str]] = []
    for rule in rules:
        rule_name = rule.get("name", "")
        desc = rule.get("description", "")

        # Extract MITRE techniques from description
        # Sigma converter packs as "MITRE: T1059.001,T1078"
        mitre_techs = ""
        if "MITRE:" in desc:
            mitre_part = desc.split("MITRE:")[1].split("|")[0]
            mitre_techs = mitre_part.strip().rstrip(",")

        records.append({
            "key": rule_name,
            title_id: "",
            family_id: "",
            rule_name_id: rule_name,
            rule_type_id: "correlation",
            mitre_id: mitre_techs,
            fw_id: fw.name,
        })

    if records:
        try:
            add_records(
                client, table_id, records, operation="replace",
            )
            result.records_written = len(records)
        except Exception as e:
            result.errors.append(f"Write: {e}")

    return result

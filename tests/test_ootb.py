"""Tests for compliance OOTB control table sync."""

from exa.compliance.ootb import _build_control_records, sync_ootb_tables

# Simulated attr_map: displayName → attribute ID
# In production these come from GET /tables/{id}.attributes
_MOCK_ATTR_MAP = {
    "Control Title": "ctrl_title_abc",
    "Control Family": "ctrl_family_def",
    "Control Description": "ctrl_desc_ghi",
    "MITRE Techniques": "mitre_techs_jkl",
    "SIEM Testable": "siem_test_mno",
    "Compliance Framework": "comp_fw_pqr",
}


class TestBuildControlRecords:
    def test_builds_from_framework(self) -> None:
        """Build records from a real framework."""
        from exa.compliance.frameworks import load_framework

        fw = load_framework("NIST_CSF")
        records = _build_control_records(
            fw.name, fw.leaf_controls, _MOCK_ATTR_MAP,
        )
        assert len(records) == len(fw.leaf_controls)
        # Key uses built-in "key" attribute ID
        assert records[0]["key"]
        # Other fields use resolved attribute IDs
        assert records[0]["ctrl_family_def"]
        assert records[0]["comp_fw_pqr"] == "NIST CSF v2.0"

    def test_description_truncated(self) -> None:
        """Description is truncated to 500 chars."""
        from exa.compliance.frameworks import Control

        long_desc = "x" * 600
        controls = [
            Control(
                control_id="TEST-01",
                family="Test",
                description=long_desc,
                siem_validatable=True,
            ),
        ]
        records = _build_control_records(
            "Test", controls, _MOCK_ATTR_MAP,
        )
        assert len(records[0]["ctrl_desc_ghi"]) <= 500

    def test_testable_flag(self) -> None:
        """Testable column reflects siem_validatable."""
        from exa.compliance.frameworks import Control

        controls = [
            Control("A-01", "F", "desc", siem_validatable=True),
            Control("A-02", "F", "desc", siem_validatable=False),
        ]
        records = _build_control_records(
            "Test", controls, _MOCK_ATTR_MAP,
        )
        assert records[0]["siem_test_mno"] == "Yes"
        assert records[1]["siem_test_mno"] == "No"

    def test_uses_compliance_framework_column(self) -> None:
        """Uses 'Compliance Framework' attribute ID."""
        from exa.compliance.frameworks import Control

        controls = [Control("X-01", "F", "desc")]
        records = _build_control_records(
            "NIST CSF v2.0", controls, _MOCK_ATTR_MAP,
        )
        assert "comp_fw_pqr" in records[0]
        # Should NOT have raw "Framework" key
        assert "Framework" not in records[0]

    def test_falls_back_to_display_name(self) -> None:
        """Falls back to display name if attr_map is empty."""
        from exa.compliance.frameworks import Control

        controls = [Control("X-01", "F", "desc")]
        records = _build_control_records(
            "Test", controls, {},
        )
        # Without attr_map, keys are display names (fallback)
        assert "Control Family" in records[0]

    def test_record_count_nist_csf(self) -> None:
        """NIST CSF v2.0 should produce 106 leaf control records."""
        from exa.compliance.frameworks import load_framework

        fw = load_framework("NIST_CSF")
        records = _build_control_records(
            fw.name, fw.leaf_controls, {},
        )
        assert len(records) == 106


class TestDryRun:
    def test_dry_run_counts_records(self) -> None:
        """Dry run returns record count without API calls."""
        from unittest.mock import MagicMock

        client = MagicMock()
        results = sync_ootb_tables(
            client, "NIST_CSF", dry_run=True,
        )
        assert len(results) == 2
        assert results[0].records_written > 0
        assert results[0].table_name == (
            "Compliance - NIST CSF v2.0 Controls"
        )
        assert results[1].table_name == (
            "Compliance - NIST CSF v2.0 Mapping"
        )
        # No API calls should have been made
        client.get.assert_not_called()
        client.post.assert_not_called()

"""Tests for compliance OOTB control table sync."""

from exa.compliance.ootb import _build_records, sync_ootb_tables


class TestBuildRecords:
    def test_builds_from_framework(self):
        """Build records from a real framework."""
        from exa.compliance.frameworks import load_framework

        fw = load_framework("NIST_CSF")
        records = _build_records(fw.name, fw.leaf_controls)
        assert len(records) == len(fw.leaf_controls)
        assert records[0]["key"]  # has a control_id
        assert records[0]["Family"]  # has a family
        assert records[0]["Compliance Framework"] == "NIST CSF v2.0"

    def test_description_truncated(self):
        """Description is truncated to 500 chars."""
        from exa.compliance.frameworks import Control

        long_desc = "x" * 600
        controls = [
            Control(
                control_id="TEST-01",
                family="Test",
                description=long_desc,
                siem_validatable=True,
            )
        ]
        records = _build_records("Test", controls)
        assert len(records[0]["Description"]) <= 500

    def test_testable_flag(self):
        """Testable column reflects siem_validatable."""
        from exa.compliance.frameworks import Control

        controls = [
            Control("A-01", "F", "desc", siem_validatable=True),
            Control("A-02", "F", "desc", siem_validatable=False),
        ]
        records = _build_records("Test", controls)
        assert records[0]["Testable"] == "Yes"
        assert records[1]["Testable"] == "No"

    def test_uses_compliance_framework_column(self):
        """Uses 'Compliance Framework' not 'Framework' (EXA-CONTEXT-SCHEMA-35)."""
        from exa.compliance.frameworks import Control

        controls = [Control("X-01", "F", "desc")]
        records = _build_records("NIST CSF v2.0", controls)
        assert "Compliance Framework" in records[0]
        assert "Framework" not in records[0]


class TestDryRun:
    def test_dry_run_counts_records(self):
        """Dry run returns record count without API calls."""
        from unittest.mock import MagicMock

        client = MagicMock()
        result = sync_ootb_tables(client, "NIST_CSF", dry_run=True)
        assert result.records_written > 0
        assert result.table_name == "Compliance - NIST CSF v2.0 Controls"
        # No API calls should have been made
        client.get.assert_not_called()
        client.post.assert_not_called()

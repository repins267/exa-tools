"""Tests for exa/cli/tables.py — pure helpers + mock-based command tests."""

import pytest

from exa.cli.tables import _derive_attributes, _parse_csv_file

BASE_URL = "https://api.us-west.exabeam.cloud"
TABLES_URL = f"{BASE_URL}/context-management/v1/tables"


# ---------------------------------------------------------------------------
# Pure helper tests — no mocking needed
# ---------------------------------------------------------------------------


class TestParseCsvFile:
    def test_basic(self, tmp_path):
        csv = tmp_path / "test.csv"
        csv.write_text("key,value\nalpha,1\nbeta,2\n", encoding="utf-8")
        headers, rows = _parse_csv_file(str(csv))
        assert headers == ["key", "value"]
        assert rows == [{"key": "alpha", "value": "1"}, {"key": "beta", "value": "2"}]

    def test_strips_whitespace(self, tmp_path):
        csv = tmp_path / "test.csv"
        csv.write_text(" key , value \n alpha , 1 \n", encoding="utf-8")
        headers, rows = _parse_csv_file(str(csv))
        assert headers == ["key", "value"]
        assert rows[0] == {"key": "alpha", "value": "1"}

    def test_skips_blank_rows(self, tmp_path):
        csv = tmp_path / "test.csv"
        csv.write_text("key,value\nalpha,1\n,\nbeta,2\n", encoding="utf-8")
        headers, rows = _parse_csv_file(str(csv))
        assert len(rows) == 2

    def test_bom_stripped(self, tmp_path):
        csv = tmp_path / "test.csv"
        csv.write_bytes(b"\xef\xbb\xbfkey,value\nalpha,1\n")
        headers, rows = _parse_csv_file(str(csv))
        assert headers[0] == "key"

    def test_empty_file(self, tmp_path):
        csv = tmp_path / "test.csv"
        csv.write_text("", encoding="utf-8")
        headers, rows = _parse_csv_file(str(csv))
        assert headers == []
        assert rows == []


class TestDeriveAttributes:
    def test_first_col_is_key_by_default(self):
        attrs = _derive_attributes(["key", "name", "dept"], key_col="key")
        assert attrs[0] == {"id": "key", "isKey": True}
        assert attrs[1] == {"id": "name", "isKey": False}

    def test_named_key_col(self):
        attrs = _derive_attributes(["email", "name", "dept"], key_col="email")
        key_attrs = [a for a in attrs if a["isKey"]]
        assert len(key_attrs) == 1
        assert key_attrs[0]["id"] == "email"

    def test_all_cols_present(self):
        headers = ["a", "b", "c"]
        attrs = _derive_attributes(headers, key_col="a")
        assert [a["id"] for a in attrs] == ["a", "b", "c"]

    def test_missing_key_raises(self):
        with pytest.raises(ValueError, match="Key column 'x' not found"):
            _derive_attributes(["a", "b"], key_col="x")


# ---------------------------------------------------------------------------
# Mock-based command tests via ExaClient
# ---------------------------------------------------------------------------


TABLE_ROW = {
    "id": "tbl-uuid-001",
    "name": "My Table",
    "displayName": "My Table",
    "contextType": "Other",
    "source": "Custom",
    "totalItems": 42,
    "lastUpdated": 1_700_000_000,
}


class TestGetTables:
    def test_list_tables_calls_get(self, exa, mock_auth):
        mock_auth.add_response(url=TABLES_URL, method="GET", json=[TABLE_ROW])
        from exa.context import get_tables

        result = get_tables(exa)
        assert len(result) == 1
        assert result[0]["id"] == "tbl-uuid-001"

    def test_list_tables_name_filter(self, exa, mock_auth):
        # get_tables filters client-side — no query param sent to API
        other_row = {**TABLE_ROW, "id": "tbl-uuid-002", "name": "Other Table", "displayName": "Other Table"}
        mock_auth.add_response(url=TABLES_URL, method="GET", json=[TABLE_ROW, other_row])
        from exa.context import get_tables

        result = get_tables(exa, name="my table")
        assert len(result) == 1
        assert result[0]["id"] == "tbl-uuid-001"


class TestCreateTable:
    def test_create_table_no_csv(self, exa, mock_auth):
        mock_auth.add_response(
            url=TABLES_URL,
            method="POST",
            json={"table": {"id": "new-tbl-001", "displayName": "Test Table"}},
        )
        from exa.context import create_table

        result = create_table(
            exa,
            "Test Table",
            context_type="Other",
            attributes=[{"id": "key", "isKey": True}],
        )
        table_obj = result.get("table", result)
        assert table_obj["id"] == "new-tbl-001"

    def test_create_table_with_csv_uploads_records(self, exa, mock_auth, tmp_path):
        csv = tmp_path / "data.csv"
        csv.write_text("key,label\nalpha,A\nbeta,B\n", encoding="utf-8")

        mock_auth.add_response(
            url=TABLES_URL,
            method="POST",
            json={"table": {"id": "new-tbl-002"}},
        )
        mock_auth.add_response(
            url=f"{TABLES_URL}/new-tbl-002/addRecords",
            method="POST",
            json={"status": "ok"},
        )

        from exa.context import add_records, create_table
        from exa.cli.tables import _derive_attributes, _parse_csv_file

        headers, rows = _parse_csv_file(str(csv))
        attrs = _derive_attributes(headers, key_col="key")
        result = create_table(exa, "New Table", context_type="Other", attributes=attrs)
        table_obj = result.get("table", result)
        assert table_obj["id"] == "new-tbl-002"
        add_records(exa, table_obj["id"], rows, operation="append")
        assert len(rows) == 2


class TestUploadRecords:
    def test_upload_append_operation(self, exa, mock_auth, tmp_path):
        csv = tmp_path / "data.csv"
        csv.write_text("key,value\nalpha,1\n", encoding="utf-8")

        mock_auth.add_response(
            url=f"{TABLES_URL}/tbl-uuid-001/addRecords",
            method="POST",
            json={"status": "ok"},
        )

        import json
        from exa.context import add_records
        from exa.cli.tables import _parse_csv_file

        _, rows = _parse_csv_file(str(csv))
        add_records(exa, "tbl-uuid-001", rows, operation="append")

        req = mock_auth.get_request(url=f"{TABLES_URL}/tbl-uuid-001/addRecords")
        body = json.loads(req.content)
        assert "data" in body
        assert body["data"][0]["key"] == "alpha"
        assert body["operation"] == "append"

    def test_upload_replace_operation(self, exa, mock_auth, tmp_path):
        csv = tmp_path / "data.csv"
        csv.write_text("key,value\nalpha,1\n", encoding="utf-8")

        mock_auth.add_response(
            url=f"{TABLES_URL}/tbl-uuid-001/addRecords",
            method="POST",
            json={"status": "ok"},
        )

        import json
        from exa.context import add_records
        from exa.cli.tables import _parse_csv_file

        _, rows = _parse_csv_file(str(csv))
        add_records(exa, "tbl-uuid-001", rows, operation="replace")

        req = mock_auth.get_request(url=f"{TABLES_URL}/tbl-uuid-001/addRecords")
        body = json.loads(req.content)
        assert body["operation"] == "replace"
        assert "data" in body

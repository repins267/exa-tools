"""Tests for context table operations."""

from exa.context import (
    add_records,
    create_table,
    delete_records,
    delete_table,
    get_attributes,
    get_records,
    get_table,
    get_tables,
)

BASE_URL = "https://api.us-west.exabeam.cloud"


class TestGetTables:
    def test_list_all(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=[
                {"name": "AI/LLM Web Domains", "id": "t1"},
                {"name": "Compliance Mapping", "id": "t2"},
            ],
        )
        result = get_tables(exa)
        assert len(result) == 2

    def test_filter_by_name_substring(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=[
                {"name": "AI/LLM Web Domains", "id": "t1"},
                {"name": "Compliance Mapping", "id": "t2"},
            ],
        )
        result = get_tables(exa, name="AI/LLM")
        assert len(result) == 1
        assert result[0]["id"] == "t1"

    def test_filter_by_name_exact(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="GET",
            json=[
                {"name": "AI/LLM Web Domains", "id": "t1"},
                {"name": "AI/LLM", "id": "t2"},
            ],
        )
        result = get_tables(exa, name="AI/LLM", exact=True)
        assert len(result) == 1
        assert result[0]["id"] == "t2"


class TestGetTable:
    def test_get_by_id(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/t1",
            method="GET",
            json={"table": {"id": "t1", "name": "Test"}},
        )
        result = get_table(exa, "t1")
        assert result["table"]["id"] == "t1"


class TestCreateTable:
    def test_create_basic(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="POST",
            json={"table": {"id": "new-1", "name": "My Table"}},
        )
        result = create_table(exa, "My Table")
        assert result["table"]["id"] == "new-1"

    def test_create_with_attributes(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables",
            method="POST",
            json={"table": {"id": "new-2"}},
        )
        result = create_table(
            exa,
            "Privileged Users",
            context_type="User",
            attributes=[{"id": "key", "isKey": True}, {"id": "risk"}],
        )
        assert result["table"]["id"] == "new-2"


class TestDeleteTable:
    def test_delete(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/t1?deleteUnusedCustomAttributes=false",
            method="DELETE",
            text="",
            status_code=204,
        )
        delete_table(exa, "t1")  # should not raise


class TestGetAttributes:
    def test_get_by_type(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/attributes/Other",
            method="GET",
            json={"attributes": [{"id": "key", "displayName": "Key"}]},
        )
        result = get_attributes(exa, "Other")
        assert result[0]["id"] == "key"


class TestRecords:
    def test_get_records(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/t1/records?limit=1000&offset=0",
            method="GET",
            json={"records": [{"key": "admin@test.com"}]},
        )
        result = get_records(exa, "t1")
        assert len(result["records"]) == 1

    def test_add_records(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/t1/addRecords",
            method="POST",
            json={"status": "ok"},
        )
        result = add_records(exa, "t1", [{"key": "user@test.com"}])
        assert result["status"] == "ok"

    def test_add_records_batching(self, exa, mock_auth):
        """Records over 20k should be split into batches."""
        # Register two responses for two batches
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/t1/addRecords",
            method="POST",
            json={"batch": 1},
        )
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/t1/addRecords",
            method="POST",
            json={"batch": 2},
        )
        data = [{"key": f"user{i}"} for i in range(25_000)]
        result = add_records(exa, "t1", data)
        assert result["batch"] == 2  # last batch response returned

    def test_delete_records(self, exa, mock_auth):
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/t1/deleteRecords",
            method="DELETE",
            json={"deleted": 2},
        )
        result = delete_records(exa, "t1", ["rec-1", "rec-2"])
        assert result["deleted"] == 2

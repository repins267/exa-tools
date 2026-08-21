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


class TestTrackedUpload:
    """add_records_tracked + poll_upload_status (EXA-ADDRECORDS-ASYNC).

    addRecords returns HTTP 200 with a trackerId BEFORE the records are
    queryable, so an immediate read returns the pre-write state and reads as a
    failed write. Re-running to "fix" that duplicates the payload, because
    addRecords is additive. These tests pin the behaviour that prevents it.
    """

    TABLE = "tbl-1"
    ADD_URL = f"{BASE_URL}/context-management/v1/tables/tbl-1/addRecords"

    def test_returns_a_tracker_per_batch(self, exa, mock_auth):
        """add_records() returned only the LAST batch's response, discarding
        every earlier trackerId -- over 20k records that loses the only handle
        on whether the first batches landed."""
        from exa.context.tables import _BATCH_SIZE, add_records_tracked

        for n in range(2):
            mock_auth.add_response(
                url=self.ADD_URL,
                method="POST",
                json={"trackerId": f"trk-{n}", "jsonEntries": 1, "totalDuplicates": 0},
            )
        data = [{"key": f"k{i}"} for i in range(_BATCH_SIZE + 1)]
        results = add_records_tracked(exa, self.TABLE, data)

        assert len(results) == 2, "one UploadResult per batch"
        assert [r.tracker_id for r in results] == ["trk-0", "trk-1"]
        assert results[0].submitted == _BATCH_SIZE
        assert results[1].submitted == 1

    def test_poll_reports_completion(self, exa, mock_auth):
        from exa.context.tables import UploadResult, poll_upload_status

        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/uploadStatus/trk-1",
            method="GET",
            json={"status": "Completed", "totalUploaded": 6, "totalErrors": 0},
        )
        r = poll_upload_status(
            exa, UploadResult(tracker_id="trk-1", submitted=6), interval_s=0
        )
        assert r.status == "Completed"
        assert r.uploaded == 6
        assert r.ok is True

    def test_errors_make_it_not_ok(self, exa, mock_auth):
        """Completed with errors is not success -- the tenant reports both."""
        from exa.context.tables import UploadResult, poll_upload_status

        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/uploadStatus/trk-2",
            method="GET",
            json={"status": "Completed", "totalUploaded": 4, "totalErrors": 2},
        )
        r = poll_upload_status(
            exa, UploadResult(tracker_id="trk-2", submitted=6), interval_s=0
        )
        assert r.errors == 2
        assert r.ok is False

    def test_timeout_is_not_reported_as_failure(self, exa, mock_auth):
        """A slow write must never read as a failed one.

        Calling a still-in-flight write "failed" is exactly what triggers the
        duplicate re-run this module exists to prevent.
        """
        from exa.context.tables import UploadResult, poll_upload_status

        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/uploadStatus/trk-3",
            method="GET",
            json={"status": "InProgress", "totalUploaded": 0, "totalErrors": 0},
            is_reusable=True,
        )
        r = poll_upload_status(
            exa,
            UploadResult(tracker_id="trk-3", submitted=6),
            timeout_s=0.05,
            interval_s=0.01,
        )
        assert r.timed_out is True
        assert r.errors == 0, "a timeout must not invent errors"
        assert r.ok is False, "but it is not success either"

    def test_missing_tracker_is_surfaced(self, exa, mock_auth):
        """No trackerId means the write cannot be verified -- say so rather than
        assuming it worked."""
        from exa.context.tables import UploadResult, poll_upload_status

        r = poll_upload_status(exa, UploadResult(tracker_id="", submitted=6))
        assert r.status == "NoTracker"
        assert r.ok is False

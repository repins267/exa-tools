"""Tests for snapshot -> manifest -> replace on context tables.

These pin the three safety properties that make a whole-table replace recoverable.
On an Exabeam-managed table deleteRecords returns 404 (EXA-COLLECTOR-API-9), so a
replace is the only edit path AND is irreversible without the manifest. Each test
below corresponds to a way that guarantee can be lost.
"""

from __future__ import annotations

import pytest

from exa.context.safe_replace import (
    ReplaceAbortedError,
    is_managed,
    list_manifests,
    load_manifest,
    replace_table,
    restore,
)

BASE_URL = "https://api.us-west.exabeam.cloud"
TABLE_ID = "tbl-abc123"

ORIGINAL = [{"key": "openai.com"}, {"key": "anthropic.com"}]
NEW = [{"key": "openai.com"}, {"key": "perplexity.ai"}]


@pytest.fixture(autouse=True)
def _isolate_manifests(tmp_path, monkeypatch):
    """Never write manifests into the developer's real ~/.exa during tests."""
    monkeypatch.setattr("exa.context.safe_replace.MANIFEST_DIR", tmp_path / "rollback")


def _api_calls(mock_auth):
    """Requests excluding the OAuth handshake the client fixture performs."""
    return [r for r in mock_auth.get_requests() if "/auth/v1/token" not in str(r.url)]


def _mock_records(mock_auth, records):
    mock_auth.add_response(
        url=f"{BASE_URL}/context-management/v1/tables/{TABLE_ID}/records"
        "?limit=100000&offset=0",
        method="GET",
        json={"records": records},
    )


def _mock_replace_ok(mock_auth):
    mock_auth.add_response(
        url=f"{BASE_URL}/context-management/v1/tables/{TABLE_ID}/addRecords",
        method="POST",
        json={"jsonEntries": 2, "trackerId": "deadbeef"},
    )


class TestIsManaged:
    def test_exabeam_source_is_managed(self):
        assert is_managed({"source": "Exabeam"}) is True

    def test_custom_source_is_not_managed(self):
        assert is_managed({"source": "Custom"}) is False

    @pytest.mark.parametrize("table", [{}, {"source": None}, {"source": ""}, {"source": "?"}])
    def test_unknown_source_fails_toward_caution(self, table):
        """Guessing 'Custom' on a managed table is what loses data."""
        assert is_managed(table) is True


class TestReplaceTable:
    def test_writes_manifest_containing_full_original(self, exa, mock_auth, tmp_path):
        _mock_records(mock_auth, ORIGINAL)
        _mock_replace_ok(mock_auth)

        path = replace_table(
            exa, TABLE_ID, NEW,
            tenant="sademodev22",
            display_name="AI/LLM Web Domains",
            source="Exabeam",
            reason="test",
        )

        assert path is not None
        manifest = load_manifest(path)
        # The FULL prior contents, not a delta -- a delta cannot undo a replace.
        assert manifest.original_records == ORIGINAL
        assert manifest.record_count == 2
        assert manifest.table_source == "Exabeam"
        assert manifest.reason == "test"

    def test_refuses_empty_record_set(self, exa, mock_auth):
        """Zero records means the sync produced nothing -- stop, don't continue.

        Not because it would wipe the table (it cannot -- see the test below),
        but because a silent no-op reporting success is how a broken upstream
        merge gets mistaken for a completed sync.
        """
        with pytest.raises(ReplaceAbortedError, match="0 records"):
            replace_table(exa, TABLE_ID, [], tenant="t", display_name="Web Domains")

        # Nothing was read or written -- it aborts before touching the API.
        assert _api_calls(mock_auth) == []

    def test_allow_empty_snapshots_but_cannot_actually_empty_the_table(
        self, exa, mock_auth
    ):
        """An empty replace issues ZERO requests -- it is inert, not a wipe.

        add_records batches with ceil(len/20000), so zero records means no
        call is made. The manifest is still written, and the table is
        unchanged. Pinning this so nobody assumes replace-with-nothing clears
        a table.
        """
        _mock_records(mock_auth, ORIGINAL)
        path = replace_table(
            exa, TABLE_ID, [], tenant="t", display_name="X", allow_empty=True
        )
        assert path is not None
        assert load_manifest(path).original_records == ORIGINAL
        writes = [r for r in _api_calls(mock_auth)
                  if r.method == "POST" and "addRecords" in str(r.url)]
        assert writes == [], "an empty replace should issue no request at all"

    def test_aborts_without_writing_when_snapshot_fails(self, exa, mock_auth):
        """If the prior state cannot be captured, the replace must not happen."""
        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/{TABLE_ID}/records"
            "?limit=100000&offset=0",
            method="GET",
            status_code=500,
        )
        with pytest.raises(ReplaceAbortedError, match="could not snapshot"):
            replace_table(exa, TABLE_ID, NEW, tenant="t", display_name="X")

        writes = [r for r in _api_calls(mock_auth) if r.method == "POST"
                  and "addRecords" in str(r.url)]
        assert writes == [], "replace proceeded despite an unreadable snapshot"

    def test_dry_run_snapshots_but_does_not_write(self, exa, mock_auth):
        _mock_records(mock_auth, ORIGINAL)
        path = replace_table(
            exa, TABLE_ID, NEW, tenant="t", display_name="X", dry_run=True
        )
        assert path is None
        writes = [r for r in _api_calls(mock_auth) if r.method == "POST"
                  and "addRecords" in str(r.url)]
        assert writes == []
        assert list_manifests("t") == []


class TestRestore:
    def test_restore_replays_the_snapshot(self, exa, mock_auth):
        _mock_records(mock_auth, ORIGINAL)
        _mock_replace_ok(mock_auth)
        path = replace_table(exa, TABLE_ID, NEW, tenant="t", display_name="X")

        mock_auth.add_response(
            url=f"{BASE_URL}/context-management/v1/tables/{TABLE_ID}/addRecords",
            method="POST",
            json={"jsonEntries": 2, "trackerId": "cafe"},
        )
        assert restore(exa, load_manifest(path)) == 2

    def test_restore_of_an_empty_snapshot_is_a_no_op(self, exa, mock_auth):
        _mock_records(mock_auth, [])
        _mock_replace_ok(mock_auth)
        path = replace_table(
            exa, TABLE_ID, NEW, tenant="t", display_name="X", allow_empty=True
        )
        before = len(_api_calls(mock_auth))
        assert restore(exa, load_manifest(path)) == 0
        # No write attempted for an empty restore.
        assert len(_api_calls(mock_auth)) == before

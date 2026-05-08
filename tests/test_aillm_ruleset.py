"""Tests for exa.aillm.ruleset — sync_dlp_ruleset."""

from __future__ import annotations

import pytest

from exa.aillm.ruleset import DEFAULT_KEYWORDS, _match_keywords, sync_dlp_ruleset

BASE_URL = "https://api.us-west.exabeam.cloud"

# ---------------------------------------------------------------------------
# Unit tests — _match_keywords
# ---------------------------------------------------------------------------


def test_match_keywords_case_insensitive():
    assert _match_keywords("Public AI Domains and Risk", DEFAULT_KEYWORDS)
    assert _match_keywords("LLM Data Exfiltration", DEFAULT_KEYWORDS)
    assert _match_keywords("GenAI Upload Detected", DEFAULT_KEYWORDS)


def test_match_keywords_no_match():
    assert not _match_keywords("Failed Login - VPN", DEFAULT_KEYWORDS)
    assert not _match_keywords("Brute Force Detected", DEFAULT_KEYWORDS)


def test_match_keywords_custom():
    assert _match_keywords("Copilot Activity", ["copilot"])
    assert not _match_keywords("Copilot Activity", ["openai"])


def test_match_keywords_word_boundary():
    # "ai" must NOT match mid-word — word-boundary protection
    assert not _match_keywords("airedale", ["ai"])
    assert not _match_keywords("email alert", ["ai"])
    assert not _match_keywords("domain activity", ["ai"])
    # But standalone "AI" in a real alert name should match
    assert _match_keywords("Public AI Domains and Risk", ["ai"])
    assert _match_keywords("AI Upload Detected", ["ai"])


# ---------------------------------------------------------------------------
# Integration tests — sync_dlp_ruleset
# ---------------------------------------------------------------------------


def _tables_response(table_id: str = "tbl-dlp-001") -> list[dict]:
    return [
        {
            "id": table_id,
            "name": "AI/LLM DLP Rulesets",
            "displayName": "AI/LLM DLP Rulesets",
            "totalItems": 0,
            "source": "Custom",
            "contextType": "Other",
        }
    ]


def _alerts_response(names: list[str]) -> dict:
    return {
        "rows": [{"alertName": n} for n in names],
        "totalRows": len(names),
        "startTime": "2026-01-01T00:00:00Z",
        "endTime": "2026-04-01T00:00:00Z",
    }


def test_sync_dry_run(exa, httpx_mock):
    """Dry run returns matched names without calling write endpoint."""
    httpx_mock.add_response(
        url=f"{BASE_URL}/threat-center/v1/search/alerts",
        method="POST",
        json=_alerts_response(["Public AI Domains and Risk", "Failed Login", "LLM Upload"]),
    )

    result = sync_dlp_ruleset(exa, dry_run=True)

    assert result.alerts_searched == 3
    assert result.alert_names_found == 3
    assert result.keyword_matched == 2  # "Public AI Domains and Risk" + "LLM Upload"
    assert result.upserted == 0
    assert result.success


def test_sync_writes_new_records(exa, httpx_mock):
    """Matched alert names are written to the context table."""
    httpx_mock.add_response(
        url=f"{BASE_URL}/threat-center/v1/search/alerts",
        method="POST",
        json=_alerts_response(["Public AI Domains and Risk", "Brute Force", "GenAI Data Transfer"]),
    )
    httpx_mock.add_response(
        url=f"{BASE_URL}/context-management/v1/tables",
        method="GET",
        json=_tables_response("tbl-001"),
    )
    # Existing records (empty table)
    httpx_mock.add_response(
        url=f"{BASE_URL}/context-management/v1/tables/tbl-001/records?limit=100000&offset=0",
        method="GET",
        json={"records": [], "paging": {"count": 0, "limit": 100000, "offset": 0, "pages": 0}},
    )
    httpx_mock.add_response(
        url=f"{BASE_URL}/context-management/v1/tables/tbl-001/addRecords",
        method="POST",
        json={"status": "ok"},
    )

    result = sync_dlp_ruleset(exa)

    assert result.keyword_matched == 2
    assert result.already_present == 0
    assert result.upserted == 2
    assert result.success


def test_sync_skips_existing_records(exa, httpx_mock):
    """Records already in the table are not re-written."""
    httpx_mock.add_response(
        url=f"{BASE_URL}/threat-center/v1/search/alerts",
        method="POST",
        json=_alerts_response(["Public AI Domains and Risk", "GenAI Data Transfer"]),
    )
    httpx_mock.add_response(
        url=f"{BASE_URL}/context-management/v1/tables",
        method="GET",
        json=_tables_response("tbl-001"),
    )
    # One already present
    httpx_mock.add_response(
        url=f"{BASE_URL}/context-management/v1/tables/tbl-001/records?limit=100000&offset=0",
        method="GET",
        json={
            "records": [{"key": "Public AI Domains and Risk"}],
            "paging": {"count": 1, "limit": 100000, "offset": 0, "pages": 1},
        },
    )
    httpx_mock.add_response(
        url=f"{BASE_URL}/context-management/v1/tables/tbl-001/addRecords",
        method="POST",
        json={"status": "ok"},
    )

    result = sync_dlp_ruleset(exa)

    assert result.keyword_matched == 2
    assert result.already_present == 1
    assert result.upserted == 1
    assert result.success


def test_sync_force_replaces(exa, httpx_mock):
    """--force skips dedup and calls replace operation."""
    httpx_mock.add_response(
        url=f"{BASE_URL}/threat-center/v1/search/alerts",
        method="POST",
        json=_alerts_response(["Public AI Domains and Risk"]),
    )
    httpx_mock.add_response(
        url=f"{BASE_URL}/context-management/v1/tables",
        method="GET",
        json=_tables_response("tbl-001"),
    )
    httpx_mock.add_response(
        url=f"{BASE_URL}/context-management/v1/tables/tbl-001/addRecords",
        method="POST",
        json={"status": "ok"},
    )

    result = sync_dlp_ruleset(exa, force=True)

    assert result.upserted == 1
    assert result.success


def test_sync_no_ai_alerts_returns_zero(exa, httpx_mock):
    """No AI/LLM-related alerts → keyword_matched=0, no write call."""
    httpx_mock.add_response(
        url=f"{BASE_URL}/threat-center/v1/search/alerts",
        method="POST",
        json=_alerts_response(["Failed Login", "Brute Force", "VPN Anomaly"]),
    )

    result = sync_dlp_ruleset(exa)

    assert result.keyword_matched == 0
    assert result.upserted == 0
    assert result.success


def test_sync_table_not_found_returns_error(exa, httpx_mock):
    """If the DLP Rulesets table doesn't exist, returns an error."""
    httpx_mock.add_response(
        url=f"{BASE_URL}/threat-center/v1/search/alerts",
        method="POST",
        json=_alerts_response(["Public AI Domains and Risk"]),
    )
    httpx_mock.add_response(
        url=f"{BASE_URL}/context-management/v1/tables",
        method="GET",
        json=[],  # No tables
    )

    result = sync_dlp_ruleset(exa)

    assert not result.success
    assert "not found" in result.error.lower()


def test_sync_all_already_present(exa, httpx_mock):
    """All matched names already in table → upserted=0, success=True."""
    httpx_mock.add_response(
        url=f"{BASE_URL}/threat-center/v1/search/alerts",
        method="POST",
        json=_alerts_response(["Public AI Domains and Risk"]),
    )
    httpx_mock.add_response(
        url=f"{BASE_URL}/context-management/v1/tables",
        method="GET",
        json=_tables_response("tbl-001"),
    )
    httpx_mock.add_response(
        url=f"{BASE_URL}/context-management/v1/tables/tbl-001/records?limit=100000&offset=0",
        method="GET",
        json={
            "records": [{"key": "Public AI Domains and Risk"}],
            "paging": {"count": 1, "limit": 100000, "offset": 0, "pages": 1},
        },
    )

    result = sync_dlp_ruleset(exa)

    assert result.keyword_matched == 1
    assert result.already_present == 1
    assert result.upserted == 0
    assert result.success

"""Tests for exa.correlation.validate.validate_eql."""
from __future__ import annotations

import pytest

from exa.correlation.validate import validate_eql

BASE_URL = "https://api.us-west.exabeam.cloud"


def test_validate_eql_success(exa, httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url=f"{BASE_URL}/search/v2/events",
        status_code=200,
        json={"rows": []},
    )
    assert validate_eql(exa, 'activity_type:"file-write"') == []


def test_validate_eql_400_unknown_field(exa, httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url=f"{BASE_URL}/search/v2/events",
        status_code=400,
        text="Field '_raw' is unknown",
    )
    errors = validate_eql(exa, '_raw:RGXi(".*")')
    assert errors
    assert "_raw" in errors[0]


def test_validate_eql_non_400_does_not_block(exa, httpx_mock):
    # 500 is not retried (only 429/503 are); ExaAPIError raised but we return []
    httpx_mock.add_response(
        method="POST",
        url=f"{BASE_URL}/search/v2/events",
        status_code=500,
        text="Internal Server Error",
    )
    assert validate_eql(exa, 'activity_type:"file-write"') == []

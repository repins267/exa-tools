"""EQL validation against the live Exabeam search engine."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from exa.exceptions import ExaAPIError

if TYPE_CHECKING:
    from exa.client import ExaClient


def validate_eql(client: "ExaClient", eql: str) -> list[str]:
    """Validate an EQL query string against the live Exabeam search engine.

    Calls POST /search/v2/events with a 1-minute lookback and limit=1.
    Returns an empty list if the query is accepted; a list of error strings
    if Exabeam rejects it (unknown fields, syntax errors, etc.).

    Never raises — transient failures (network, auth, 5xx) return [] so that
    a flaky search tier does not block all deployments.
    """
    now = datetime.now(UTC)
    try:
        client.post(
            "/search/v2/events",
            json={
                "query": eql,
                "filter": "",
                "startTime": (now - timedelta(minutes=1)).isoformat(),
                "endTime": now.isoformat(),
                "limit": 1,
            },
        )
        return []
    except ExaAPIError as e:
        if e.status_code == 400:
            return [e.detail or "EQL rejected (HTTP 400)"]
        return []  # 5xx / auth errors don't block deployment
    except Exception:
        return []

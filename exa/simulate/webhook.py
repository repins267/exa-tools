"""Webhook Cloud Collector ingest transport.

Ships synthetic events to a tenant's Webhook Cloud Collector.

Two things make this the one place in the toolkit that does not go through
``client._request()``:

1. **Different host.** Ingest lives on ``api2.<region>.exabeam.cloud``, not the
   ``api.<region>`` host ExaClient is bound to.
2. **Different token issuer.** The bearer token is minted when the Webhook
   Cloud Collector is created in the tenant UI. The OAuth token ExaClient holds
   is rejected with ``401 Jwt issuer is not configured``.

The retry behaviour ExaClient's transport would normally provide is
reimplemented here for 429/503 so the exception is narrow rather than a
silent loss of resilience. See EXA-INGEST-API2-HOST in CLAUDE.md.
"""

from __future__ import annotations

import gzip
import json
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient

# Documented limit is 32 MB uncompressed per batch; stay well under it.
_MAX_UNCOMPRESSED_BYTES = 24 * 1024 * 1024
_MAX_RETRIES = 3
_RETRY_STATUSES = frozenset({429, 503})
_TIMEOUT_SECONDS = 60.0


def resolve_ingest_url(client: ExaClient, *, fmt: str = "json") -> str:
    """Derive the Webhook Cloud Collector ingest URL for a client's tenant.

    ``https://api.us-west.exabeam.cloud`` ->
    ``https://api2.us-west.exabeam.cloud/cloud-collectors/v1/logs/json``
    """
    if fmt not in ("json", "raw"):
        raise ValueError(f"fmt must be 'json' or 'raw', got {fmt!r}")

    base = client.base_url.rstrip("/")
    if "://api2." in base:
        api2 = base
    elif "://api." in base:
        api2 = base.replace("://api.", "://api2.", 1)
    else:
        raise ValueError(
            f"Cannot derive ingest host from base URL {base!r}. "
            "Expected an https://api.<region>.exabeam.cloud style URL."
        )
    return f"{api2}/cloud-collectors/v1/logs/{fmt}"


def _batch(events: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Split events into batches below the uncompressed size limit."""
    batches: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    size = 0
    for event in events:
        encoded = len(json.dumps(event).encode("utf-8")) + 1
        if current and size + encoded > _MAX_UNCOMPRESSED_BYTES:
            batches.append(current)
            current = []
            size = 0
        current.append(event)
        size += encoded
    if current:
        batches.append(current)
    return batches


def send_events(
    client: ExaClient,
    events: list[dict[str, Any]],
    *,
    token: str,
    fmt: str = "json",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Send events to the tenant's Webhook Cloud Collector.

    Args:
        client: authenticated ExaClient; used only to resolve the tenant region.
        events: Sysmon-shaped event dicts from ``exa.simulate.scenarios``.
        token: webhook collector bearer token. Never persisted by this module.
        fmt: ``json`` or ``raw``.
        dry_run: build and size the payload without sending.

    Returns:
        dict with ``url``, ``events``, ``batches``, ``sent``, ``dry_run`` and,
        when a send occurred, ``responses`` (one status code per batch).
    """
    import httpx

    url = resolve_ingest_url(client, fmt=fmt)
    batches = _batch(events)
    result: dict[str, Any] = {
        "url": url,
        "events": len(events),
        "batches": len(batches),
        "sent": 0,
        "dry_run": dry_run,
    }
    if dry_run:
        return result

    if not token:
        raise ValueError("A webhook collector token is required to send events.")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Encoding": "gzip",
        "Content-Type": "application/gzip",
    }
    responses: list[int] = []

    for batch in batches:
        if fmt == "json":
            payload = json.dumps(batch).encode("utf-8")
        else:
            payload = "\n".join(json.dumps(e) for e in batch).encode("utf-8")
        body = gzip.compress(payload)

        last_error: Exception | None = None
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                resp = httpx.post(
                    url, content=body, headers=headers, timeout=_TIMEOUT_SECONDS
                )
            except Exception as e:  # network-level failure
                last_error = e
                if attempt == _MAX_RETRIES:
                    raise
                time.sleep(2 ** (attempt - 1))
                continue

            if resp.status_code in _RETRY_STATUSES and attempt < _MAX_RETRIES:
                retry_after = resp.headers.get("Retry-After")
                delay = (
                    float(retry_after)
                    if retry_after and retry_after.isdigit()
                    else 2 ** (attempt - 1)
                )
                time.sleep(delay)
                continue

            if resp.status_code >= 400:
                from exa.exceptions import ExaAPIError

                raise ExaAPIError(resp.status_code, resp.text)

            responses.append(resp.status_code)
            result["sent"] += len(batch)
            break
        else:  # pragma: no cover - defensive
            if last_error is not None:
                raise last_error

    result["responses"] = responses
    return result

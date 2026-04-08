"""Exabeam API client with retry, auto-refresh, and batch helpers."""

from __future__ import annotations

import asyncio
import math
import time
from typing import Any

import httpx

from exa.exceptions import ExaAPIError, ExaAuthError

# Retry defaults matching reference implementation
_RETRY_STATUS_CODES = frozenset({429, 503})
_MAX_RETRIES = 25
_INITIAL_DELAY_MS = 500
_MAX_DELAY_MS = 60_000
_TOKEN_TTL_BUFFER = 60  # refresh 60s before expiry
_BATCH_WRITE_SLEEP = 1.0  # 1s between table writes


class _RetryTransport(httpx.BaseTransport):
    """httpx transport that retries on 429/503 with Retry-After + exponential backoff."""

    def __init__(
        self,
        wrapped: httpx.BaseTransport | None = None,
        *,
        max_retries: int = _MAX_RETRIES,
        initial_delay_ms: int = _INITIAL_DELAY_MS,
        max_delay_ms: int = _MAX_DELAY_MS,
        retry_status_codes: frozenset[int] = _RETRY_STATUS_CODES,
    ) -> None:
        self._wrapped = wrapped or httpx.HTTPTransport()
        self._max_retries = max_retries
        self._initial_delay_ms = initial_delay_ms
        self._max_delay_ms = max_delay_ms
        self._retry_status_codes = retry_status_codes

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        attempt = 0
        while True:
            response = self._wrapped.handle_request(request)
            if response.status_code not in self._retry_status_codes or attempt >= self._max_retries:
                return response
            attempt += 1
            # Retry-After header takes priority
            retry_after = response.headers.get("retry-after")
            if retry_after:
                try:
                    wait_ms = min(int(float(retry_after) * 1000), self._max_delay_ms)
                except ValueError:
                    wait_ms = self._backoff_ms(attempt)
            else:
                wait_ms = self._backoff_ms(attempt)
            response.close()
            time.sleep(wait_ms / 1000)

    def _backoff_ms(self, attempt: int) -> int:
        return min(self._initial_delay_ms * int(math.pow(2, attempt - 1)), self._max_delay_ms)

    def close(self) -> None:
        self._wrapped.close()


class ExaClient:
    """Exabeam New-Scale API client.

    Usage::

        async with ExaClient(base_url, client_id, client_secret) as exa:
            tables = exa.get("/context-management/v1/tables")

    Or synchronously::

        exa = ExaClient(base_url, client_id, client_secret)
        exa.authenticate()
        tables = exa.get("/context-management/v1/tables")
        exa.close()
    """

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        *,
        timeout: float = 30.0,
        max_retries: int = _MAX_RETRIES,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._access_token: str | None = None
        self._expires_at: float = 0.0

        transport = _RetryTransport(
            httpx.HTTPTransport(),
            max_retries=max_retries,
        )
        self._http = httpx.Client(
            base_url=self.base_url,
            transport=transport,
            timeout=timeout,
            follow_redirects=True,
        )

    # -- Auth -----------------------------------------------------------------

    def authenticate(self) -> None:
        """Obtain a new access token via client credentials grant."""
        # Use a plain httpx.Client for the token request to avoid retry transport
        # on auth failures (we want immediate feedback on bad creds).
        response = self._http.post(
            "/auth/v1/token",
            json={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
            headers={"accept": "application/json", "content-type": "application/json"},
        )
        if response.status_code != 200:
            raise ExaAuthError(
                f"Authentication failed: HTTP {response.status_code} — {response.text}"
            )
        data = response.json()
        self._access_token = data["access_token"]
        expires_in = int(data.get("expires_in", 14400))
        self._expires_at = time.time() + expires_in

    def _ensure_token(self) -> None:
        """Refresh token if expired or within buffer window."""
        if self._access_token is None or time.time() >= (self._expires_at - _TOKEN_TTL_BUFFER):
            self.authenticate()

    @property
    def _auth_headers(self) -> dict[str, str]:
        self._ensure_token()
        return {"Authorization": f"Bearer {self._access_token}"}

    # -- HTTP helpers ---------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Make an authenticated API request, auto-refreshing the token."""
        merged_headers = {**self._auth_headers, **(headers or {})}
        response = self._http.request(
            method, path, json=json, params=params, headers=merged_headers
        )
        if response.status_code >= 400:
            raise ExaAPIError(response.status_code, response.text)
        return response

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        return self.request("GET", path, params=params).json()

    def post(self, path: str, *, json: Any = None, params: dict[str, Any] | None = None) -> Any:
        return self.request("POST", path, json=json, params=params).json()

    def put(self, path: str, *, json: Any = None) -> Any:
        return self.request("PUT", path, json=json).json()

    def delete(self, path: str) -> Any:
        resp = self.request("DELETE", path)
        if resp.content:
            return resp.json()
        return None

    # -- Batch helper ---------------------------------------------------------

    @staticmethod
    def batch_write_sleep() -> None:
        """Sleep 1s between table write operations to avoid rate-limiting."""
        time.sleep(_BATCH_WRITE_SLEEP)

    # -- Context manager ------------------------------------------------------

    def __enter__(self) -> ExaClient:
        self.authenticate()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

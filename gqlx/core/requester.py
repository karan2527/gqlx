"""Async HTTP client wrapper with retry logic, proxy support, and rate limiting."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx

from gqlx.utils.logger import get_logger
from gqlx.utils.models import ScanConfig

logger = get_logger(__name__)

_BASE_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "User-Agent": "gqlx/1.0 (GraphQL Security Scanner)",
}


class RequestError(Exception):
    """Raised when a request fails after all retry attempts."""


class Requester:
    """
    Shared async HTTP session for all gqlx network I/O.

    Use as an async context manager:
        async with Requester(config) as req:
            resp = await req.graphql("{ __typename }")
    """

    def __init__(self, config: ScanConfig, max_retries: int | None = None) -> None:
        self.config = config
        self.max_retries = max_retries if max_retries is not None else config.max_retries
        self._client: httpx.AsyncClient | None = None
        self._concurrency = asyncio.Semaphore(config.concurrency)

    async def __aenter__(self) -> Requester:
        merged_headers = {**_BASE_HEADERS, **self.config.headers}
        merged_headers["User-Agent"] = self.config.user_agent
        proxy_arg: dict[str, Any] = {}
        if self.config.proxy:
            proxy_arg["proxy"] = self.config.proxy

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.timeout),
            headers=merged_headers,
            cookies=self.config.cookies,
            follow_redirects=self.config.follow_redirects,
            verify=self.config.verify_ssl,
            trust_env=False,
            **proxy_arg,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client:
            await self._client.aclose()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def graphql(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        operation_name: str | None = None,
        url: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Send a single GraphQL operation."""
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name
        return await self._post(url or self.config.url, payload, extra_headers=extra_headers)

    async def graphql_batch(
        self,
        operations: list[dict[str, Any]],
        url: str | None = None,
    ) -> httpx.Response:
        """Send a batched array of GraphQL operations in a single request."""
        return await self._post(url or self.config.url, operations)

    async def timed_graphql(
        self,
        query: str,
        url: str | None = None,
    ) -> tuple[httpx.Response | None, float]:
        """Send one GraphQL operation and return ``(response, round_trip_seconds)``.

        For *time-based* oracles only. Unlike :meth:`graphql`, this measures the
        clock *after* the concurrency slot and rate-limit delay are satisfied and
        makes a SINGLE attempt with no retry. Retry backoff and queue-wait must be
        excluded from the measurement, otherwise an unrelated request retrying
        while holding the semaphore inflates this timing and the caller mistakes
        the queue wait for an injected ``sleep``. Returns ``(None, 0.0)`` on a
        transport error so the caller can skip the sample.
        """
        target = url or self.config.url
        async with self._concurrency:
            if self.config.rate_limit > 0:
                await asyncio.sleep(self.config.rate_limit)
            assert self._client is not None, "Requester must be an async context manager"
            start = time.monotonic()
            try:
                resp = await self._client.request("POST", target, json={"query": query})
            except httpx.RequestError:
                return None, 0.0
            return resp, time.monotonic() - start

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """HTTP GET with retry."""
        return await self._request("GET", url, **kwargs)

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    async def _post(
        self,
        url: str,
        body: Any,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        kwargs: dict[str, Any] = {"json": body}
        if extra_headers:
            kwargs["headers"] = extra_headers
        return await self._request("POST", url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        async with self._concurrency:
            if self.config.rate_limit > 0:
                await asyncio.sleep(self.config.rate_limit)

            last_exc: Exception | None = None
            for attempt in range(1, self.max_retries + 1):
                try:
                    assert self._client is not None, "Requester must be an async context manager"
                    resp = await self._client.request(method, url, **kwargs)
                    logger.debug(
                        "http_request",
                        method=method,
                        url=url,
                        status=resp.status_code,
                        attempt=attempt,
                    )
                    return resp
                except httpx.TimeoutException as exc:
                    last_exc = exc
                    logger.warning("request_timeout", url=url, attempt=attempt)
                except httpx.RequestError as exc:
                    last_exc = exc
                    logger.warning("request_error", url=url, error=str(exc), attempt=attempt)

                if attempt < self.max_retries:
                    await asyncio.sleep(2**attempt)

            raise RequestError(
                f"{method} {url} failed after {self.max_retries} attempts"
            ) from last_exc

    def parse_json(self, response: httpx.Response) -> dict[str, Any] | None:
        """Safe JSON parse; returns None on failure."""
        try:
            return response.json()  # type: ignore[no-any-return]
        except (json.JSONDecodeError, ValueError):
            return None

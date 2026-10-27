"""Async HTTP client for the Corporate Twin backend.

The client is genuinely asynchronous (:class:`httpx.AsyncClient`) and is bridged
into Streamlit's synchronous script runner by :func:`run_sync`, which executes
the coroutine on a dedicated thread with its own event loop. That avoids the
"event loop already running" trap Streamlit's rerun model creates and keeps a
single connection pool per call.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Coroutine
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Self, TypeVar

import httpx

T = TypeVar("T")

#: Default backend location; override with ``TWIN_API_BASE_URL``.
DEFAULT_BASE_URL: str = os.environ.get("TWIN_API_BASE_URL", "http://localhost:8000")

#: Default per-request timeout. Simulations re-solve a full matrix and can take
#: noticeably longer than a health check on a Raspberry Pi.
DEFAULT_TIMEOUT_SECONDS: float = 30.0

API_PREFIX = "/api/v1"


class TwinAPIError(RuntimeError):
    """Raised when the backend returns an error or is unreachable.

    Attributes:
        code: Stable backend error code when the failure came from the API.
        status_code: HTTP status, or ``None`` for a transport failure.
        context: Structured diagnostic data returned by the backend.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str = "client_error",
        status_code: int | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.context = context or {}

    @property
    def is_connectivity_error(self) -> bool:
        """Whether the failure was a transport problem rather than an API error."""
        return self.status_code is None


def run_sync(coro: Coroutine[Any, Any, T]) -> T:
    """Execute a coroutine from synchronous code.

    Runs the coroutine on a short-lived worker thread with its own event loop so
    it is safe to call from Streamlit's script thread even if a loop exists
    there.

    Args:
        coro: Coroutine to execute.

    Returns:
        The coroutine's result.

    Raises:
        TwinAPIError: If the coroutine raised one.
    """
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


class TwinAPIClient:
    """Asynchronous client for the Corporate Twin REST API."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        """Create a client.

        Args:
            base_url: Backend origin, e.g. ``http://localhost:8000``.
            timeout: Per-request timeout in seconds.
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> Self:
        """Open the underlying connection pool."""
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        """Close the underlying connection pool."""
        await self.aclose()

    async def aclose(self) -> None:
        """Close the connection pool if it is open."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # -- Transport -----------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """Issue a request and decode the response.

        Args:
            method: HTTP method.
            path: Path relative to the API prefix.
            json_body: Optional JSON body.
            params: Optional query parameters.

        Returns:
            The decoded JSON payload, or an empty dict for an empty body.

        Raises:
            TwinAPIError: On transport failure, timeout, or a non-2xx response.
        """
        client = self._client or httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)
        owns_client = self._client is None
        try:
            response = await client.request(
                method,
                f"{API_PREFIX}{path}",
                json=json_body,
                params=params,
            )
        except httpx.TimeoutException as exc:
            raise TwinAPIError(
                f"Request to {path} timed out after {self.timeout:.0f}s. The backend may be "
                "re-solving a large matrix; retry or raise the timeout.",
                code="timeout",
            ) from exc
        except httpx.HTTPError as exc:
            raise TwinAPIError(
                f"Cannot reach the backend at {self.base_url}: {exc}. "
                "Start it with scripts/run_backend.sh.",
                code="connection_error",
            ) from exc
        finally:
            if owns_client:
                await client.aclose()

        if response.status_code >= 400:
            envelope: dict[str, Any] = {}
            try:
                envelope = response.json()
            except ValueError:
                envelope = {"detail": response.text}
            raise TwinAPIError(
                envelope.get("detail", f"HTTP {response.status_code} from {path}."),
                code=envelope.get("code", "http_error"),
                status_code=response.status_code,
                context=envelope.get("context", {}),
            )

        if not response.content:
            return {}
        return response.json()

    # -- Endpoints -----------------------------------------------------------

    async def health(self) -> dict[str, Any]:
        """Fetch readiness and runtime mode."""
        return await self._request("GET", "/health")

    async def topology(self) -> dict[str, Any]:
        """Fetch the topology projection."""
        return await self._request("GET", "/topology")

    async def runtime(self) -> dict[str, Any]:
        """Fetch container runtime status."""
        return await self._request("GET", "/runtime")

    async def policies(self) -> list[dict[str, Any]]:
        """Fetch the compiled firewall policy per node and chain."""
        return await self._request("GET", "/policies")

    async def capture_snapshot(self) -> dict[str, Any]:
        """Capture and activate a new baseline snapshot."""
        return await self._request("POST", "/snapshot")

    async def get_snapshot(self) -> dict[str, Any]:
        """Fetch the active baseline summary."""
        return await self._request("GET", "/snapshot")

    async def snapshot_nodes(self) -> list[dict[str, Any]]:
        """Fetch per-node baseline state."""
        return await self._request("GET", "/snapshot/nodes")

    async def simulate_change(
        self, change: dict[str, Any], apply_to_runtime: bool = False
    ) -> dict[str, Any]:
        """Evaluate a candidate change against the baseline."""
        return await self._request(
            "POST",
            "/simulate-change",
            json_body=change,
            params={"apply_to_runtime": str(apply_to_runtime).lower()},
        )

    async def analyze_blast_radius(self, request: dict[str, Any]) -> dict[str, Any]:
        """Run graph-based blast-radius analysis."""
        return await self._request("POST", "/analyze-blast-radius", json_body=request)

    async def rollback(self, apply_to_runtime: bool = True) -> dict[str, Any]:
        """Revert the twin to the captured baseline."""
        return await self._request(
            "POST", "/rollback", params={"apply_to_runtime": str(apply_to_runtime).lower()}
        )

    async def compliance(self) -> dict[str, Any]:
        """Fetch the compliance report for the active baseline."""
        return await self._request("GET", "/compliance")

    async def simulations(self) -> list[dict[str, Any]]:
        """Fetch the simulation history, newest first."""
        return await self._request("GET", "/simulations")

    async def deploy_lab(self) -> dict[str, Any]:
        """Deploy the Containerlab topology through the backend."""
        return await self._request("POST", "/lab/deploy")

    async def destroy_lab(self) -> dict[str, Any]:
        """Destroy the Containerlab topology through the backend."""
        return await self._request("POST", "/lab/destroy")


# ---------------------------------------------------------------------------
# Synchronous convenience wrappers used by the Streamlit app.
# ---------------------------------------------------------------------------


def call(method_name: str, base_url: str, **kwargs: Any) -> Any:
    """Invoke a client method synchronously.

    Args:
        method_name: :class:`TwinAPIClient` method to call.
        base_url: Backend origin.
        **kwargs: Keyword arguments forwarded to the method.

    Returns:
        The method's decoded result.

    Raises:
        TwinAPIError: On any transport or API failure.
        AttributeError: If ``method_name`` is not a client method.
    """

    async def _call() -> Any:
        async with TwinAPIClient(base_url) as client:
            method = getattr(client, method_name, None)
            if method is None:
                raise AttributeError(f"TwinAPIClient has no method {method_name!r}")
            return await method(**kwargs)

    return run_sync(_call())


__all__ = [
    "API_PREFIX",
    "DEFAULT_BASE_URL",
    "TwinAPIClient",
    "TwinAPIError",
    "call",
    "run_sync",
]

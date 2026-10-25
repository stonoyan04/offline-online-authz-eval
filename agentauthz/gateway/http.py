"""HTTP client the gateway uses to reach the authorization server (both modes).

httpcore's pool walks every connection it holds on each request event, and
polls each idle one to see whether it has expired, so its cost per request
grows with the pool. After one stall a 200-connection pool keeps ~100 idle
connections, and at 800 req/s that bookkeeping alone pinned the online
gateway's CPU and it never recovered. Several small pools, used round-robin,
keep the same connection limit with a flat cost (same idea as the load
generator's pools).
"""

from __future__ import annotations

import itertools
import math
from typing import Sequence

import httpx

MAX_CONNECTIONS = 200
POOL_SIZE = 25


class RoundRobinTransport(httpx.AsyncBaseTransport):
    """Send each request through the next of several transports."""

    def __init__(self, pools: Sequence[httpx.AsyncBaseTransport]) -> None:
        self.pools = list(pools)
        self._next = itertools.cycle(self.pools)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await next(self._next).handle_async_request(request)

    async def aclose(self) -> None:
        for pool in self.pools:
            await pool.aclose()


def gateway_client(
    *, max_connections: int = MAX_CONNECTIONS, pool_size: int = POOL_SIZE, timeout: float = 2.0
) -> httpx.AsyncClient:
    limits = httpx.Limits(max_connections=pool_size, max_keepalive_connections=pool_size)
    pools = [httpx.AsyncHTTPTransport(limits=limits) for _ in range(math.ceil(max_connections / pool_size))]
    return httpx.AsyncClient(transport=RoundRobinTransport(pools), timeout=timeout)

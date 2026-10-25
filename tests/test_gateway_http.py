"""Gateway HTTP client: requests spread over several small connection pools."""

import asyncio

import httpx

from agentauthz.gateway.http import RoundRobinTransport, gateway_client


class Counting(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.requests = 0
        self.closed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        return httpx.Response(200, json={"ok": True})

    async def aclose(self) -> None:
        self.closed = True


def test_round_robin_spreads_requests_and_closes_every_pool():
    pools = [Counting() for _ in range(4)]

    async def scenario():
        async with httpx.AsyncClient(transport=RoundRobinTransport(pools)) as http:
            for _ in range(10):
                assert (await http.get("http://authz/x")).status_code == 200

    asyncio.run(scenario())
    assert [p.requests for p in pools] == [3, 3, 2, 2]
    assert all(p.closed for p in pools)


def test_gateway_client_splits_the_connection_limit_into_small_pools():
    http = gateway_client(max_connections=200, pool_size=25, timeout=1.5)
    try:
        pools = http._transport.pools
        assert len(pools) == 8
        assert all(p._pool._max_connections == 25 for p in pools)
        assert http.timeout.read == 1.5
    finally:
        asyncio.run(http.aclose())

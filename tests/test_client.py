"""AgentClient signs what goes on the wire, so encoded paths and queries verify."""

import asyncio

import httpx
import pytest
from biscuit_auth import KeyPair

from agentauthz.client import AgentClient
from agentauthz.demo_service import create_demo_app
from agentauthz.gateway import GatewayDecision


class AllowAll:
    mode = "offline"

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def check(self, token, presenter, operation, amount) -> GatewayDecision:
        return GatewayDecision.allow(presenter)


def get_status(path: str, method: str = "GET") -> int:
    app = create_demo_app(AllowAll())

    async def go() -> int:
        http = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://svc")
        async with AgentClient("http://svc", KeyPair(), "tok", http=http) as agent:
            r = await agent.request(method, path)
        await http.aclose()
        return r.status_code

    return asyncio.run(go())


@pytest.mark.parametrize(
    "path",
    ["/flights?to=CDG", "/flights?to=Երևան", "/flights?to=a b", "/flights?to=a%2Fb&x=1"],
)
def test_encoded_queries_verify(path):
    assert get_status(path) == 200


def test_encoded_path_segment_verifies():
    # Route matches on the decoded path; signature covers the raw one.
    assert get_status("/orders/a%20b") == 404  # passed the gateway, unknown order

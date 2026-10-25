"""HTTP client that signs every request, as an agent (or the load generator) would.

    async with AgentClient("http://127.0.0.1:8000", holder, token) as agent:
        r = await agent.get("/flights?to=CDG")
        r = await agent.post_json("/orders", {"flight_id": "EVN-CDG-1", "price": 250})
"""

from __future__ import annotations

import json
from typing import Any, Optional

import httpx
from biscuit_auth import KeyPair

from agentauthz.pop import sign_request, to_headers


class AgentClient:
    def __init__(
        self,
        base_url: str,
        holder: KeyPair,
        token: str,
        *,
        http: Optional[httpx.AsyncClient] = None,
        timeout: float = 10.0,
    ) -> None:
        self.holder = holder
        self.token = token
        self._own = http is None
        self.http = http or httpx.AsyncClient(base_url=base_url, timeout=timeout)

    async def __aenter__(self) -> "AgentClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._own:
            await self.http.aclose()

    async def request(self, method: str, path: str, body: bytes = b"", content_type: Optional[str] = None) -> httpx.Response:
        request = self.http.build_request(method, path, content=body)
        # Sign the target exactly as it goes on the wire (percent-encoded),
        # which is what the gateway reconstructs from the request line.
        target = request.url.raw_path.decode("ascii")
        signed = sign_request(self.holder, method, target, body, token=self.token)
        request.headers.update(to_headers(signed))
        if content_type:
            request.headers["Content-Type"] = content_type
        return await self.http.send(request)

    async def get(self, path: str) -> httpx.Response:
        return await self.request("GET", path)

    async def delete(self, path: str) -> httpx.Response:
        return await self.request("DELETE", path)

    async def post_json(self, path: str, payload: Any) -> httpx.Response:
        body = json.dumps(payload).encode()
        return await self.request("POST", path, body, "application/json")

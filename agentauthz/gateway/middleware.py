"""ASGI middleware that authorizes every request before the service sees it.

Order of checks (identical in both modes):

1. Public paths (e.g. /healthz) pass straight through.
2. The route must be mapped to an operation (default deny).
3. A bearer token and a valid request signature are required; the signature
   proves the caller holds the private key (shared ReplayCache).
4. The amount, for spending routes, is read from the JSON body.
5. The mode-specific authorizer decides (offline or online).

Every response carries `Server-Timing: authz;dur=<ms>` with the time spent in
steps 2-5, and `Agent-Authz-Mode: offline|online`, so the experiments can
separate authorization cost from the service's own work.
"""

from __future__ import annotations

import json
import time
from typing import Callable

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from agentauthz.gateway.authorizers import Authorizer, GatewayDecision
from agentauthz.gateway.routes import RouteError, RouteMap
from agentauthz.pop import ReplayCache, from_http, verify_request

MAX_BODY_BYTES = 1_000_000


class AuthzMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        authorizer: Authorizer,
        routes: RouteMap,
        replay: ReplayCache | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.app = app
        self.authorizer = authorizer
        self.routes = routes
        self.replay = replay or ReplayCache()
        self.clock = clock

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self.routes.is_public(scope["path"]):
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        body, too_large = await _read_body(receive)
        if too_large:
            await self._deny(send, started, GatewayDecision.deny(413, "invalid_request", "body too large"))
            return

        decision = await self._decide(scope, body)
        if not decision.allowed:
            await self._deny(send, started, decision)
            return

        elapsed = time.perf_counter() - started
        scope.setdefault("state", {})["agentauthz"] = {
            "mode": self.authorizer.mode,
            "holder": decision.holder,
            "depth": decision.depth,
        }
        extra = self._timing_headers(elapsed)

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                message = dict(message)
                message["headers"] = list(message.get("headers", [])) + extra
            await send(message)

        await self.app(scope, _replay_body(body, receive), send_with_headers)

    async def _decide(self, scope: Scope, body: bytes) -> GatewayDecision:
        method, path = scope["method"], scope["path"]
        route = self.routes.match(method, path)
        if route is None:
            return GatewayDecision.deny(403, "route_not_mapped", f"{method} {path} is not mapped")

        # The signature covers the request target as sent on the wire
        # (percent-encoded), so use raw_path rather than the decoded path.
        raw_path = (scope.get("raw_path") or path.encode()).decode("latin-1")
        query = scope.get("query_string", b"").decode("latin-1")
        target = raw_path + (f"?{query}" if query else "")
        signed = from_http(method, target, body, Headers(scope=scope))
        if signed is None or not signed.token:
            return GatewayDecision.deny(401, "invalid_request", "missing token or signature headers")
        presenter = verify_request(signed, self.replay, now=int(self.clock()))
        if presenter is None:
            return GatewayDecision.deny(401, "invalid_signature", "bad, stale or replayed request signature")

        try:
            amount = route.amount(body)
        except RouteError as exc:
            return GatewayDecision.deny(400, "invalid_request", str(exc))

        return await self.authorizer.check(signed.token, presenter, route.operation, amount)

    def _timing_headers(self, elapsed: float) -> list[tuple[bytes, bytes]]:
        return [
            (b"server-timing", f"authz;dur={elapsed * 1000:.3f}".encode()),
            (b"agent-authz-mode", self.authorizer.mode.encode()),
        ]

    async def _deny(self, send: Send, started: float, decision: GatewayDecision) -> None:
        payload = json.dumps(
            {"error": decision.error, "reason": decision.reason, "mode": self.authorizer.mode}
        ).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ] + self._timing_headers(time.perf_counter() - started)
        if decision.status == 401:
            headers.append((b"www-authenticate", f'Bearer error="{decision.error}"'.encode()))
        if decision.status == 503:
            headers.append((b"retry-after", b"1"))
        await send({"type": "http.response.start", "status": decision.status, "headers": headers})
        await send({"type": "http.response.body", "body": payload})


async def _read_body(receive: Receive) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            return b"", True
        chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks), False


def _replay_body(body: bytes, receive: Receive) -> Receive:
    sent = False

    async def replay() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return replay

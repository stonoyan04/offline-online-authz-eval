"""The two authorization checks the experiment compares.

Everything else in the gateway (routing, body handling, proof of possession,
error responses, timing) is shared, so a difference in the measurements comes
from these two classes alone.

OfflineAuthorizer
    Verifies the Biscuit token locally with the issuer's public key. The only
    network traffic is a background refresh of the signed revocation list.
    `max_staleness` decides what happens when that list gets old: None keeps
    serving (availability first); a number makes the gateway fail closed once
    the list is older than that many seconds (revocation first).

OnlineAuthorizer
    Asks the authorization server about every request (RFC 7662). If the
    server is slow, every request is slow; if it is down, every request is
    refused (fail closed, as OAuth deployments do). An optional `cache_ttl`
    keeps positive answers for a few seconds, the usual optimization; it
    trades revocation lag for availability exactly like the offline refresh.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional, Protocol

import httpx
from biscuit_auth import PublicKey

from agentauthz import delegation
from agentauthz.revocation import RevocationList, verify_revocation_list

log = logging.getLogger("agentauthz.gateway")


@dataclass(frozen=True)
class GatewayDecision:
    allowed: bool
    status: int  # HTTP status to answer with when denied
    error: str  # short machine-readable code
    reason: str  # human-readable detail
    holder: Optional[str] = None
    depth: int = 0

    @classmethod
    def allow(cls, holder: Optional[str], depth: int = 0) -> "GatewayDecision":
        return cls(True, 200, "ok", "ok", holder, depth)

    @classmethod
    def deny(cls, status: int, error: str, reason: str, holder=None, depth=0) -> "GatewayDecision":
        return cls(False, status, error, reason, holder, depth)


class Authorizer(Protocol):
    mode: str

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def check(
        self, token: str, presenter: str, operation: str, amount: int
    ) -> GatewayDecision: ...


# --------------------------------------------------------------------------
# Offline
# --------------------------------------------------------------------------


class OfflineAuthorizer:
    mode = "offline"

    def __init__(
        self,
        issuer: PublicKey,
        *,
        revocations_url: Optional[str] = None,
        http: Optional[httpx.AsyncClient] = None,
        refresh_seconds: float = 5.0,
        max_staleness: Optional[float] = None,
        refresh_timeout: float = 2.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.issuer = issuer
        self.refresh_timeout = refresh_timeout
        self.revocations_url = revocations_url
        self.http = http
        self.refresh_seconds = refresh_seconds
        self.max_staleness = max_staleness
        self.clock = clock
        self.revocations: Optional[RevocationList] = None
        self.refresh_ok = 0
        self.refresh_failed = 0
        self._task: Optional[asyncio.Task] = None

    @property
    def revoked(self) -> frozenset[str]:
        return self.revocations.revoked if self.revocations else frozenset()

    def staleness(self) -> Optional[float]:
        """Seconds since the issuer signed the list we hold; None if we have none."""
        if self.revocations is None:
            return None
        return max(0.0, self.clock() - self.revocations.issued_at)

    async def refresh(self) -> bool:
        if not (self.revocations_url and self.http):
            return False
        try:
            resp = await asyncio.wait_for(
                self.http.get(self.revocations_url), self.refresh_timeout
            )
            resp.raise_for_status()
            fresh = verify_revocation_list(resp.json(), self.issuer)
        except (httpx.HTTPError, ValueError, asyncio.TimeoutError) as exc:
            self.refresh_failed += 1
            log.debug("revocation refresh failed: %s", exc)
            return False
        if fresh is None:
            self.refresh_failed += 1
            log.warning("revocation list rejected: bad signature or format")
            return False
        current = self.revocations
        # Never go back to an older list (rollback protection).
        if current is None or (fresh.seq, fresh.issued_at) >= (current.seq, current.issued_at):
            self.revocations = fresh
        self.refresh_ok += 1
        return True

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self.refresh_seconds)
            await self.refresh()

    async def start(self) -> None:
        await self.refresh()
        if self.revocations_url and self.http and self._task is None:
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def check(self, token: str, presenter: str, operation: str, amount: int) -> GatewayDecision:
        if self.max_staleness is not None:
            age = self.staleness()
            if age is None or age > self.max_staleness:
                return GatewayDecision.deny(
                    503, "revocation_list_stale", "revocation list missing or too old"
                )
        d = delegation.verify(
            token,
            self.issuer,
            presenter=presenter,
            operation=operation,
            amount=amount,
            revoked=self.revoked,
            now=datetime.fromtimestamp(self.clock(), timezone.utc),
        )
        if d.allowed:
            return GatewayDecision.allow(d.holder, d.depth)
        if d.reason == "policy check failed":
            return GatewayDecision.deny(403, "insufficient_scope", d.reason, d.holder, d.depth)
        return GatewayDecision.deny(401, "invalid_token", d.reason, d.holder, d.depth)


# --------------------------------------------------------------------------
# Online
# --------------------------------------------------------------------------


class OnlineAuthorizer:
    mode = "online"

    def __init__(
        self,
        introspection_url: str,
        client_id: str,
        client_secret: str,
        *,
        http: httpx.AsyncClient,
        timeout: float = 2.0,
        cache_ttl: float = 0.0,
        cache_size: int = 10_000,
        max_in_flight: int = 200,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.url = introspection_url
        self.auth = httpx.BasicAuth(client_id, client_secret)
        self.http = http
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.cache_size = cache_size
        self.clock = clock
        # At most this many calls inside the HTTP pool (set it to the pool size).
        # httpcore rescans its whole queue on every pool event, so when the server
        # hangs, thousands of queued calls pin the CPU and the gateway stops
        # answering anything. Extra calls wait here instead, under the same deadline.
        self._slots = asyncio.Semaphore(max_in_flight)
        self._cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
        self.calls = 0
        self.failures = 0
        self.cache_hits = 0

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    def _cached(self, token: str) -> Optional[dict]:
        hit = self._cache.get(token)
        if hit is None:
            return None
        stored_at, info = hit
        if self.clock() - stored_at > self.cache_ttl:
            del self._cache[token]
            return None
        self._cache.move_to_end(token)
        self.cache_hits += 1
        return info

    def _store(self, token: str, info: dict) -> None:
        self._cache[token] = (self.clock(), info)
        self._cache.move_to_end(token)
        while len(self._cache) > self.cache_size:
            self._cache.popitem(last=False)

    async def _introspect(self, token: str) -> Optional[dict]:
        """The server's answer, or None if it could not be reached."""
        if self.cache_ttl > 0:
            cached = self._cached(token)
            if cached is not None:
                return cached
        self.calls += 1
        try:
            # httpx timeouts apply per phase (connect, read, ...); wait_for
            # bounds the whole call, which is what a gateway deadline means.
            resp = await asyncio.wait_for(self._post(token), self.timeout)
        except (httpx.HTTPError, asyncio.TimeoutError) as exc:
            self.failures += 1
            log.debug("introspection failed: %s", exc)
            return None
        if resp.status_code != 200:
            self.failures += 1
            return None
        try:
            info = resp.json()
        except ValueError:
            self.failures += 1
            return None
        if self.cache_ttl > 0 and info.get("active") is True:
            self._store(token, info)
        return info

    async def _post(self, token: str) -> httpx.Response:
        async with self._slots:
            return await self.http.post(self.url, data={"token": token}, auth=self.auth)

    async def check(self, token: str, presenter: str, operation: str, amount: int) -> GatewayDecision:
        info = await self._introspect(token)
        if info is None:
            return GatewayDecision.deny(
                503, "authorization_unavailable", "authorization server unreachable"
            )
        if info.get("active") is not True:
            return GatewayDecision.deny(401, "invalid_token", "token not active")
        holder = (info.get("cnf") or {}).get("agent_key")
        depth = int(info.get("delegation_depth", 0))
        if holder != presenter:
            return GatewayDecision.deny(
                401, "invalid_token", "request not signed by the token holder", holder, depth
            )
        exp = info.get("exp")
        if not isinstance(exp, int) or exp <= self.clock():
            return GatewayDecision.deny(401, "invalid_token", "token expired", holder, depth)
        if operation not in str(info.get("scope", "")).split():
            return GatewayDecision.deny(403, "insufficient_scope", "operation not granted", holder, depth)
        limit = info.get("max_amount")
        if not isinstance(limit, int) or amount > limit:
            return GatewayDecision.deny(403, "insufficient_scope", "amount over limit", holder, depth)
        return GatewayDecision.allow(holder, depth)

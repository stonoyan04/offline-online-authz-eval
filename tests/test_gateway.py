"""Gateway end to end: demo service + middleware + real authorization server.

The authorization server runs in-process (httpx.ASGITransport), so these tests
exercise the full path without sockets. Most tests run in both modes; the
ones at the bottom pin down where the modes differ, which is the subject of
the experiments.
"""

import json
from urllib.parse import urlencode

import httpx
import pytest
from biscuit_auth import Biscuit, KeyPair
from fastapi.testclient import TestClient

from agentauthz import delegation
from agentauthz.authz_server import Settings, State, create_app
from agentauthz.authz_server.app import TOKEN_EXCHANGE
from agentauthz.demo_service import create_demo_app
from agentauthz.gateway import OfflineAuthorizer, OnlineAuthorizer
from agentauthz.keys import public_hex
from agentauthz.pop import sign_request, to_headers

ADMIN = "admin-secret"
T0 = 1_760_000_000


class Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class Env:
    def __init__(self, mode: str, *, max_staleness=None, cache_ttl=0.0, timeout=2.0):
        self.mode = mode
        self.clock = Clock(T0)
        self.root = KeyPair()
        settings = Settings(self.root, ADMIN, {"gw": "sec"}, clock=self.clock)
        self.authz_app = create_app(state=State(settings))
        self.admin = TestClient(self.authz_app)
        http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.authz_app), base_url="http://authz"
        )
        if mode == "offline":
            self.authorizer = OfflineAuthorizer(
                self.root.public_key,
                revocations_url="http://authz/revocations",
                http=http,
                refresh_seconds=3600,  # tests refresh by hand
                max_staleness=max_staleness,
                clock=self.clock,
            )
        else:
            self.authorizer = OnlineAuthorizer(
                "http://authz/introspect", "gw", "sec",
                http=http, cache_ttl=cache_ttl, timeout=timeout, clock=self.clock,
            )
        self.app = create_demo_app(self.authorizer, clock=self.clock, on_shutdown=http.aclose)
        self.client = TestClient(self.app)

    # ---- helpers --------------------------------------------------------

    def grant(self, holder: KeyPair, **kw) -> str:
        body = {
            "user": "alice",
            "holder_key": public_hex(holder),
            "operations": kw.pop("operations", ["search", "buy"]),
            "max_amount": kw.pop("max_amount", 300),
            "ttl_seconds": kw.pop("ttl_seconds", 3600),
            "format": "biscuit" if self.mode == "offline" else "opaque",
        }
        r = self.admin.post("/admin/grants", json=body, headers={"Authorization": f"Bearer {ADMIN}"})
        assert r.status_code == 200, r.text
        return r.json()["token"]

    def delegate(self, parent_token: str, parent: KeyPair, child: KeyPair, **kw) -> str:
        if self.mode == "offline":
            parent_biscuit = Biscuit.from_base64(parent_token, self.root.public_key)
            ops = kw.get("operations")
            return delegation.delegate(
                parent_biscuit, parent, child.public_key,
                operations=ops, max_amount=kw.get("max_amount"),
            ).to_base64()
        form = {"grant_type": TOKEN_EXCHANGE, "subject_token": parent_token, "actor_key": public_hex(child)}
        if "operations" in kw:
            form["scope"] = " ".join(kw["operations"])
        if "max_amount" in kw:
            form["max_amount"] = str(kw["max_amount"])
        body = urlencode(form).encode()
        headers = to_headers(sign_request(parent, "POST", "/token/exchange", body, created=int(self.clock.t)))
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        r = self.admin.post("/token/exchange", content=body, headers=headers)
        assert r.status_code == 200, r.text
        return r.json()["access_token"]

    def revoke(self, token: str) -> None:
        r = self.admin.post(
            "/revoke",
            content=urlencode({"token": token}),
            headers={"Authorization": f"Bearer {ADMIN}", "Content-Type": "application/x-www-form-urlencoded"},
        )
        assert r.status_code == 200

    def fault(self, **cfg) -> None:
        r = self.admin.put("/admin/fault", json=cfg, headers={"Authorization": f"Bearer {ADMIN}"})
        assert r.status_code == 200, r.text

    def refresh(self) -> bool:
        return self.client.portal.call(self.authorizer.refresh)

    def call(self, signer: KeyPair, method: str, path: str, token: str, body_json=None, headers=None):
        body = json.dumps(body_json).encode() if body_json is not None else b""
        signed = sign_request(signer, method, path, body, token=token, created=int(self.clock.t))
        hdrs = to_headers(signed)
        if body:
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        return self.client.request(method, path, content=body, headers=hdrs)


@pytest.fixture(params=["offline", "online"])
def env(request):
    e = Env(request.param)
    with e.client:
        yield e


def make_env(mode, **kw):
    e = Env(mode, **kw)
    e.client.__enter__()
    return e


def authz_ms(response) -> float:
    return float(response.headers["server-timing"].split("dur=")[1])


# ---- shared behaviour (both modes) ------------------------------------------


def test_allowed_request_reaches_service(env):
    agent = KeyPair()
    token = env.grant(agent)
    r = env.call(agent, "GET", "/flights?to=CDG", token)
    assert r.status_code == 200, r.text
    assert [f["id"] for f in r.json()] == ["EVN-CDG-1", "EVN-CDG-2"]
    assert r.headers["agent-authz-mode"] == env.mode
    assert authz_ms(r) >= 0


def test_buy_within_and_over_limit(env):
    agent = KeyPair()
    token = env.grant(agent, max_amount=300)
    ok = env.call(agent, "POST", "/orders", token, {"flight_id": "EVN-CDG-1", "price": 250})
    assert ok.status_code == 201, ok.text
    assert ok.json()["agent"] == public_hex(agent)
    over = env.call(agent, "POST", "/orders", token, {"flight_id": "EVN-CDG-2", "price": 410})
    assert over.status_code == 403
    assert over.json()["error"] == "insufficient_scope"


def test_operation_not_granted(env):
    agent = KeyPair()
    token = env.grant(agent, operations=["search"])
    r = env.call(agent, "DELETE", "/orders/1", token)
    assert r.status_code == 403


def test_public_and_unmapped_routes(env):
    assert env.client.get("/healthz").status_code == 200
    agent = KeyPair()
    token = env.grant(agent)
    r = env.call(agent, "PUT", "/flights", token)
    assert r.status_code == 403
    assert r.json()["error"] == "route_not_mapped"


def test_missing_token_or_signature(env):
    assert env.client.get("/flights").status_code == 401
    agent = KeyPair()
    token = env.grant(agent)
    r = env.client.get("/flights", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_stolen_token_signed_by_thief(env):
    agent, thief = KeyPair(), KeyPair()
    token = env.grant(agent)
    r = env.call(thief, "GET", "/flights", token)
    assert r.status_code == 401
    assert r.json()["error"] == "invalid_token"


def test_replayed_request_rejected(env):
    agent = KeyPair()
    token = env.grant(agent)
    signed = sign_request(agent, "GET", "/flights", token=token, created=int(env.clock.t))
    headers = to_headers(signed)
    assert env.client.get("/flights", headers=headers).status_code == 200
    r = env.client.get("/flights", headers=headers)
    assert r.status_code == 401
    assert r.json()["error"] == "invalid_signature"


def test_tampered_body_rejected(env):
    agent = KeyPair()
    token = env.grant(agent)
    body = json.dumps({"flight_id": "EVN-CDG-1", "price": 250}).encode()
    headers = to_headers(sign_request(agent, "POST", "/orders", body, token=token, created=int(env.clock.t)))
    headers["Content-Type"] = "application/json"
    tampered = json.dumps({"flight_id": "EVN-JFK-1", "price": 250}).encode()
    assert env.client.post("/orders", content=tampered, headers=headers).status_code == 401


def test_bad_amount_body(env):
    agent = KeyPair()
    token = env.grant(agent)
    r = env.call(agent, "POST", "/orders", token, {"flight_id": "EVN-CDG-1", "price": "cheap"})
    assert r.status_code == 400


def test_expired_token(env):
    agent = KeyPair()
    token = env.grant(agent, ttl_seconds=60)
    env.clock.t = T0 + 120
    assert env.call(agent, "GET", "/flights", token).status_code == 401


def test_sub_agent_delegation(env):
    agent, sub = KeyPair(), KeyPair()
    parent = env.grant(agent)
    child = env.delegate(parent, agent, sub, operations=["search"])
    assert env.call(sub, "GET", "/flights", child).status_code == 200
    assert env.call(sub, "POST", "/orders", child, {"flight_id": "EVN-CDG-1", "price": 250}).status_code == 403
    assert env.call(agent, "GET", "/flights", child).status_code == 401  # token belongs to sub


def test_revoking_parent_blocks_sub_agent(env):
    agent, sub = KeyPair(), KeyPair()
    parent = env.grant(agent)
    child = env.delegate(parent, agent, sub)
    env.revoke(parent)
    env.refresh() if env.mode == "offline" else None
    assert env.call(sub, "GET", "/flights", child).status_code == 401


# ---- where the modes differ ---------------------------------------------------


def test_outage_online_fails_closed():
    e = make_env("online")
    agent = KeyPair()
    token = e.grant(agent)
    e.fault(mode="error")
    r = e.call(agent, "GET", "/flights", token)
    assert r.status_code == 503
    assert r.json()["error"] == "authorization_unavailable"
    e.client.__exit__(None, None, None)


def test_outage_offline_keeps_serving():
    e = make_env("offline")
    agent = KeyPair()
    token = e.grant(agent)
    e.fault(mode="error")
    assert e.refresh() is False  # cannot reach the issuer
    assert e.call(agent, "GET", "/flights", token).status_code == 200
    e.client.__exit__(None, None, None)


def test_offline_revocation_lag_until_refresh():
    e = make_env("offline")
    agent = KeyPair()
    token = e.grant(agent)
    e.revoke(token)
    # Still allowed: the gateway has not fetched the new list yet.
    assert e.call(agent, "GET", "/flights", token).status_code == 200
    assert e.refresh() is True
    assert e.call(agent, "GET", "/flights", token).status_code == 401
    e.client.__exit__(None, None, None)


def test_online_revocation_is_immediate_without_cache():
    e = make_env("online")
    agent = KeyPair()
    token = e.grant(agent)
    assert e.call(agent, "GET", "/flights", token).status_code == 200
    e.revoke(token)
    assert e.call(agent, "GET", "/flights", token).status_code == 401
    e.client.__exit__(None, None, None)


def test_online_cache_trades_revocation_lag_for_availability():
    e = make_env("online", cache_ttl=30)
    agent = KeyPair()
    token = e.grant(agent)
    assert e.call(agent, "GET", "/flights", token).status_code == 200
    e.revoke(token)
    e.fault(mode="error")
    # Cached positive answer: still allowed during the outage, and despite revocation.
    assert e.call(agent, "GET", "/flights", token).status_code == 200
    assert e.authorizer.cache_hits == 1
    e.clock.t += 31
    assert e.call(agent, "GET", "/flights", token).status_code == 503
    e.fault(mode="none")
    assert e.call(agent, "GET", "/flights", token).status_code == 401
    e.client.__exit__(None, None, None)


def test_offline_max_staleness_fails_closed():
    e = make_env("offline", max_staleness=10)
    agent = KeyPair()
    token = e.grant(agent)
    assert e.call(agent, "GET", "/flights", token).status_code == 200
    e.fault(mode="error")
    e.clock.t += 11
    e.refresh()
    r = e.call(agent, "GET", "/flights", token)
    assert r.status_code == 503
    assert r.json()["error"] == "revocation_list_stale"
    e.fault(mode="none")
    assert e.refresh() is True
    assert e.call(agent, "GET", "/flights", token).status_code == 200
    e.client.__exit__(None, None, None)


def test_slow_server_slows_online_only():
    on, off = make_env("online"), make_env("offline")
    a1, a2 = KeyPair(), KeyPair()
    t1, t2 = on.grant(a1), off.grant(a2)
    on.fault(mode="slow", delay_ms=120)
    off.fault(mode="slow", delay_ms=120)
    r_on = on.call(a1, "GET", "/flights", t1)
    r_off = off.call(a2, "GET", "/flights", t2)
    assert r_on.status_code == r_off.status_code == 200
    assert authz_ms(r_on) >= 120
    assert authz_ms(r_off) < 50
    on.client.__exit__(None, None, None)
    off.client.__exit__(None, None, None)


def test_online_timeout_is_an_outage():
    e = make_env("online", timeout=0.1)
    agent = KeyPair()
    token = e.grant(agent)
    e.fault(mode="hang", hang_seconds=1)
    r = e.call(agent, "GET", "/flights", token)
    assert r.status_code == 503
    assert authz_ms(r) < 900
    e.client.__exit__(None, None, None)


def test_online_bounds_calls_waiting_on_a_hung_server():
    """A hung server must not let calls pile up inside the HTTP pool.

    httpcore rescans its whole queue on every pool event, so thousands of queued
    calls pin the gateway's CPU and it stops answering at all (found in the
    `hang` experiment). Extra calls wait outside the pool, still under the
    deadline, and are refused on time.
    """
    import asyncio
    import time

    in_server, peak = 0, 0

    async def hang(request):
        nonlocal in_server, peak
        in_server += 1
        peak = max(peak, in_server)
        try:
            await asyncio.sleep(60)
        finally:
            in_server -= 1

    async def scenario():
        http = httpx.AsyncClient(transport=httpx.MockTransport(hang))
        authz = OnlineAuthorizer("http://authz/introspect", "gw", "sec", http=http,
                                 timeout=0.2, max_in_flight=5)
        start = time.perf_counter()
        decisions = await asyncio.gather(*(authz.check("t", "k", "search", 0) for _ in range(50)))
        elapsed = time.perf_counter() - start
        await http.aclose()
        return decisions, elapsed

    decisions, elapsed = asyncio.run(scenario())
    assert {(d.status, d.error) for d in decisions} == {(503, "authorization_unavailable")}
    assert peak <= 5
    assert elapsed < 1.0

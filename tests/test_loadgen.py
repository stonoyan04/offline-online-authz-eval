"""Load generator: open-loop schedule and summary arithmetic."""

import asyncio
import sys
from pathlib import Path

import httpx
from biscuit_auth import KeyPair

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))
from loadgen import Sample, run_load, summarize  # noqa: E402


def test_summary_phases_and_percentiles():
    samples = [Sample(i, i * 0.1, 0.0, 10.0 + i, 200, 1.0, "") for i in range(10)]
    samples += [Sample(10 + i, 1.0 + i * 0.1, 0.0, 500.0, 503, None, "authorization_unavailable") for i in range(10)]
    out = {p["phase"]: p for p in summarize(samples, phases=[("a", 0, 1), ("b", 1, 2)])}
    assert out["a"]["success_rate"] == 1.0
    assert out["a"]["p50_ms"] == 15.0
    assert out["b"]["success_rate"] == 0.0
    assert out["b"]["p50_ms"] is None
    assert out["b"]["fail_p50_ms"] == 500.0
    assert out["b"]["errors"] == {"authorization_unavailable": 10}


def test_open_loop_keeps_schedule_when_server_stalls():
    """A stalled server must not slow the generator down (no coordinated omission)."""

    async def stalled(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.3)
        return httpx.Response(200, headers={"server-timing": "authz;dur=0.250"})

    async def go():
        # Patch AsyncClient to use the stalled transport.
        original = httpx.AsyncClient

        class Client(original):
            def __init__(self, *a, **kw):
                kw["transport"] = httpx.MockTransport(stalled)
                super().__init__(*a, **kw)

        httpx.AsyncClient = Client
        try:
            return await run_load("http://svc", KeyPair(), lambda: "t", rate=50, duration=1.0)
        finally:
            httpx.AsyncClient = original

    samples = asyncio.run(go())
    assert len(samples) == 50
    assert max(s.send_lag_ms for s in samples) < 100  # sent on schedule despite 300 ms responses
    assert all(s.latency_ms >= 290 for s in samples)
    assert all(s.authz_ms == 0.25 for s in samples)


def test_requests_are_spread_over_small_connection_pools():
    """httpcore rescans every connection of a pool on each event, so one pool with
    thousands of connections stalls the generator under overload (seen after the
    `hang` fault). The generator uses several small pools instead."""
    created = []

    async def ok(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    async def go():
        original = httpx.AsyncClient

        class Client(original):
            def __init__(self, *a, **kw):
                created.append({"limits": kw.get("limits"), "requests": 0})
                me = created[-1]

                async def count(request):
                    me["requests"] += 1
                    return await ok(request)

                kw["transport"] = httpx.MockTransport(count)
                super().__init__(*a, **kw)

        httpx.AsyncClient = Client
        try:
            return await run_load("http://svc", KeyPair(), lambda: "t", rate=200, duration=0.5,
                                  max_in_flight=256)
        finally:
            httpx.AsyncClient = original

    samples = asyncio.run(go())
    assert len(samples) == 100 and all(s.status == 200 for s in samples)
    assert len(created) == 4
    assert all(c["limits"].max_connections == 64 for c in created)
    assert [c["requests"] for c in created] == [25, 25, 25, 25]


# ---- delegation chains (--chain-depth) ------------------------------------------

import pytest  # noqa: E402
from biscuit_auth import Biscuit  # noqa: E402

from agentauthz import delegation  # noqa: E402
from loadgen import delegation_chain, offline_hop, online_hop  # noqa: E402
from test_gateway import Env  # noqa: E402


def chain_for(env, depth):
    first = KeyPair()
    token = env.grant(first)
    if env.mode == "offline":
        hop = offline_hop(env.root.public_key)
    else:
        hop = online_hop(lambda path, content, headers: env.admin.post(path, content=content, headers=headers),
                         now=env.clock)
    last, chained = delegation_chain(first, token, depth, hop)
    return first, last, chained


@pytest.mark.parametrize("mode", ["offline", "online"])
@pytest.mark.parametrize("depth", [0, 1, 2, 3, 5])
def test_chain_is_valid_through_the_gateway_at_each_depth(mode, depth):
    env = Env(mode)
    with env.client:
        first, last, token = chain_for(env, depth)
        assert (last is first) == (depth == 0)
        r = env.call(last, "GET", "/flights", token)
        assert r.status_code == 200, r.text
        assert r.headers["agent-authz-mode"] == mode
        if mode == "offline":
            parsed = Biscuit.from_base64(token, env.root.public_key)
            assert parsed.block_count() == depth + 1
        else:
            info = env.admin.post("/introspect", data={"token": token}, auth=("gw", "sec")).json()
            assert info["active"] and info["delegation_depth"] == depth
            assert info["cnf"]["agent_key"] == delegation.key_hex(last.public_key)


@pytest.mark.parametrize("mode", ["offline", "online"])
def test_chain_rejects_every_holder_but_the_last(mode):
    env = Env(mode)
    with env.client:
        first, last, token = chain_for(env, 3)
        for signer in (first, KeyPair()):
            r = env.call(signer, "GET", "/flights", token)
            assert r.status_code == 401 and r.json()["error"] == "invalid_token", r.text


def test_each_hop_narrows_the_amount():
    env = Env("offline")
    with env.client:
        _, last, token = chain_for(env, 2)
        ok = env.call(last, "POST", "/orders", token, {"flight_id": "EVN-CDG-1", "price": 298})
        over = env.call(last, "POST", "/orders", token, {"flight_id": "EVN-CDG-1", "price": 299})
        assert ok.status_code != 403 and over.status_code == 403, (ok.text, over.text)

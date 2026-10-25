"""Agent-task workload: delegate to a fresh sub-agent, then use the new token."""

import asyncio
import sys
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
from biscuit_auth import KeyPair

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))
from tasks import (  # noqa: E402
    DelegationFailed,
    TaskSample,
    online_task_hop,
    run_tasks,
    summarize_tasks,
)

from agentauthz.keys import public_hex  # noqa: E402
from agentauthz.pop import HEADER_KEY, HEADER_SIGNATURE  # noqa: E402


def gateway(handler):
    return httpx.MockTransport(handler)


def ok(request):
    return httpx.Response(200, headers={"server-timing": "authz;dur=0.200"}, json={"ok": True})


def run(hop, handler=ok, **kw):
    kw.setdefault("rate", 20)
    kw.setdefault("duration", 0.5)
    return asyncio.run(run_tasks("http://svc", KeyPair(), "root", hop, transport=gateway(handler), **kw))


def test_task_delegates_once_then_sends_its_requests_with_the_new_token():
    hops, seen = [], []

    async def hop(token, parent, child, max_amount):
        hops.append((token, max_amount, public_hex(child)))
        return f"sub-{len(hops)}"

    def handler(request):
        seen.append(request.headers["authorization"])
        return ok(request)

    tasks, requests = run(hop, handler, requests_per_task=3, max_amount=300)
    assert len(tasks) == 10 and len(requests) == 30
    assert all(t.error == "" and t.requests_ok == 3 for t in tasks)
    assert {h[0] for h in hops} == {"root"} and {h[1] for h in hops} == {299}
    assert len({h[2] for h in hops}) == 10  # a fresh sub-agent key per task
    assert sorted(seen) == sorted(f"Bearer sub-{i}" for i in range(1, 11) for _ in range(3))
    assert all(r.status == 200 and r.authz_ms == 0.2 for r in requests)


def test_failed_delegation_sends_no_requests():
    async def hop(token, parent, child, max_amount):
        raise DelegationFailed("exchange_503")

    tasks, requests = run(hop)
    assert requests == []
    assert {(t.delegate_error, t.error, t.requests_ok) for t in tasks} == {("exchange_503", "exchange_503", 0)}


def test_task_stops_at_its_first_failed_request():
    count = 0

    async def hop(token, parent, child, max_amount):
        return "sub"

    def handler(request):
        nonlocal count
        count += 1
        if count == 2:
            return httpx.Response(503, json={"error": "authorization_unavailable"})
        return ok(request)

    tasks, requests = run(hop, handler, rate=1, duration=1, requests_per_task=5)
    assert [r.status for r in requests] == [200, 503]
    assert (tasks[0].requests_ok, tasks[0].error) == (1, "authorization_unavailable")


def test_tasks_over_the_in_flight_cap_are_recorded_not_queued():
    async def hop(token, parent, child, max_amount):
        await asyncio.sleep(0.5)
        return "sub"

    tasks, _ = run(hop, rate=40, duration=0.25, max_in_flight=3)
    assert len(tasks) == 10
    assert sum(t.error == "generator_overload" for t in tasks) == 7
    assert max(t.send_lag_ms for t in tasks) < 100  # schedule kept while tasks stall


def test_online_hop_exchanges_the_token_signed_by_the_parent():
    parent, child = KeyPair(), KeyPair()
    seen = {}

    def server(request):
        seen.update(path=request.url.path, form=parse_qs(request.content.decode()),
                    key=request.headers.get(HEADER_KEY), signed=HEADER_SIGNATURE in request.headers)
        return httpx.Response(200, json={"access_token": "sub-token"})

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(server), base_url="http://authz") as http:
            return await online_task_hop(http, deadline=1.0)("root", parent, child, 299)

    assert asyncio.run(go()) == "sub-token"
    assert seen["path"] == "/token/exchange" and seen["signed"]
    assert seen["key"] == public_hex(parent)  # the current holder signs the exchange
    assert seen["form"]["subject_token"] == ["root"]
    assert seen["form"]["actor_key"] == [public_hex(child)]
    assert seen["form"]["max_amount"] == ["299"]


@pytest.mark.parametrize("handler, code", [
    (lambda r: httpx.Response(503, json={"error": "temporarily_unavailable"}), "exchange_503"),
    (lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused")), "ConnectError"),
])
def test_online_hop_failures_become_delegation_errors(handler, code):
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://authz") as http:
            await online_task_hop(http, deadline=1.0)("root", KeyPair(), KeyPair(), 299)

    with pytest.raises(DelegationFailed) as exc:
        asyncio.run(go())
    assert exc.value.code == code


def test_online_hop_gives_up_at_the_deadline():
    async def hang(request):
        await asyncio.sleep(5)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(hang), base_url="http://authz") as http:
            loop = asyncio.get_running_loop()
            start = loop.time()
            with pytest.raises(DelegationFailed) as exc:
                await online_task_hop(http, deadline=0.2)("root", KeyPair(), KeyPair(), 299)
            return exc.value.code, loop.time() - start

    code, elapsed = asyncio.run(go())
    assert code == "exchange_timeout" and elapsed < 1.0


def test_summary_per_phase():
    def task(seq, t, error="", delegate_ms=1.0, task_ms=10.0, lag=0.1):
        return TaskSample(seq, t, lag, delegate_ms, error if error.startswith("exchange") else "",
                          0 if error else 5, task_ms, error)

    tasks = [task(i, i * 0.1, task_ms=10.0 + i) for i in range(10)]
    tasks += [task(10 + i, 1.0 + i * 0.1, error="exchange_503", delegate_ms=2.0) for i in range(8)]
    tasks += [task(18, 1.8, error="authorization_unavailable"), task(19, 1.9, task_ms=30.0)]
    out = {p["phase"]: p for p in summarize_tasks(tasks, phases=[("a", 0, 1), ("b", 1, 2)])}
    assert out["a"]["tasks"] == 10
    assert out["a"]["task_success_rate"] == 1.0 and out["a"]["delegation_success_rate"] == 1.0
    assert out["a"]["task_p50_ms"] == 15.0 and out["a"]["delegate_p50_ms"] == 1.0
    assert out["b"]["task_success_rate"] == 0.1
    assert out["b"]["delegation_success_rate"] == 0.2
    assert out["b"]["task_p50_ms"] == 30.0
    assert out["b"]["errors"] == {"authorization_unavailable": 1, "exchange_503": 8}
    assert out["b"]["send_lag_p99_ms"] == 0.1

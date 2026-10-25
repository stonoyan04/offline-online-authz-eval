"""Agent-task workload: delegate to a fresh sub-agent, then use the new token.

Each task is what an agent does when it hands part of its work to a
sub-agent: generate a key pair for the sub-agent, delegate a narrower token
to it (offline: a Biscuit block signed locally; online: an RFC 8693 token
exchange at the authorization server), and let the sub-agent send
`requests_per_task` signed requests through the gateway, one after another.
Tasks start open-loop at a fixed rate, as in loadgen.py, so a stalled
server cannot slow the schedule down.

Each task is recorded with:

    seq             task number
    t_sched         scheduled start, seconds since the run started
    send_lag_ms     how late the task actually started (generator health)
    delegate_ms     time to get the sub-agent's token, or to give up on it
    delegate_error  why delegation failed ("" if it succeeded)
    requests_ok     requests that got a 2xx answer (the task stops at the first failure)
    task_ms         scheduled start -> last response
    error           first error of the task ("" if the whole task succeeded)

Every request is also recorded as a loadgen.Sample. Requests inside a task
are not scheduled (each waits for the previous one), so their `t_sched` is
the actual send time and `send_lag_ms` is 0; generator health is the task's
send lag.
"""

from __future__ import annotations

import asyncio
import contextlib
import math
import time
from dataclasses import asdict, dataclass
from typing import Awaitable, Callable, Optional
from urllib.parse import urlencode

import httpx
from biscuit_auth import KeyPair, PublicKey

from loadgen import MAX_AMOUNT, POOL_SIZE, TOKEN_EXCHANGE, Sample, _authz_ms, _pct, offline_hop

from agentauthz.keys import public_hex
from agentauthz.pop import sign_request, to_headers

# (token, current holder, next holder, max_amount for the next holder) -> next token
AsyncHop = Callable[[str, KeyPair, KeyPair, int], Awaitable[str]]


class DelegationFailed(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class TaskSample:
    seq: int
    t_sched: float
    send_lag_ms: float
    delegate_ms: Optional[float]
    delegate_error: str
    requests_ok: int
    task_ms: Optional[float]
    error: str

    def row(self) -> dict:
        return asdict(self)


def offline_task_hop(issuer: PublicKey) -> AsyncHop:
    """loadgen.offline_hop for tasks: local attenuation, nothing to wait for."""
    hop = offline_hop(issuer)

    async def run(token: str, parent: KeyPair, child: KeyPair, max_amount: int) -> str:
        return hop(token, parent, child, max_amount)
    return run


def online_task_hop(http: httpx.AsyncClient, deadline: float, now: Callable[[], float] = time.time) -> AsyncHop:
    """RFC 8693 token exchange signed by the current holder, given up after `deadline` s.

    `http` has the authorization server as base URL. Same request as
    loadgen.online_hop, which builds chains before a run.
    """
    async def run(token: str, parent: KeyPair, child: KeyPair, max_amount: int) -> str:
        body = urlencode({"grant_type": TOKEN_EXCHANGE, "subject_token": token,
                          "actor_key": public_hex(child), "max_amount": str(max_amount)}).encode()
        headers = to_headers(sign_request(parent, "POST", "/token/exchange", body, created=int(now())))
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            r = await asyncio.wait_for(http.post("/token/exchange", content=body, headers=headers), deadline)
        except asyncio.TimeoutError:
            raise DelegationFailed("exchange_timeout") from None
        except httpx.HTTPError as exc:
            raise DelegationFailed(type(exc).__name__) from None
        if r.status_code != 200:
            raise DelegationFailed(f"exchange_{r.status_code}")
        return r.json()["access_token"]
    return run


async def run_tasks(
    base_url: str,
    holder: KeyPair,
    token: str,
    hop: AsyncHop,
    *,
    rate: float,
    duration: float,
    requests_per_task: int = 5,
    max_amount: int = MAX_AMOUNT,
    path: str = "/flights",
    timeout: float = 5.0,
    max_in_flight: int = 1000,
    on_tick: Optional[Callable[[float], None]] = None,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> tuple[list[TaskSample], list[Sample]]:
    """Start `rate` tasks/second for `duration` seconds; returns (tasks, requests).

    `holder` owns `token`; every task delegates from it with `max_amount - 1`.
    `on_tick(t)` is called about every 100 ms with the elapsed run time.
    `transport` replaces the gateway connection (tests).
    """
    tasks: list[TaskSample] = []
    requests: list[Sample] = []
    limits = httpx.Limits(max_connections=POOL_SIZE, max_keepalive_connections=POOL_SIZE)
    async with contextlib.AsyncExitStack() as stack:
        clients = [
            await stack.enter_async_context(httpx.AsyncClient(
                base_url=base_url, timeout=timeout, limits=limits,
                **({"transport": transport} if transport else {})))
            # A task sends one request at a time, so tasks in flight bound the connections.
            for _ in range(math.ceil(max_in_flight / POOL_SIZE))
        ]
        start = time.perf_counter()
        in_flight: set[asyncio.Task] = set()
        next_tick = 0.0

        async def request(seq: int, http: httpx.AsyncClient, sub: KeyPair, sub_token: str) -> Sample:
            sent = time.perf_counter()
            signed = sign_request(sub, "GET", path, token=sub_token)
            status, authz, error = 0, None, ""
            try:
                resp = await http.get(path, headers=to_headers(signed))
                status, authz = resp.status_code, _authz_ms(resp)
                if status >= 400:
                    try:
                        error = resp.json().get("error", "")
                    except ValueError:
                        error = "non_json"
            except httpx.TimeoutException:
                error = "client_timeout"
            except httpx.HTTPError as exc:
                error = type(exc).__name__
            return Sample(seq, round(sent - start, 6), 0.0,
                          round((time.perf_counter() - sent) * 1000, 3), status, authz, error)

        async def one(seq: int, t_sched: float) -> None:
            began = time.perf_counter()
            lag = (began - start - t_sched) * 1000
            sub = KeyPair()
            delegate_error, sub_token = "", ""
            try:
                sub_token = await hop(token, holder, sub, max_amount - 1)
            except DelegationFailed as exc:
                delegate_error = exc.code
            except Exception as exc:  # offline attenuation has no server to blame
                delegate_error = type(exc).__name__
            delegate_ms = (time.perf_counter() - began) * 1000
            ok, error = 0, delegate_error
            if not delegate_error:
                http = clients[seq % len(clients)]
                for i in range(requests_per_task):
                    s = await request(seq * requests_per_task + i, http, sub, sub_token)
                    requests.append(s)
                    if not 200 <= s.status < 300:
                        error = s.error or f"status_{s.status}"
                        break
                    ok += 1
            tasks.append(TaskSample(seq, round(t_sched, 6), round(lag, 3), round(delegate_ms, 3),
                                    delegate_error, ok, round((time.perf_counter() - start - t_sched) * 1000, 3),
                                    error))

        for seq in range(int(rate * duration)):
            t_sched = seq / rate
            delay = start + t_sched - time.perf_counter()
            if delay > 0:
                await asyncio.sleep(delay)
            elapsed = time.perf_counter() - start
            if on_tick and elapsed >= next_tick:
                on_tick(elapsed)
                next_tick = elapsed + 0.1
            if len(in_flight) >= max_in_flight:
                tasks.append(TaskSample(seq, round(t_sched, 6), 0.0, None, "", 0, None, "generator_overload"))
                continue
            task = asyncio.create_task(one(seq, t_sched))
            in_flight.add(task)
            task.add_done_callback(in_flight.discard)

        if in_flight:
            await asyncio.gather(*in_flight, return_exceptions=True)
    tasks.sort(key=lambda t: t.seq)
    requests.sort(key=lambda s: s.seq)
    return tasks, requests


def summarize_tasks(tasks: list[TaskSample], *, phases: Optional[list[tuple[str, float, float]]] = None) -> list[dict]:
    """Per-phase summary by task start time. `phases` is [(name, start_s, end_s)]."""
    if not tasks:
        return []
    end = max(t.t_sched for t in tasks) + 1e-9
    phases = phases or [("all", 0.0, end)]
    out = []
    for name, lo, hi in phases:
        rows = [t for t in tasks if lo <= t.t_sched < hi]
        if not rows:
            continue
        done = [t for t in rows if not t.error]
        delegated = [t for t in rows if t.delegate_ms is not None and not t.delegate_error]
        out.append({
            "phase": name,
            "tasks": len(rows),
            "task_success_rate": round(len(done) / len(rows), 4),
            "delegation_success_rate": round(len(delegated) / len(rows), 4),
            "delegate_p50_ms": _pct([t.delegate_ms for t in delegated], 0.50),
            "delegate_p99_ms": _pct([t.delegate_ms for t in delegated], 0.99),
            "task_p50_ms": _pct([t.task_ms for t in done], 0.50),
            "task_p99_ms": _pct([t.task_ms for t in done], 0.99),
            "send_lag_p99_ms": _pct([t.send_lag_ms for t in rows], 0.99),
            "errors": dict(sorted({e: sum(1 for t in rows if t.error == e)
                                   for e in {t.error for t in rows if t.error}}.items())),
        })
    return out

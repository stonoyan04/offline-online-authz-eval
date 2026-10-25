"""Open-loop load generator that signs every request.

Requests are scheduled at a fixed rate, independent of how fast responses come
back. Latency is measured from each request's *scheduled* send time, so a
slow or stalled server cannot hide its slowness by slowing the generator down
(coordinated omission).

Each request is recorded with:

    seq          request number
    t_sched      scheduled send time, seconds since the run started
    send_lag_ms  how late the generator actually sent it (generator health)
    latency_ms   scheduled send time -> response (or error)
    status       HTTP status, or 0 for timeout / connection error
    authz_ms     gateway's own authorization time (Server-Timing), if present
    error        short error code from the gateway or the client

If send_lag_ms grows, the generator itself is the bottleneck and the run is
not valid at that rate; `summarize()` reports it.
"""

from __future__ import annotations

import asyncio
import contextlib
import math
import statistics
import time
from dataclasses import asdict, dataclass
from typing import Callable, Optional

from urllib.parse import urlencode

import httpx
from biscuit_auth import Biscuit, KeyPair, PublicKey

from agentauthz import delegation
from agentauthz.keys import public_hex
from agentauthz.pop import sign_request, to_headers

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"

# Connections per httpx client. httpcore rescans every connection of a pool on
# each request event, so one pool with thousands of connections pins the CPU
# when responses slow down and the generator falls behind its schedule. Several
# small pools, used round-robin, keep that cost flat.
POOL_SIZE = 64


@dataclass
class Sample:
    seq: int
    t_sched: float
    send_lag_ms: float
    latency_ms: float
    status: int
    authz_ms: Optional[float]
    error: str

    def row(self) -> dict:
        return asdict(self)


def _authz_ms(resp: httpx.Response) -> Optional[float]:
    timing = resp.headers.get("server-timing", "")
    if "dur=" not in timing:
        return None
    try:
        return float(timing.split("dur=")[1].split(";")[0].split(",")[0])
    except ValueError:
        return None


async def run_load(
    base_url: str,
    holder: KeyPair,
    token_for: Callable[[], str],
    *,
    rate: float,
    duration: float,
    path: str = "/flights",
    timeout: float = 5.0,
    max_in_flight: int = 2000,
    on_tick: Optional[Callable[[float], None]] = None,
) -> list[Sample]:
    """Send GET `path` at `rate` requests/second for `duration` seconds.

    `token_for()` is called per request, so a scenario can switch tokens.
    `on_tick(t)` is called about every 100 ms with the elapsed run time, so a
    scenario can inject faults on a timeline without a second clock.
    """
    samples: list[Sample] = []
    limits = httpx.Limits(max_connections=POOL_SIZE, max_keepalive_connections=POOL_SIZE)
    async with contextlib.AsyncExitStack() as stack:
        clients = [
            await stack.enter_async_context(httpx.AsyncClient(base_url=base_url, timeout=timeout, limits=limits))
            for _ in range(math.ceil(max_in_flight / POOL_SIZE))
        ]
        start = time.perf_counter()
        total = int(rate * duration)
        in_flight: set[asyncio.Task] = set()
        next_tick = 0.0

        async def one(seq: int, t_sched: float) -> None:
            sent_at = time.perf_counter()
            lag = (sent_at - start - t_sched) * 1000
            token = token_for()
            signed = sign_request(holder, "GET", path, token=token)
            status, authz, error = 0, None, ""
            try:
                resp = await clients[seq % len(clients)].get(path, headers=to_headers(signed))
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
            done = time.perf_counter()
            samples.append(
                Sample(seq, round(t_sched, 6), round(lag, 3),
                       round((done - start - t_sched) * 1000, 3), status, authz, error)
            )

        for seq in range(total):
            t_sched = seq / rate
            delay = start + t_sched - time.perf_counter()
            if delay > 0:
                await asyncio.sleep(delay)
            elapsed = time.perf_counter() - start
            if on_tick and elapsed >= next_tick:
                on_tick(elapsed)
                next_tick = elapsed + 0.1
            if len(in_flight) >= max_in_flight:
                # Record as a generator-side drop rather than blocking the schedule.
                samples.append(Sample(seq, round(t_sched, 6), 0.0, 0.0, 0, None, "generator_overload"))
                continue
            task = asyncio.create_task(one(seq, t_sched))
            in_flight.add(task)
            task.add_done_callback(in_flight.discard)

        if in_flight:
            await asyncio.gather(*in_flight, return_exceptions=True)
    samples.sort(key=lambda s: s.seq)
    return samples


# --------------------------------------------------------------------------
# Delegation chains (run_experiment.py --chain-depth)
# --------------------------------------------------------------------------

# One hop: (token, current holder, next holder, max_amount for the next holder) -> next token.
Hop = Callable[[str, KeyPair, KeyPair, int], str]


def delegation_chain(holder: KeyPair, token: str, depth: int, hop: Hop) -> tuple[KeyPair, str]:
    """Delegate `depth` times to fresh keys; returns the last holder and its token.

    Each hop also lowers the amount limit by one, so every hop adds a real
    restriction, as in spike/bench.py. Done before the load starts, so token
    creation is never inside the measured window.
    """
    limit = None
    for _ in range(depth):
        child = KeyPair()
        limit = (MAX_AMOUNT if limit is None else limit) - 1
        token = hop(token, holder, child, limit)
        holder = child
    return holder, token


MAX_AMOUNT = 300  # of the root grant (run_experiment.Stack.grant)


def offline_hop(issuer: PublicKey) -> Hop:
    """Attenuate the Biscuit locally: a third-party block signed by the current holder."""
    def hop(token: str, parent: KeyPair, child: KeyPair, max_amount: int) -> str:
        parsed = Biscuit.from_base64(token, issuer)
        return delegation.delegate(parsed, parent, child.public_key, max_amount=max_amount).to_base64()
    return hop


def online_hop(post: Callable[..., httpx.Response], now: Callable[[], float] = time.time) -> Hop:
    """RFC 8693 token exchange at the authorization server, signed by the current holder.

    `post(path, content=..., headers=...)` sends to the authorization server.
    """
    def hop(token: str, parent: KeyPair, child: KeyPair, max_amount: int) -> str:
        body = urlencode({"grant_type": TOKEN_EXCHANGE, "subject_token": token,
                          "actor_key": public_hex(child), "max_amount": str(max_amount)}).encode()
        headers = to_headers(sign_request(parent, "POST", "/token/exchange", body, created=int(now())))
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        r = post("/token/exchange", content=body, headers=headers)
        if r.status_code != 200:
            raise RuntimeError(f"token exchange failed: {r.status_code} {r.text}")
        return r.json()["access_token"]
    return hop


def _pct(values: list[float], q: float) -> Optional[float]:
    if not values:
        return None
    values = sorted(values)
    return round(values[min(len(values) - 1, int(q * len(values)))], 3)


def summarize(samples: list[Sample], *, phases: Optional[list[tuple[str, float, float]]] = None) -> list[dict]:
    """Per-phase summary. `phases` is [(name, start_s, end_s)]; default one phase."""
    if not samples:
        return []
    end = max(s.t_sched for s in samples) + 1e-9
    phases = phases or [("all", 0.0, end)]
    out = []
    for name, lo, hi in phases:
        rows = [s for s in samples if lo <= s.t_sched < hi]
        if not rows:
            continue
        ok = [s for s in rows if 200 <= s.status < 300]
        lat_ok = [s.latency_ms for s in ok]
        lat_fail = [s.latency_ms for s in rows if not 200 <= s.status < 300 and s.error != "generator_overload"]
        lags = [s.send_lag_ms for s in rows]
        out.append(
            {
                "phase": name,
                "requests": len(rows),
                "success_rate": round(len(ok) / len(rows), 4),
                "p50_ms": _pct(lat_ok, 0.50),
                "p95_ms": _pct(lat_ok, 0.95),
                "p99_ms": _pct(lat_ok, 0.99),
                "authz_p50_ms": _pct([s.authz_ms for s in ok if s.authz_ms is not None], 0.50),
                "fail_p50_ms": _pct(lat_fail, 0.50),
                "fail_p99_ms": _pct(lat_fail, 0.99),
                "send_lag_p99_ms": _pct(lags, 0.99),
                "errors": dict(
                    sorted(
                        {e: sum(1 for s in rows if s.error == e) for e in {s.error for s in rows if s.error}}.items()
                    )
                ),
                "mean_ms": round(statistics.fmean(lat_ok), 3) if lat_ok else None,
            }
        )
    return out

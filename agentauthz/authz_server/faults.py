"""Fault injection for the authorization server.

The experiments change the server's behaviour at runtime through
`PUT /admin/fault`. Faults apply only to the endpoints gateways depend on
(introspection, token exchange, revocation list), never to admin or health
endpoints, so the harness can always switch them back off.

Modes
-----
none      normal operation
slow      add `delay_ms` (+ uniform random up to `jitter_ms`) to every response
error     answer `error_status` (default 503) immediately
hang      hold the request for `hang_seconds`, then answer 503; models a
          black-holed server, so the gateway's own timeout decides
flapping  alternate healthy and failing: in every `period_seconds`, the first
          `down_fraction` of the period behaves like `error`

A stopped server (connection refused) is not simulated here; the evaluation
harness stops the process or container for that case.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from typing import Callable, Literal, Optional

from pydantic import BaseModel, Field

Mode = Literal["none", "slow", "error", "hang", "flapping"]


class FaultConfig(BaseModel):
    mode: Mode = "none"
    delay_ms: float = Field(0, ge=0, le=60_000)
    jitter_ms: float = Field(0, ge=0, le=60_000)
    error_status: int = Field(503, ge=400, le=599)
    hang_seconds: float = Field(30, ge=0, le=600)
    period_seconds: float = Field(10, gt=0, le=3600)
    down_fraction: float = Field(0.5, ge=0, le=1)


@dataclass
class FaultOutcome:
    """What the endpoint should do after the fault has been applied."""

    fail_status: Optional[int] = None  # None means: answer normally


class FaultInjector:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._config = FaultConfig()
        self._since = clock()
        self.counters = {"requests": 0, "failed": 0, "delayed": 0}

    @property
    def config(self) -> FaultConfig:
        return self._config

    def set(self, config: FaultConfig) -> None:
        self._config = config
        self._since = self._clock()

    def state(self) -> dict:
        return {"config": self._config.model_dump(), "counters": dict(self.counters)}

    def _flapping_down(self) -> bool:
        cfg = self._config
        position = (self._clock() - self._since) % cfg.period_seconds
        return position < cfg.down_fraction * cfg.period_seconds

    async def apply(self) -> FaultOutcome:
        cfg = self._config
        self.counters["requests"] += 1

        if cfg.mode == "slow":
            delay = cfg.delay_ms + random.uniform(0, cfg.jitter_ms)
            if delay > 0:
                self.counters["delayed"] += 1
                await asyncio.sleep(delay / 1000)
            return FaultOutcome()

        if cfg.mode == "error" or (cfg.mode == "flapping" and self._flapping_down()):
            self.counters["failed"] += 1
            return FaultOutcome(fail_status=cfg.error_status)

        if cfg.mode == "hang":
            self.counters["failed"] += 1
            await asyncio.sleep(cfg.hang_seconds)
            return FaultOutcome(fail_status=503)

        return FaultOutcome()


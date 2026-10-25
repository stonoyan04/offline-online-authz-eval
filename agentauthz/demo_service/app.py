"""Demo airline API protected by the gateway middleware.

The handlers are trivial on purpose: the experiments measure authorization,
so the service itself should add as little latency and noise as possible.

Operations used in tokens:
    search  GET /flights, GET /orders/{id}
    buy     POST /orders           (amount = "price" in the JSON body)
    cancel  DELETE /orders/{id}
"""

from __future__ import annotations

import itertools
from contextlib import asynccontextmanager
from typing import Awaitable, Callable, Optional

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from agentauthz.gateway import Authorizer, AuthzMiddleware, Route, RouteMap
from agentauthz.pop import ReplayCache

ROUTES = RouteMap(
    routes=(
        Route("GET", "/flights", "search"),
        Route("GET", "/orders/{order_id}", "search"),
        Route("POST", "/orders", "buy", amount_field="price"),
        Route("DELETE", "/orders/{order_id}", "cancel"),
    )
)

FLIGHTS = [
    {"id": "EVN-CDG-1", "from": "EVN", "to": "CDG", "price": 250},
    {"id": "EVN-CDG-2", "from": "EVN", "to": "CDG", "price": 410},
    {"id": "EVN-JFK-1", "from": "EVN", "to": "JFK", "price": 780},
]


class OrderRequest(BaseModel):
    flight_id: str
    price: int = Field(ge=0)


def create_demo_app(
    authorizer: Authorizer,
    *,
    routes: RouteMap = ROUTES,
    replay: Optional[ReplayCache] = None,
    on_shutdown: Optional[Callable[[], Awaitable[None]]] = None,
    clock=None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await authorizer.start()
        try:
            yield
        finally:
            await authorizer.stop()
            if on_shutdown:
                await on_shutdown()

    app = FastAPI(title="agentauthz demo service", version="0.1.0", lifespan=lifespan)
    orders: dict[str, dict] = {}
    ids = itertools.count(1)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"ok": True, "mode": authorizer.mode}

    @app.get("/flights")
    async def flights(to: Optional[str] = None) -> list[dict]:
        return [f for f in FLIGHTS if to is None or f["to"] == to.upper()]

    @app.post("/orders", status_code=201)
    async def buy(order: OrderRequest, request: Request) -> dict:
        flight = next((f for f in FLIGHTS if f["id"] == order.flight_id), None)
        if flight is None:
            raise HTTPException(404, "unknown flight")
        if order.price != flight["price"]:
            raise HTTPException(409, "price changed")
        order_id = str(next(ids))
        orders[order_id] = {
            "id": order_id,
            "flight_id": order.flight_id,
            "price": order.price,
            "agent": request.scope.get("state", {}).get("agentauthz", {}).get("holder"),
            "status": "confirmed",
        }
        return orders[order_id]

    @app.get("/orders/{order_id}")
    async def get_order(order_id: str) -> dict:
        if order_id not in orders:
            raise HTTPException(404, "unknown order")
        return orders[order_id]

    @app.delete("/orders/{order_id}")
    async def cancel(order_id: str) -> dict:
        if order_id not in orders:
            raise HTTPException(404, "unknown order")
        orders[order_id]["status"] = "cancelled"
        return orders[order_id]

    kwargs = {"authorizer": authorizer, "routes": routes, "replay": replay}
    if clock is not None:
        kwargs["clock"] = clock
    app.add_middleware(AuthzMiddleware, **kwargs)
    return app

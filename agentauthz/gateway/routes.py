"""Map HTTP requests to operations the token speaks about.

The token grants operations such as "search" or "buy"; the service exposes
routes such as `GET /flights` or `POST /orders`. The gateway needs a mapping
between the two, and for spending operations, where in the request the amount
is. Routes that are not mapped are denied (default deny), except for paths
explicitly marked public.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional


class RouteError(ValueError):
    """The request matched a route but its amount could not be read."""


@dataclass(frozen=True)
class Route:
    method: str
    pattern: str  # e.g. "/orders/{order_id}"
    operation: str
    amount_field: Optional[str] = None  # JSON body field holding the amount
    _regex: re.Pattern = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        parts = re.split(r"(\{[a-zA-Z_][a-zA-Z0-9_]*\})", self.pattern)
        regex = "".join(
            "[^/]+" if p.startswith("{") and p.endswith("}") else re.escape(p) for p in parts
        )
        object.__setattr__(self, "_regex", re.compile(f"^{regex}$"))
        object.__setattr__(self, "method", self.method.upper())

    def matches(self, method: str, path: str) -> bool:
        return method.upper() == self.method and bool(self._regex.match(path))

    def amount(self, body: bytes) -> int:
        if self.amount_field is None:
            return 0
        try:
            value = json.loads(body or b"null")[self.amount_field]
        except (ValueError, TypeError, KeyError):
            raise RouteError(f"request body must be JSON with '{self.amount_field}'")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RouteError(f"'{self.amount_field}' must be a non-negative integer")
        return value


@dataclass(frozen=True)
class RouteMap:
    routes: tuple[Route, ...]
    public_paths: frozenset[str] = frozenset({"/healthz"})

    def is_public(self, path: str) -> bool:
        return path in self.public_paths

    def match(self, method: str, path: str) -> Optional[Route]:
        for route in self.routes:
            if route.matches(method, path):
                return route
        return None

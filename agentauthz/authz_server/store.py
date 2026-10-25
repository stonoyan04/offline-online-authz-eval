"""In-memory grant store for the online baseline.

Opaque tokens map to grants held by the server. Every request the gateway
authorizes in online mode needs this store, through introspection (RFC 7662).
Delegation to a sub-agent needs it too, through token exchange (RFC 8693),
which is the second architectural difference from the offline design.

The store keeps the same semantics as the Biscuit tokens: a holder key per
grant, rights can only narrow along a delegation chain, and revoking a grant
revokes everything derived from it.

The store is not thread-safe and lives in one process; run the server with a
single worker. That is enough for the experiments and keeps the baseline as
fast as an online check can be, which makes the comparison fair to it.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Iterable, Optional

_OP_RE = re.compile(r"^[a-z][a-z0-9_:.-]{0,63}$")
_KEY_RE = re.compile(r"^[0-9a-f]{64}$")

MAX_DEPTH = 16


class GrantError(ValueError):
    """A request to issue or exchange a grant was refused."""


@dataclass
class Grant:
    token: str
    user: str
    holder: str  # hex Ed25519 public key
    operations: frozenset[str]
    max_amount: int
    issued_at: int
    expires_at: int
    parent: Optional[str] = None
    depth: int = 0
    revoked: bool = False


def _check_ops(ops: Iterable[str]) -> frozenset[str]:
    ops = frozenset(ops)
    if not ops:
        raise GrantError("at least one operation is required")
    bad = [op for op in ops if not _OP_RE.match(op)]
    if bad:
        raise GrantError(f"invalid operation names: {sorted(bad)}")
    return ops


def _check_key(key: str) -> str:
    if not _KEY_RE.match(key):
        raise GrantError("holder key must be 64 lowercase hex characters")
    return key


class GrantStore:
    def __init__(self) -> None:
        self._grants: dict[str, Grant] = {}

    def __len__(self) -> int:
        return len(self._grants)

    def get(self, token: str) -> Optional[Grant]:
        return self._grants.get(token)

    def issue(
        self,
        *,
        user: str,
        holder: str,
        operations: Iterable[str],
        max_amount: int,
        ttl_seconds: int,
        now: int,
    ) -> Grant:
        if max_amount < 0:
            raise GrantError("max_amount must be non-negative")
        if ttl_seconds <= 0:
            raise GrantError("ttl_seconds must be positive")
        grant = Grant(
            token=secrets.token_urlsafe(32),
            user=user,
            holder=_check_key(holder),
            operations=_check_ops(operations),
            max_amount=max_amount,
            issued_at=now,
            expires_at=now + ttl_seconds,
        )
        self._grants[grant.token] = grant
        return grant

    def active(self, token: str, now: int) -> Optional[Grant]:
        """The grant if it and every ancestor is unexpired and unrevoked."""
        grant = self._grants.get(token)
        node = grant
        while node is not None:
            if node.revoked or node.expires_at <= now:
                return None
            node = self._grants.get(node.parent) if node.parent else None
        return grant

    def exchange(
        self,
        subject_token: str,
        *,
        presenter: str,
        new_holder: str,
        operations: Optional[Iterable[str]] = None,
        max_amount: Optional[int] = None,
        ttl_seconds: Optional[int] = None,
        now: int,
    ) -> Grant:
        """Derive a narrower grant for a sub-agent (RFC 8693 token exchange)."""
        parent = self.active(subject_token, now)
        if parent is None:
            raise GrantError("subject token is not active")
        if presenter != parent.holder:
            raise GrantError("request not signed by the subject token holder")
        if parent.depth + 1 > MAX_DEPTH:
            raise GrantError("delegation chain too deep")

        ops = parent.operations if operations is None else _check_ops(operations)
        if not ops <= parent.operations:
            raise GrantError("requested operations exceed the subject token")

        limit = parent.max_amount if max_amount is None else max_amount
        if limit < 0 or limit > parent.max_amount:
            raise GrantError("requested max_amount exceeds the subject token")

        expires = parent.expires_at
        if ttl_seconds is not None:
            if ttl_seconds <= 0:
                raise GrantError("ttl_seconds must be positive")
            expires = min(expires, now + ttl_seconds)

        child = Grant(
            token=secrets.token_urlsafe(32),
            user=parent.user,
            holder=_check_key(new_holder),
            operations=ops,
            max_amount=limit,
            issued_at=now,
            expires_at=expires,
            parent=parent.token,
            depth=parent.depth + 1,
        )
        self._grants[child.token] = child
        return child

    def revoke(self, token: str) -> bool:
        """Revoke a grant (and, through `active`, all its descendants).

        Returns False for unknown tokens; RFC 7009 still answers 200 then.
        """
        grant = self._grants.get(token)
        if grant is None:
            return False
        grant.revoked = True
        return True

    def introspect(self, token: str, now: int) -> dict:
        """RFC 7662 response body."""
        grant = self.active(token, now)
        if grant is None:
            return {"active": False}
        return {
            "active": True,
            "token_type": "Bearer",
            "sub": grant.user,
            "scope": " ".join(sorted(grant.operations)),
            "iat": grant.issued_at,
            "exp": grant.expires_at,
            # RFC 7800-style confirmation: the key that must sign requests.
            "cnf": {"agent_key": grant.holder},
            # Extensions used by the gateway.
            "max_amount": grant.max_amount,
            "delegation_depth": grant.depth,
        }

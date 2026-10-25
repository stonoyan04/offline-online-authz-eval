"""Offline-verifiable delegation for AI agents, built on Biscuit tokens.

Model
-----
* The **issuer** (the user's Permission Manager) signs the authority block with
  its root key. The block names the first **holder** (the agent's public key),
  the operations it may perform, a spending limit, and an expiry.
* A holder can hand a narrower token to a **sub-agent** by appending a
  *third-party block* signed with its own key. The block names the next holder
  (`delegate(...)`) and may add checks (fewer operations, lower limit, earlier
  expiry). Checks in any block are always enforced, so attenuation can only
  narrow rights.
* The **verifier** (the service's gateway) needs only the issuer's public key.
  It walks the chain of delegation blocks, accepts a block only if it is
  signed by the current holder, and requires the request to be signed by the
  final holder (proof of possession, see `pop.py`).

Why the walk happens in Python, not Datalog
-------------------------------------------
A Datalog rule can only trust a block signed by a key written into the rule
text. Which keys are legitimate holders is only known after reading the chain,
so the verifier discovers them block by block and queries each delegation
block with `trusting {key}` for the current holder only. A delegation fact in
a first-party block, or in a block signed by any key other than the current
holder, is never trusted. This resolves the conflict between attenuation and
proof of possession noted in the design review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from biscuit_auth import (
    AuthorizationError,
    AuthorizerBuilder,
    Biscuit,
    BiscuitBuilder,
    BlockBuilder,
    KeyPair,
    PublicKey,
    Rule,
)

_OP_RE = re.compile(r"^[a-z][a-z0-9_:.-]{0,63}$")

# Wall-clock budget for Datalog evaluation per request. biscuit's default is
# 1 ms, which a short host stall exceeds on a valid token (seen once at 1500
# req/s). Facts and iterations keep biscuit's limits; they bound a costly
# attenuation block deterministically.
MAX_TIME = timedelta(milliseconds=10)
_LIMITS_HIT = "Reached Datalog execution limits"


def key_hex(public_key: PublicKey) -> str:
    """Hex encoding of a raw 32-byte Ed25519 public key."""
    return public_key.to_bytes().hex()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_ops(ops: Iterable[str]) -> set[str]:
    ops = set(ops)
    if not ops:
        raise ValueError("at least one operation is required")
    for op in ops:
        if not _OP_RE.match(op):
            raise ValueError(f"invalid operation name: {op!r}")
    return ops


# --------------------------------------------------------------------------
# Issuing and attenuating
# --------------------------------------------------------------------------


def issue(
    root: KeyPair,
    *,
    user: str,
    holder: PublicKey,
    operations: Iterable[str],
    max_amount: int,
    ttl: timedelta = timedelta(hours=1),
    now: Optional[datetime] = None,
) -> Biscuit:
    """Issue a root token that delegates `operations` from `user` to `holder`."""
    ops = _validate_ops(operations)
    if max_amount < 0:
        raise ValueError("max_amount must be non-negative")
    expires = (now or _now()) + ttl

    builder = BiscuitBuilder(
        """
        user({user});
        holder({holder});
        expires({expires});
        check if time($t), $t < {expires};
        check if amount($a), $a <= {max_amount};
        """,
        {
            "user": user,
            "holder": key_hex(holder),
            "expires": expires,
            "max_amount": max_amount,
        },
    )
    for op in sorted(ops):
        builder.add_code("right({op});", {"op": op})
    return builder.build(root.private_key)


def delegate(
    token: Biscuit,
    parent: KeyPair,
    child: PublicKey,
    *,
    operations: Optional[Iterable[str]] = None,
    max_amount: Optional[int] = None,
    ttl: Optional[timedelta] = None,
    now: Optional[datetime] = None,
) -> Biscuit:
    """Return a narrower token for `child`, signed by the current holder `parent`.

    Needs no server: the parent signs a third-party block locally.
    Restrictions are optional; with none, the child gets the parent's rights.
    """
    block = BlockBuilder("delegate({child});", {"child": key_hex(child)})
    if operations is not None:
        ops = _validate_ops(operations)
        block.add_code("check if operation($op), {ops}.contains($op);", {"ops": ops})
    if max_amount is not None:
        block.add_code("check if amount($a), $a <= {max};", {"max": max_amount})
    if ttl is not None:
        exp = (now or _now()) + ttl
        # The fact only lets the verifier report "expired" precisely;
        # the check is what enforces it.
        block.add_code("expires({exp}); check if time($t), $t < {exp};", {"exp": exp})

    request = token.third_party_request()
    signed = request.create_block(parent.private_key, block)
    return token.append_third_party(parent.public_key, signed)


# --------------------------------------------------------------------------
# Verifying
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    holder: Optional[str] = None  # hex key of the final holder, if resolved
    depth: int = 0  # number of delegation hops


def _single_key(facts: list, what: str) -> str:
    if len(facts) != 1:
        raise ValueError(f"expected exactly one {what} fact, found {len(facts)}")
    value = facts[0].terms[0]
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"malformed {what} key")
    return value


def _expiries(facts: list) -> list[datetime]:
    return [f.terms[0] for f in facts if isinstance(f.terms[0], datetime)]


def _resolve_holder(authorizer, token: Biscuit) -> tuple[str, int, Optional[datetime]]:
    """Walk the delegation chain.

    Returns (final holder hex, number of hops, earliest declared expiry).

    Only the authority block may name the first holder. Every later block that
    names a delegate must be a third-party block signed by the current holder
    and must name exactly one delegate. Any other block that tries to change
    the holder is rejected. Expiry facts are read only from the same trusted
    blocks; they serve to report "expired" precisely, while the Datalog checks
    enforce it.
    """
    # The authorizer trusts only the authority block by default.
    current = _single_key(authorizer.query(Rule("h($k) <- holder($k)")), "holder")
    expiries = _expiries(authorizer.query(Rule("e($t) <- expires($t)")))
    hops = 0

    for index in range(1, token.block_count()):
        external = token.block_external_key(index)
        source = token.block_source(index)
        names_delegate = "delegate(" in source

        if external is None:
            if names_delegate:
                raise ValueError(f"block {index}: delegation must be signed by the holder")
            continue  # plain first-party attenuation: its checks still apply

        if key_hex(external) != current:
            raise ValueError(f"block {index}: signed by a key that is not the current holder")
        expiries += _expiries(
            authorizer.query(
                Rule("e($t) <- expires($t) trusting {signer}", None, {"signer": external})
            )
        )
        if not names_delegate:
            continue  # holder added a restriction for itself; allowed

        delegates = authorizer.query(
            Rule("d($k) <- delegate($k) trusting {signer}", None, {"signer": external})
        )
        current = _single_key(delegates, "delegate")
        hops += 1

    return current, hops, min(expiries) if expiries else None


def verify(
    token_b64: str,
    root_public_key: PublicKey,
    *,
    presenter: str,
    operation: str,
    amount: int = 0,
    revoked: frozenset[str] | set[str] = frozenset(),
    now: Optional[datetime] = None,
    max_time: timedelta = MAX_TIME,
) -> Decision:
    """Decide a request locally, with no call to the authorization server.

    `presenter` is the hex public key that signed the HTTP request (already
    checked by `pop.verify_request`). `revoked` is the cached revocation list.
    """
    try:
        token = Biscuit.from_base64(token_b64, root_public_key)
    except Exception as exc:  # bad signature, bad encoding, wrong root key
        return Decision(False, f"invalid token: {type(exc).__name__}")

    if revoked and not revoked.isdisjoint(token.revocation_ids):
        return Decision(False, "token revoked")

    now = now or _now()
    builder = AuthorizerBuilder(
        """
        time({now});
        operation({operation});
        amount({amount});
        allow if operation($op), right($op);
        """,
        {"now": now, "operation": operation, "amount": amount},
    )
    limits = builder.limits()
    limits.max_time = max_time
    builder.set_limits(limits)
    try:
        authorizer = builder.build(token)
    except Exception as exc:
        return Decision(False, f"authorizer error: {type(exc).__name__}")

    try:
        holder, hops, expires = _resolve_holder(authorizer, token)
    except ValueError as exc:
        return Decision(False, f"bad delegation chain: {exc}")
    except AuthorizationError as exc:  # run limits also cover queries
        if _LIMITS_HIT in str(exc):
            return Decision(False, "authorizer limits exceeded")
        raise

    if presenter != holder:
        return Decision(False, "request not signed by the token holder", holder, hops)

    if expires is not None and now >= expires:
        return Decision(False, "token expired", holder, hops)

    try:
        authorizer.authorize()
    except AuthorizationError as exc:
        if _LIMITS_HIT in str(exc):
            return Decision(False, "authorizer limits exceeded", holder, hops)
        return Decision(False, "policy check failed", holder, hops)

    return Decision(True, "ok", holder, hops)

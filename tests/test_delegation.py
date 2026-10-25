"""Security tests for the delegation spike.

Each test is one attack or misuse from the threat model; the expected outcome
is in the test name.
"""

from datetime import datetime, timedelta, timezone

import pytest
from biscuit_auth import BlockBuilder, KeyPair

from agentauthz.delegation import delegate, issue, key_hex, verify
from agentauthz.pop import ReplayCache, sign_request, verify_request

NOW = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def keys():
    return {name: KeyPair() for name in ("root", "agent", "sub", "subsub", "thief", "other_root")}


@pytest.fixture
def root_token(keys):
    return issue(
        keys["root"],
        user="alice",
        holder=keys["agent"].public_key,
        operations=["search", "buy"],
        max_amount=300,
        ttl=timedelta(hours=1),
        now=NOW,
    )


def check(token, keys, presenter, operation, amount=0, **kw):
    return verify(
        token.to_base64(),
        keys["root"].public_key,
        presenter=key_hex(keys[presenter].public_key),
        operation=operation,
        amount=amount,
        now=kw.pop("now", NOW),
        **kw,
    )


# ---- root token ----------------------------------------------------------


def test_holder_within_limits_allowed(root_token, keys):
    d = check(root_token, keys, "agent", "buy", 250)
    assert d.allowed, d.reason
    assert d.depth == 0


def test_over_spending_limit_denied(root_token, keys):
    assert not check(root_token, keys, "agent", "buy", 301).allowed


def test_operation_not_granted_denied(root_token, keys):
    assert not check(root_token, keys, "agent", "cancel").allowed


def test_expired_token_denied(root_token, keys):
    later = NOW + timedelta(hours=2)
    assert not check(root_token, keys, "agent", "search", now=later).allowed


def test_stolen_token_without_holder_key_denied(root_token, keys):
    d = check(root_token, keys, "thief", "search")
    assert not d.allowed
    assert "holder" in d.reason


def test_token_from_other_issuer_denied(keys):
    forged = issue(
        keys["other_root"],
        user="alice",
        holder=keys["agent"].public_key,
        operations=["buy"],
        max_amount=10_000,
        now=NOW,
    )
    d = check(forged, keys, "agent", "buy", 5000)
    assert not d.allowed
    assert "invalid token" in d.reason


def test_tampered_token_denied(root_token, keys):
    raw = bytearray(root_token.to_bytes())
    raw[len(raw) // 2] ^= 0xFF
    import base64

    tampered = base64.urlsafe_b64encode(bytes(raw)).decode()
    d = verify(
        tampered,
        keys["root"].public_key,
        presenter=key_hex(keys["agent"].public_key),
        operation="search",
        now=NOW,
    )
    assert not d.allowed


def test_revoked_token_denied(root_token, keys):
    revoked = {root_token.revocation_ids[0]}
    d = check(root_token, keys, "agent", "search", revoked=revoked)
    assert not d.allowed
    assert d.reason == "token revoked"


# ---- delegation to sub-agents ---------------------------------------------


@pytest.fixture
def sub_token(root_token, keys):
    return delegate(
        root_token,
        keys["agent"],
        keys["sub"].public_key,
        operations=["search"],
        now=NOW,
    )


def test_sub_agent_within_narrowed_rights_allowed(sub_token, keys):
    d = check(sub_token, keys, "sub", "search")
    assert d.allowed, d.reason
    assert d.depth == 1
    assert d.holder == key_hex(keys["sub"].public_key)


def test_sub_agent_cannot_use_removed_operation(sub_token, keys):
    assert not check(sub_token, keys, "sub", "buy", 10).allowed


def test_parent_cannot_present_sub_agent_token(sub_token, keys):
    # The token now belongs to the sub-agent only.
    assert not check(sub_token, keys, "agent", "search").allowed


def test_thief_cannot_use_sub_agent_token(sub_token, keys):
    assert not check(sub_token, keys, "thief", "search").allowed


def test_sub_agent_cannot_widen_with_first_party_block(sub_token, keys):
    widened = sub_token.append(BlockBuilder('right("cancel"); right("buy");'))
    assert not check(widened, keys, "sub", "cancel").allowed
    assert not check(widened, keys, "sub", "buy", 10).allowed


def test_thief_cannot_redirect_holder_with_first_party_block(root_token, keys):
    hijacked = root_token.append(
        BlockBuilder("delegate({k});", {"k": key_hex(keys["thief"].public_key)})
    )
    d = check(hijacked, keys, "thief", "search")
    assert not d.allowed
    assert "chain" in d.reason


def test_thief_cannot_redirect_holder_with_own_signed_block(root_token, keys):
    # Thief signs a delegation with its own key: not the current holder.
    hijacked = delegate(root_token, keys["thief"], keys["thief"].public_key)
    d = check(hijacked, keys, "thief", "search")
    assert not d.allowed
    assert "not the current holder" in d.reason


def test_two_hop_delegation_keeps_all_restrictions(sub_token, keys):
    deeper = delegate(sub_token, keys["sub"], keys["subsub"].public_key, max_amount=50, now=NOW)
    ok = check(deeper, keys, "subsub", "search")
    assert ok.allowed, ok.reason
    assert ok.depth == 2
    # Restriction from the first hop (search only) still applies.
    assert not check(deeper, keys, "subsub", "buy", 10).allowed


def test_sub_agent_shorter_expiry_enforced(root_token, keys):
    short = delegate(
        root_token, keys["agent"], keys["sub"].public_key, ttl=timedelta(minutes=5), now=NOW
    )
    assert check(short, keys, "sub", "search", now=NOW + timedelta(minutes=1)).allowed
    assert not check(short, keys, "sub", "search", now=NOW + timedelta(minutes=10)).allowed


def test_sub_agent_lower_limit_enforced(root_token, keys):
    low = delegate(root_token, keys["agent"], keys["sub"].public_key, max_amount=100, now=NOW)
    assert check(low, keys, "sub", "buy", 100).allowed
    assert not check(low, keys, "sub", "buy", 101).allowed


def test_revoking_parent_token_revokes_delegated_token(root_token, sub_token, keys):
    revoked = {root_token.revocation_ids[0]}
    assert not check(sub_token, keys, "sub", "search", revoked=revoked).allowed


# ---- proof of possession ----------------------------------------------------


def test_signed_request_accepted(keys):
    cache = ReplayCache()
    req = sign_request(keys["agent"], "POST", "/buy", b'{"amount":250}', created=1000)
    assert verify_request(req, cache, now=1005) == key_hex(keys["agent"].public_key)


def test_replayed_request_rejected(keys):
    cache = ReplayCache()
    req = sign_request(keys["agent"], "POST", "/buy", b"{}", created=1000)
    assert verify_request(req, cache, now=1001)
    assert verify_request(req, cache, now=1002) is None


def test_old_request_rejected(keys):
    req = sign_request(keys["agent"], "POST", "/buy", b"{}", created=1000)
    assert verify_request(req, ReplayCache(), now=1100) is None


def test_modified_body_rejected(keys):
    req = sign_request(keys["agent"], "POST", "/buy", b'{"amount":250}', created=1000)
    from dataclasses import replace

    tampered = replace(req, body=b'{"amount":2500}')
    assert verify_request(tampered, ReplayCache(), now=1000) is None


def test_end_to_end_signed_request_with_delegated_token(sub_token, keys):
    cache = ReplayCache()
    req = sign_request(keys["sub"], "GET", "/flights?to=CDG", created=1000)
    presenter = verify_request(req, cache, now=1000)
    assert presenter is not None
    d = verify(
        sub_token.to_base64(),
        keys["root"].public_key,
        presenter=presenter,
        operation="search",
        now=NOW,
    )
    assert d.allowed, d.reason


def test_expired_root_reported_as_expired(root_token, keys):
    d = check(root_token, keys, "agent", "search", now=NOW + timedelta(hours=2))
    assert d.reason == "token expired"


def test_expired_delegation_reported_as_expired(root_token, keys):
    short = delegate(
        root_token, keys["agent"], keys["sub"].public_key, ttl=timedelta(minutes=5), now=NOW
    )
    d = check(short, keys, "sub", "search", now=NOW + timedelta(minutes=10))
    assert d.reason == "token expired"


def test_untrusted_expiry_fact_cannot_extend_lifetime(root_token, keys):
    # A first-party block declaring a later expiry changes nothing: it is not
    # read for classification, and the authority block's check still applies.
    later = root_token.append(
        BlockBuilder("expires({t});", {"t": NOW + timedelta(days=365)})
    )
    d = check(later, keys, "agent", "search", now=NOW + timedelta(hours=2))
    assert not d.allowed
    assert d.reason == "token expired"


# ---- Datalog run limits ----------------------------------------------------
# Found at 1500 req/s: a host stall pushed one evaluation past biscuit's
# default 1 ms limit, and the timeout came back as a policy refusal (403).


def test_run_limit_while_resolving_holder_is_reported_as_limit(root_token, keys):
    d = check(root_token, keys, "agent", "buy", 250, max_time=timedelta(0))
    assert not d.allowed
    assert d.reason == "authorizer limits exceeded"


def test_run_limit_during_authorize_is_not_a_policy_refusal(root_token, keys, monkeypatch):
    from agentauthz import delegation

    agent = key_hex(keys["agent"].public_key)
    monkeypatch.setattr(delegation, "_resolve_holder", lambda authorizer, token: (agent, 0, None))
    d = check(root_token, keys, "agent", "buy", 250, max_time=timedelta(0))
    assert not d.allowed
    assert d.reason == "authorizer limits exceeded"

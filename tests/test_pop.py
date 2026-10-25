"""Proof-of-possession over HTTP headers."""

from dataclasses import replace

from biscuit_auth import KeyPair
from httpx import Headers

from agentauthz.pop import (
    ReplayCache,
    bearer_token,
    from_http,
    sign_request,
    to_headers,
    verify_request,
)


def roundtrip(req, *, method=None, path=None, body=None, headers=None):
    hdrs = Headers(headers if headers is not None else to_headers(req))
    return from_http(method or req.method, path or req.path, req.body if body is None else body, hdrs)


def test_headers_roundtrip_verifies():
    agent = KeyPair()
    req = sign_request(agent, "POST", "/buy?x=1", b'{"a":1}', token="tok123", created=1000)
    rebuilt = roundtrip(req)
    assert rebuilt == req
    assert verify_request(rebuilt, ReplayCache(), now=1000) == req.key


def test_signature_bound_to_token():
    agent = KeyPair()
    req = sign_request(agent, "GET", "/flights", token="token-A", created=1000)
    headers = to_headers(req) | {"Authorization": "Bearer token-B"}
    swapped = roundtrip(req, headers=headers)
    assert swapped.token == "token-B"
    assert verify_request(swapped, ReplayCache(), now=1000) is None


def test_signature_bound_to_query_string():
    agent = KeyPair()
    req = sign_request(agent, "GET", "/flights?to=CDG", token="t", created=1000)
    moved = roundtrip(req, path="/flights?to=JFK")
    assert verify_request(moved, ReplayCache(), now=1000) is None


def test_signature_bound_to_method():
    agent = KeyPair()
    req = sign_request(agent, "GET", "/orders/1", token="t", created=1000)
    assert verify_request(roundtrip(req, method="DELETE"), ReplayCache(), now=1000) is None


def test_missing_headers_rejected():
    agent = KeyPair()
    req = sign_request(agent, "GET", "/", token="t", created=1000)
    headers = to_headers(req)
    del headers["Agent-Signature"]
    assert roundtrip(req, headers=headers) is None


def test_non_numeric_created_rejected():
    agent = KeyPair()
    req = sign_request(agent, "GET", "/", token="t", created=1000)
    headers = to_headers(req) | {"Agent-Created": "soon"}
    assert roundtrip(req, headers=headers) is None


def test_garbage_signature_and_key_rejected():
    agent = KeyPair()
    req = sign_request(agent, "GET", "/", created=1000)
    assert verify_request(replace(req, signature="!!!"), ReplayCache(), now=1000) is None
    assert verify_request(replace(req, key="zz"), ReplayCache(), now=1000) is None


def test_signature_by_other_key_rejected():
    agent, thief = KeyPair(), KeyPair()
    req = sign_request(thief, "GET", "/", created=1000)
    claimed = replace(req, key=agent.public_key.to_bytes().hex())
    assert verify_request(claimed, ReplayCache(), now=1000) is None


def test_replay_cache_fails_closed_when_full():
    cache = ReplayCache(max_entries=2)
    assert cache.check_and_add("k", "n1", 100)
    assert cache.check_and_add("k", "n2", 100)
    assert not cache.check_and_add("k", "n3", 100)  # full of live entries
    assert cache.check_and_add("k", "n4", 200)  # old entries expired


def test_bearer_token_parsing():
    assert bearer_token(Headers({"Authorization": "Bearer abc"})) == "abc"
    assert bearer_token(Headers({"Authorization": "bearer  abc "})) == "abc"
    assert bearer_token(Headers({"Authorization": "Basic abc"})) is None
    assert bearer_token(Headers({})) is None

"""Authorization server: issuing, introspection, exchange, revocation, faults."""

import base64
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

import pytest
from biscuit_auth import Biscuit, KeyPair
from fastapi.testclient import TestClient

from agentauthz import delegation
from agentauthz.authz_server import Settings, State, create_app
from agentauthz.authz_server.app import TOKEN_EXCHANGE
from agentauthz.authz_server.faults import FaultInjector
from agentauthz.keys import public_hex, public_key_from_hex
from agentauthz.pop import sign_request, to_headers
from agentauthz.revocation import verify_revocation_list

ADMIN = "admin-secret"
CLIENT = ("gateway", "gw-secret")
T0 = 1_760_000_000


class Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def env():
    clock = Clock(T0)
    fault_clock = Clock(0.0)
    root = KeyPair()
    settings = Settings(root=root, admin_token=ADMIN, clients={CLIENT[0]: CLIENT[1]}, clock=clock)
    state = State(settings, faults=FaultInjector(clock=fault_clock))
    client = TestClient(create_app(state=state))
    return {"client": client, "clock": clock, "fault_clock": fault_clock, "root": root, "state": state}


def admin_headers():
    return {"Authorization": f"Bearer {ADMIN}"}


def basic_headers(cid=CLIENT[0], secret=CLIENT[1]):
    raw = base64.b64encode(f"{cid}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {raw}"}


def grant(client, holder: KeyPair, fmt="opaque", **kw):
    body = {
        "user": "alice",
        "holder_key": public_hex(holder),
        "operations": kw.pop("operations", ["search", "buy"]),
        "max_amount": kw.pop("max_amount", 300),
        "ttl_seconds": kw.pop("ttl_seconds", 3600),
        "format": fmt,
    }
    r = client.post("/admin/grants", json=body, headers=admin_headers())
    assert r.status_code == 200, r.text
    return r.json()


def introspect(client, token, headers=None):
    return client.post(
        "/introspect",
        content=urlencode({"token": token}),
        headers={"Content-Type": "application/x-www-form-urlencoded", **(headers or basic_headers())},
    )


def exchange(client, signer: KeyPair, subject: str, actor: KeyPair, now: int, **params):
    form = {"grant_type": TOKEN_EXCHANGE, "subject_token": subject, "actor_key": public_hex(actor)}
    form.update({k: str(v) for k, v in params.items()})
    body = urlencode(form).encode()
    signed = sign_request(signer, "POST", "/token/exchange", body, created=now)
    headers = to_headers(signed) | {"Content-Type": "application/x-www-form-urlencoded"}
    return client.post("/token/exchange", content=body, headers=headers)


# ---- discovery, admin auth --------------------------------------------------


def test_discovery_publishes_issuer_key(env):
    r = env["client"].get("/.well-known/agentauthz")
    assert r.json()["issuer_public_key"] == public_hex(env["root"])


def test_grants_require_admin(env):
    r = env["client"].post("/admin/grants", json={})
    assert r.status_code == 401
    r = env["client"].post("/admin/grants", json={}, headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_invalid_grant_requests_rejected(env):
    c = env["client"]
    base = {"user": "alice", "operations": ["buy"], "max_amount": 1}
    for fmt in ("opaque", "biscuit"):
        r = c.post("/admin/grants", json=base | {"holder_key": "xyz", "format": fmt}, headers=admin_headers())
        assert r.status_code == 400, (fmt, r.text)
    r = c.post(
        "/admin/grants",
        json=base | {"holder_key": public_hex(KeyPair()), "operations": ["BAD OP"]},
        headers=admin_headers(),
    )
    assert r.status_code == 400


# ---- introspection ------------------------------------------------------------


def test_introspection_returns_grant(env):
    agent = KeyPair()
    token = grant(env["client"], agent)["token"]
    body = introspect(env["client"], token).json()
    assert body["active"] is True
    assert body["sub"] == "alice"
    assert body["scope"] == "buy search"
    assert body["cnf"] == {"agent_key": public_hex(agent)}
    assert body["max_amount"] == 300
    assert body["exp"] == T0 + 3600
    assert body["delegation_depth"] == 0


def test_introspection_requires_client_auth(env):
    token = grant(env["client"], KeyPair())["token"]
    assert introspect(env["client"], token, headers={"Authorization": "Bearer x"}).status_code == 401
    assert introspect(env["client"], token, headers=basic_headers(secret="wrong")).status_code == 401
    assert introspect(env["client"], token, headers=basic_headers(cid="other")).status_code == 401
    assert introspect(env["client"], token, headers={"Authorization": "Basic !!!"}).status_code == 401


def test_unknown_and_expired_tokens_inactive(env):
    token = grant(env["client"], KeyPair(), ttl_seconds=60)["token"]
    assert introspect(env["client"], "nope").json() == {"active": False}
    env["clock"].t = T0 + 61
    assert introspect(env["client"], token).json() == {"active": False}


def test_missing_token_parameter(env):
    r = env["client"].post("/introspect", content="", headers=basic_headers())
    assert r.status_code == 400


# ---- token exchange -------------------------------------------------------------


def test_exchange_narrows_for_sub_agent(env):
    c = env["client"]
    agent, sub = KeyPair(), KeyPair()
    parent = grant(c, agent)["token"]
    r = exchange(c, agent, parent, sub, T0, scope="search", max_amount=50, ttl_seconds=600)
    assert r.status_code == 200, r.text
    child = r.json()["access_token"]
    body = introspect(c, child).json()
    assert body["active"] and body["scope"] == "search"
    assert body["cnf"]["agent_key"] == public_hex(sub)
    assert body["max_amount"] == 50
    assert body["exp"] == T0 + 600
    assert body["delegation_depth"] == 1


def test_exchange_cannot_widen(env):
    c = env["client"]
    agent, sub = KeyPair(), KeyPair()
    parent = grant(c, agent, operations=["search"], max_amount=100)["token"]
    assert exchange(c, agent, parent, sub, T0, scope="search buy").status_code == 400
    assert exchange(c, agent, parent, sub, T0, max_amount=101).status_code == 400


def test_exchange_ttl_cannot_outlive_parent(env):
    c = env["client"]
    agent, sub = KeyPair(), KeyPair()
    parent = grant(c, agent, ttl_seconds=100)["token"]
    child = exchange(c, agent, parent, sub, T0, ttl_seconds=10_000).json()["access_token"]
    assert introspect(c, child).json()["exp"] == T0 + 100


def test_exchange_requires_holder_signature(env):
    c = env["client"]
    agent, sub, thief = KeyPair(), KeyPair(), KeyPair()
    parent = grant(c, agent)["token"]
    r = exchange(c, thief, parent, thief, T0)
    assert r.status_code == 400
    assert "holder" in r.json()["error_description"]
    unsigned = c.post(
        "/token/exchange",
        content=urlencode({"grant_type": TOKEN_EXCHANGE, "subject_token": parent, "actor_key": public_hex(sub)}),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert unsigned.status_code == 401


def test_exchange_replay_rejected(env):
    c = env["client"]
    agent, sub = KeyPair(), KeyPair()
    parent = grant(c, agent)["token"]
    form = {"grant_type": TOKEN_EXCHANGE, "subject_token": parent, "actor_key": public_hex(sub)}
    body = urlencode(form).encode()
    headers = to_headers(sign_request(agent, "POST", "/token/exchange", body, created=T0))
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    assert c.post("/token/exchange", content=body, headers=headers).status_code == 200
    assert c.post("/token/exchange", content=body, headers=headers).status_code == 401


def test_exchange_wrong_grant_type(env):
    c = env["client"]
    agent, sub = KeyPair(), KeyPair()
    parent = grant(c, agent)["token"]
    r = exchange(c, agent, parent, sub, T0, grant_type="client_credentials")
    assert r.status_code == 400
    assert r.json()["error"] == "unsupported_grant_type"


# ---- revocation ----------------------------------------------------------------


def revoke(client, token, headers=None):
    return client.post(
        "/revoke",
        content=urlencode({"token": token}),
        headers={"Content-Type": "application/x-www-form-urlencoded", **(headers or admin_headers())},
    )


def test_revoking_parent_deactivates_children(env):
    c = env["client"]
    agent, sub = KeyPair(), KeyPair()
    parent = grant(c, agent)["token"]
    child = exchange(c, agent, parent, sub, T0).json()["access_token"]
    assert revoke(c, parent).status_code == 200
    assert introspect(c, parent).json() == {"active": False}
    assert introspect(c, child).json() == {"active": False}


def test_revoking_child_keeps_parent(env):
    c = env["client"]
    agent, sub = KeyPair(), KeyPair()
    parent = grant(c, agent)["token"]
    child = exchange(c, agent, parent, sub, T0).json()["access_token"]
    revoke(c, child)
    assert introspect(c, parent).json()["active"] is True
    assert introspect(c, child).json() == {"active": False}


def test_revoke_requires_admin_and_accepts_unknown(env):
    c = env["client"]
    assert revoke(c, "x", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert revoke(c, "unknown-token").status_code == 200


def test_biscuit_grant_verifies_offline(env):
    c = env["client"]
    agent = KeyPair()
    issued = grant(c, agent, fmt="biscuit")
    issuer = public_key_from_hex(c.get("/.well-known/agentauthz").json()["issuer_public_key"])
    d = delegation.verify(
        issued["token"],
        issuer,
        presenter=public_hex(agent),
        operation="buy",
        amount=200,
        now=datetime.fromtimestamp(T0 + 10, timezone.utc),
    )
    assert d.allowed, d.reason


def test_biscuit_revocation_list(env):
    c = env["client"]
    agent, sub = KeyPair(), KeyPair()
    issued = grant(c, agent, fmt="biscuit")
    issuer = env["root"].public_key
    parent = Biscuit.from_base64(issued["token"], issuer)
    child = delegation.delegate(parent, agent, sub.public_key)

    empty = verify_revocation_list(c.get("/revocations").json(), issuer)
    assert empty is not None and empty.revoked == frozenset() and empty.seq == 0

    # Revoking the child adds only the child's last block.
    r = revoke(c, child.to_base64()).json()
    assert r["revoked"] == "biscuit"
    lst = verify_revocation_list(c.get("/revocations").json(), issuer)
    assert lst.seq == 1
    assert not lst.revoked.isdisjoint(child.revocation_ids)
    assert lst.revoked.isdisjoint(parent.revocation_ids)

    # Revoking the parent revokes the child too.
    revoke(c, parent.to_base64())
    lst = verify_revocation_list(c.get("/revocations").json(), issuer)
    assert not lst.revoked.isdisjoint(parent.revocation_ids)
    assert lst.seq == 2


def test_revocation_list_tamper_detected(env):
    c = env["client"]
    issuer = env["root"].public_key
    doc = c.get("/revocations").json()
    doc["payload"]["revoked"] = []
    doc["payload"]["seq"] = 99
    assert verify_revocation_list(doc, issuer) is None
    assert verify_revocation_list(c.get("/revocations").json(), KeyPair().public_key) is None
    assert verify_revocation_list({"nope": 1}, issuer) is None


# ---- fault injection ------------------------------------------------------------


def set_fault(client, **cfg):
    r = client.put("/admin/fault", json=cfg, headers=admin_headers())
    assert r.status_code == 200, r.text
    return r.json()


def test_error_fault_hits_only_dependency_endpoints(env):
    c = env["client"]
    token = grant(c, KeyPair())["token"]
    set_fault(c, mode="error")
    assert introspect(c, token).status_code == 503
    assert c.get("/revocations").status_code == 503
    assert c.get("/healthz").status_code == 200
    assert c.get("/.well-known/agentauthz").status_code == 200
    assert grant(c, KeyPair())["token"]  # admin still works
    set_fault(c, mode="none")
    assert introspect(c, token).json()["active"] is True


def test_fault_does_not_bypass_client_auth(env):
    c = env["client"]
    set_fault(c, mode="error")
    assert introspect(c, "t", headers=basic_headers(secret="bad")).status_code == 401


def test_custom_error_status(env):
    c = env["client"]
    set_fault(c, mode="error", error_status=500)
    assert introspect(c, "t").status_code == 500


def test_slow_fault_adds_latency(env):
    c = env["client"]
    token = grant(c, KeyPair())["token"]
    set_fault(c, mode="slow", delay_ms=150)
    start = time.perf_counter()
    assert introspect(c, token).json()["active"] is True
    assert time.perf_counter() - start >= 0.15


def test_hang_fault_then_503(env):
    c = env["client"]
    set_fault(c, mode="hang", hang_seconds=0.1)
    start = time.perf_counter()
    assert introspect(c, "t").status_code == 503
    assert time.perf_counter() - start >= 0.1


def test_flapping_alternates(env):
    c = env["client"]
    token = grant(c, KeyPair())["token"]
    fc = env["fault_clock"]
    fc.t = 100.0
    set_fault(c, mode="flapping", period_seconds=10, down_fraction=0.3)
    seen = []
    for offset in (0, 2.9, 3.0, 9.9, 10.0, 12.5, 13.5):
        fc.t = 100.0 + offset
        seen.append(introspect(c, token).status_code)
    assert seen == [503, 503, 200, 200, 503, 503, 200]


def test_fault_counters_and_validation(env):
    c = env["client"]
    set_fault(c, mode="error")
    introspect(c, "t")
    state = c.get("/admin/fault", headers=admin_headers()).json()
    assert state["counters"]["failed"] >= 1
    r = c.put("/admin/fault", json={"mode": "explode"}, headers=admin_headers())
    assert r.status_code == 422
    assert c.put("/admin/fault", json={"mode": "none"}).status_code == 401

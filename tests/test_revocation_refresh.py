"""OfflineAuthorizer.refresh: only genuine, newer revocation lists are accepted."""

import asyncio

import httpx
from biscuit_auth import KeyPair

from agentauthz.gateway import OfflineAuthorizer
from agentauthz.revocation import sign_revocation_list

ISSUER = KeyPair()


def authorizer_serving(*documents):
    """An authorizer whose revocation endpoint returns `documents` in order."""
    queue = list(documents)

    def handler(request: httpx.Request) -> httpx.Response:
        doc = queue.pop(0)
        if isinstance(doc, int):
            return httpx.Response(doc)
        return httpx.Response(200, json=doc)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return OfflineAuthorizer(
        ISSUER.public_key, revocations_url="http://issuer/revocations", http=http, clock=lambda: 1000
    )


def run(coro):
    return asyncio.run(coro)


def genuine(ids, seq, at=1000):
    return sign_revocation_list(ISSUER, ids, seq=seq, issued_at=at)


def test_newer_list_replaces_older():
    a = authorizer_serving(genuine(["a"], 1), genuine(["a", "b"], 2))
    assert run(a.refresh()) and a.revoked == {"a"}
    assert run(a.refresh()) and a.revoked == {"a", "b"}


def test_forged_list_rejected_and_current_kept():
    forged = sign_revocation_list(KeyPair(), [], seq=99, issued_at=1000)
    a = authorizer_serving(genuine(["a"], 1), forged)
    assert run(a.refresh())
    assert run(a.refresh()) is False
    assert a.revoked == {"a"}
    assert a.refresh_failed == 1


def test_tampered_list_rejected():
    doc = genuine(["a"], 1)
    doc["payload"]["revoked"] = []
    a = authorizer_serving(doc)
    assert run(a.refresh()) is False
    assert a.revocations is None


def test_rollback_to_older_list_ignored():
    a = authorizer_serving(genuine(["a", "b"], 5), genuine([], 3))
    assert run(a.refresh())
    assert run(a.refresh())  # fetched fine, but not applied
    assert a.revoked == {"a", "b"}
    assert a.revocations.seq == 5


def test_server_error_keeps_last_list():
    a = authorizer_serving(genuine(["a"], 1), 503)
    assert run(a.refresh())
    assert run(a.refresh()) is False
    assert a.revoked == {"a"}


def test_staleness_from_issue_time():
    a = authorizer_serving(genuine([], 1, at=990))
    assert a.staleness() is None
    run(a.refresh())
    assert a.staleness() == 10

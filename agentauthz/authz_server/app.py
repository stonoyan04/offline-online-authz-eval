"""Authorization server: the online baseline, plus the issuer for offline tokens.

One process plays both roles the experiments need:

* **Online mode** (baseline). Issues opaque tokens and answers RFC 7662
  introspection for every request the gateway sees. Sub-agent delegation goes
  through an RFC 8693-style token exchange. If this server is slow or down,
  online gateways are slow or down.
* **Offline mode.** Issues Biscuit tokens signed with the root key and
  publishes a signed revocation list. Gateways verify tokens locally and only
  refresh the list now and then, so they keep working when this server fails.

Fault injection (`faults.py`) affects exactly the endpoints gateways depend on:
`/introspect`, `/token/exchange` and `/revocations`.

Run:  python -m agentauthz.authz_server --port 8001
"""

from __future__ import annotations

import base64
import hmac
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Literal, Optional
from urllib.parse import parse_qs

from biscuit_auth import Biscuit, KeyPair
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from agentauthz import delegation
from agentauthz.authz_server.faults import FaultConfig, FaultInjector
from agentauthz.authz_server.store import GrantError, GrantStore
from agentauthz.keys import keypair_from_hex, public_hex, public_key_from_hex
from agentauthz.pop import ReplayCache, from_http, verify_request
from agentauthz.revocation import sign_revocation_list

log = logging.getLogger("agentauthz.authz_server")

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------


@dataclass
class Settings:
    root: KeyPair
    admin_token: str
    clients: dict[str, str]  # client_id -> secret, for introspection
    clock: Callable[[], float] = time.time

    @classmethod
    def from_env(cls) -> "Settings":
        """Read settings from environment variables.

        AUTHZ_ROOT_KEY      hex Ed25519 private key (generated if unset)
        AUTHZ_ADMIN_TOKEN   bearer token for admin endpoints (generated if unset)
        AUTHZ_CLIENTS       "id:secret,id2:secret2" for introspection clients
        """
        root_hex = os.environ.get("AUTHZ_ROOT_KEY")
        root = keypair_from_hex(root_hex) if root_hex else KeyPair()
        admin = os.environ.get("AUTHZ_ADMIN_TOKEN") or secrets.token_urlsafe(24)
        clients: dict[str, str] = {}
        for pair in filter(None, os.environ.get("AUTHZ_CLIENTS", "").split(",")):
            cid, _, secret = pair.partition(":")
            if not cid or not secret:
                raise ValueError("AUTHZ_CLIENTS must look like id:secret,id2:secret2")
            clients[cid.strip()] = secret.strip()
        if not root_hex:
            log.warning("AUTHZ_ROOT_KEY not set; generated issuer key %s", public_hex(root))
        if not os.environ.get("AUTHZ_ADMIN_TOKEN"):
            log.warning("AUTHZ_ADMIN_TOKEN not set; generated admin token %s", admin)
        if not clients:
            log.warning("AUTHZ_CLIENTS not set; introspection will reject every client")
        return cls(root=root, admin_token=admin, clients=clients)


@dataclass
class State:
    settings: Settings
    store: GrantStore = field(default_factory=GrantStore)
    faults: FaultInjector = field(default_factory=FaultInjector)
    replay: ReplayCache = field(default_factory=ReplayCache)
    revoked_ids: set[str] = field(default_factory=set)
    revocation_seq: int = 0

    def now(self) -> int:
        return int(self.settings.clock())


# --------------------------------------------------------------------------
# Request models and helpers
# --------------------------------------------------------------------------


class GrantRequest(BaseModel):
    user: str = Field(min_length=1, max_length=128)
    holder_key: str
    operations: list[str] = Field(min_length=1)
    max_amount: int = Field(ge=0)
    ttl_seconds: int = Field(3600, gt=0, le=30 * 86400)
    format: Literal["opaque", "biscuit"] = "opaque"


def oauth_error(status: int, error: str, description: str = "") -> JSONResponse:
    body = {"error": error}
    if description:
        body["error_description"] = description
    return JSONResponse(body, status_code=status)


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


async def _form(request: Request) -> dict[str, str]:
    """Parse an application/x-www-form-urlencoded body (first value per key)."""
    raw = (await request.body()).decode("utf-8", errors="replace")
    return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}


def _path_with_query(request: Request) -> str:
    query = request.url.query
    return request.url.path + (f"?{query}" if query else "")


# --------------------------------------------------------------------------
# App
# --------------------------------------------------------------------------


def create_app(settings: Optional[Settings] = None, *, state: Optional[State] = None) -> FastAPI:
    state = state or State(settings or Settings.from_env())
    app = FastAPI(title="agentauthz authorization server", version="0.1.0")
    app.state.authz = state

    def require_admin(request: Request) -> None:
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not _same(token.strip(), state.settings.admin_token):
            raise _Unauthorized()

    def require_client(request: Request) -> None:
        scheme, _, value = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "basic":
            raise _Unauthorized(basic=True)
        try:
            cid, _, secret = base64.b64decode(value.strip(), validate=True).decode().partition(":")
        except (ValueError, UnicodeDecodeError):
            raise _Unauthorized(basic=True)
        expected = state.settings.clients.get(cid)
        if expected is None or not _same(secret, expected):
            raise _Unauthorized(basic=True)

    async def fault_gate() -> None:
        outcome = await state.faults.apply()
        if outcome.fail_status is not None:
            raise _Unavailable(outcome.fail_status)

    @app.exception_handler(_Unauthorized)
    async def _unauthorized(_: Request, exc: "_Unauthorized") -> JSONResponse:
        resp = oauth_error(401, "invalid_client" if exc.basic else "invalid_token")
        resp.headers["WWW-Authenticate"] = "Basic" if exc.basic else "Bearer"
        return resp

    @app.exception_handler(_Unavailable)
    async def _unavailable(_: Request, exc: "_Unavailable") -> JSONResponse:
        return oauth_error(exc.status, "temporarily_unavailable", "fault injected")

    # ---- discovery and health (never faulted) ------------------------------

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"ok": True}

    @app.get("/.well-known/agentauthz")
    async def discovery() -> dict:
        return {
            "issuer_public_key": public_hex(state.settings.root),
            "introspection_endpoint": "/introspect",
            "revocation_endpoint": "/revoke",
            "token_exchange_endpoint": "/token/exchange",
            "revocation_list": "/revocations",
        }

    # ---- issuing (admin; stands in for the user's Permission Manager) ------

    @app.post("/admin/grants", dependencies=[Depends(require_admin)])
    async def create_grant(body: GrantRequest) -> JSONResponse:
        now = state.now()
        if body.format == "opaque":
            try:
                grant = state.store.issue(
                    user=body.user,
                    holder=body.holder_key,
                    operations=body.operations,
                    max_amount=body.max_amount,
                    ttl_seconds=body.ttl_seconds,
                    now=now,
                )
            except GrantError as exc:
                return oauth_error(400, "invalid_request", str(exc))
            return JSONResponse(
                {"token": grant.token, "format": "opaque", "expires_at": grant.expires_at}
            )

        try:
            holder = public_key_from_hex(body.holder_key)
            token = delegation.issue(
                state.settings.root,
                user=body.user,
                holder=holder,
                operations=body.operations,
                max_amount=body.max_amount,
                ttl=timedelta(seconds=body.ttl_seconds),
                now=datetime.fromtimestamp(now, timezone.utc),
            )
        except ValueError as exc:
            return oauth_error(400, "invalid_request", str(exc))
        return JSONResponse(
            {
                "token": token.to_base64(),
                "format": "biscuit",
                "expires_at": now + body.ttl_seconds,
                "revocation_ids": token.revocation_ids,
            }
        )

    # ---- online baseline ---------------------------------------------------

    @app.post("/introspect", dependencies=[Depends(require_client), Depends(fault_gate)])
    async def introspect(request: Request) -> JSONResponse:
        form = await _form(request)
        token = form.get("token")
        if not token:
            return oauth_error(400, "invalid_request", "missing token")
        return JSONResponse(state.store.introspect(token, state.now()))

    @app.post("/token/exchange", dependencies=[Depends(fault_gate)])
    async def token_exchange(request: Request) -> JSONResponse:
        body = await request.body()
        signed = from_http(request.method, _path_with_query(request), body, request.headers)
        presenter = signed and verify_request(signed, state.replay, now=state.now())
        if not presenter:
            return oauth_error(401, "invalid_client", "missing or invalid request signature")

        form = await _form(request)
        if form.get("grant_type") != TOKEN_EXCHANGE:
            return oauth_error(400, "unsupported_grant_type")
        if not form.get("subject_token") or not form.get("actor_key"):
            return oauth_error(400, "invalid_request", "subject_token and actor_key required")
        try:
            scope = form.get("scope")
            child = state.store.exchange(
                form["subject_token"],
                presenter=presenter,
                new_holder=form["actor_key"],
                operations=scope.split() if scope else None,
                max_amount=int(form["max_amount"]) if form.get("max_amount") else None,
                ttl_seconds=int(form["ttl_seconds"]) if form.get("ttl_seconds") else None,
                now=state.now(),
            )
        except GrantError as exc:
            return oauth_error(400, "invalid_grant", str(exc))
        except ValueError:
            return oauth_error(400, "invalid_request", "max_amount and ttl_seconds must be integers")
        return JSONResponse(
            {
                "access_token": child.token,
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "Bearer",
                "expires_in": child.expires_at - state.now(),
                "scope": " ".join(sorted(child.operations)),
            }
        )

    # ---- revocation (both modes) -------------------------------------------

    @app.post("/revoke", dependencies=[Depends(require_admin)])
    async def revoke(request: Request) -> JSONResponse:
        """RFC 7009. Answers 200 even for unknown tokens, as the RFC requires."""
        token = (await _form(request)).get("token")
        if not token:
            return oauth_error(400, "invalid_request", "missing token")
        if state.store.revoke(token):
            return JSONResponse({"revoked": "opaque"})
        try:
            parsed = Biscuit.from_base64(token, state.settings.root.public_key)
        except Exception:
            return JSONResponse({"revoked": None})
        # The last block's ID revokes this token and everything derived from it,
        # but not its parent.
        state.revoked_ids.add(parsed.revocation_ids[-1])
        state.revocation_seq += 1
        return JSONResponse({"revoked": "biscuit", "revocation_id": parsed.revocation_ids[-1]})

    @app.get("/revocations", dependencies=[Depends(fault_gate)])
    async def revocations() -> dict:
        return sign_revocation_list(
            state.settings.root,
            state.revoked_ids,
            seq=state.revocation_seq,
            issued_at=state.now(),
        )

    # ---- fault control (never faulted) -------------------------------------

    @app.get("/admin/fault", dependencies=[Depends(require_admin)])
    async def get_fault() -> dict:
        return state.faults.state()

    @app.put("/admin/fault", dependencies=[Depends(require_admin)])
    async def set_fault(config: FaultConfig) -> dict:
        state.faults.set(config)
        log.info("fault set: %s", config.model_dump())
        return state.faults.state()

    return app


class _Unauthorized(Exception):
    def __init__(self, basic: bool = False) -> None:
        self.basic = basic


class _Unavailable(Exception):
    def __init__(self, status: int) -> None:
        self.status = status

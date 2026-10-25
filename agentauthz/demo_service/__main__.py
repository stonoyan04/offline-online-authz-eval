"""Run the demo service behind the gateway in either mode.

    python -m agentauthz.demo_service --mode offline --port 8000
    python -m agentauthz.demo_service --mode online  --port 8000

Settings (flags override environment variables):

    --authz-url          AUTHZ_URL            http://127.0.0.1:8001
    --issuer-key         ISSUER_PUBLIC_KEY    hex; fetched from discovery if unset
    --refresh-seconds    REVOCATION_REFRESH   5      (offline)
    --max-staleness      MAX_STALENESS        unset = keep serving (offline)
    --timeout            INTROSPECTION_TIMEOUT 2     (online)
    --cache-ttl          INTROSPECTION_CACHE_TTL 0   (online)
    AUTHZ_CLIENT_ID / AUTHZ_CLIENT_SECRET     introspection credentials (online)
"""

from __future__ import annotations

import argparse
import logging
import os

import httpx
import uvicorn

from agentauthz.demo_service.app import create_demo_app
from agentauthz.gateway import OfflineAuthorizer, OnlineAuthorizer
from agentauthz.gateway.http import MAX_CONNECTIONS, gateway_client
from agentauthz.keys import public_key_from_hex


def _env_float(name: str):
    value = os.environ.get(name)
    return float(value) if value else None


def main() -> None:
    p = argparse.ArgumentParser(description="agentauthz demo service + gateway")
    p.add_argument("--mode", choices=["offline", "online"], default=os.environ.get("GATEWAY_MODE", "offline"))
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--authz-url", default=os.environ.get("AUTHZ_URL", "http://127.0.0.1:8001"))
    p.add_argument("--issuer-key", default=os.environ.get("ISSUER_PUBLIC_KEY"))
    p.add_argument("--refresh-seconds", type=float, default=_env_float("REVOCATION_REFRESH") or 5.0)
    p.add_argument("--max-staleness", type=float, default=_env_float("MAX_STALENESS"))
    p.add_argument("--timeout", type=float, default=_env_float("INTROSPECTION_TIMEOUT") or 2.0)
    p.add_argument("--cache-ttl", type=float, default=_env_float("INTROSPECTION_CACHE_TTL") or 0.0)
    p.add_argument("--log-level", default="info")
    args = p.parse_args()

    logging.basicConfig(level=args.log_level.upper(), format="%(levelname)s %(name)s: %(message)s")
    base = args.authz_url.rstrip("/")
    http = gateway_client(max_connections=MAX_CONNECTIONS, timeout=args.timeout)

    if args.mode == "offline":
        issuer_hex = args.issuer_key or httpx.get(f"{base}/.well-known/agentauthz").json()["issuer_public_key"]
        authorizer = OfflineAuthorizer(
            public_key_from_hex(issuer_hex),
            revocations_url=f"{base}/revocations",
            http=http,
            refresh_seconds=args.refresh_seconds,
            max_staleness=args.max_staleness,
        )
    else:
        cid = os.environ.get("AUTHZ_CLIENT_ID")
        secret = os.environ.get("AUTHZ_CLIENT_SECRET")
        if not cid or not secret:
            p.error("online mode needs AUTHZ_CLIENT_ID and AUTHZ_CLIENT_SECRET")
        authorizer = OnlineAuthorizer(
            f"{base}/introspect",
            cid,
            secret,
            http=http,
            timeout=args.timeout,
            cache_ttl=args.cache_ttl,
            max_in_flight=MAX_CONNECTIONS,
        )

    app = create_demo_app(authorizer, on_shutdown=http.aclose)
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)


if __name__ == "__main__":
    main()

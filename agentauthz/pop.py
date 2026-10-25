"""Proof of possession: the holder signs each request with its Ed25519 key.

This is a deliberately small stand-in for HTTP Message Signatures (RFC 9421).
It covers what the security argument needs:

* the signature binds method, path (with query), body digest, the digest of
  the presented token, a timestamp and a nonce;
* the verifier accepts a timestamp only inside a short window, so no
  server-issued nonce (and no extra round trip) is needed;
* a replay cache rejects a (key, nonce) pair seen inside the window.

Both gateway modes (offline and online) use this module unchanged, so the
experiment compares only the authorization check.

HTTP mapping (see spec/PROTOCOL.md):

    Authorization:   Bearer <token>
    Agent-Key:       <hex Ed25519 public key>
    Agent-Created:   <unix seconds>
    Agent-Nonce:     <random hex>
    Agent-Signature: <base64 signature>
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Mapping, Optional

from biscuit_auth import KeyPair
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

WINDOW_SECONDS = 30

HEADER_KEY = "Agent-Key"
HEADER_CREATED = "Agent-Created"
HEADER_NONCE = "Agent-Nonce"
HEADER_SIGNATURE = "Agent-Signature"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(
    method: str, path: str, body: bytes, token: str, created: int, nonce: str
) -> bytes:
    return "\n".join(
        [method.upper(), path, _sha256(body), _sha256(token.encode()), str(created), nonce]
    ).encode()


@dataclass(frozen=True)
class SignedRequest:
    method: str
    path: str  # path including query string, e.g. "/flights?to=CDG"
    body: bytes
    created: int
    nonce: str
    key: str  # hex public key of the signer
    signature: str  # base64
    token: str = ""  # the token presented with the request


def sign_request(
    holder: KeyPair,
    method: str,
    path: str,
    body: bytes = b"",
    *,
    token: str = "",
    created: Optional[int] = None,
    nonce: Optional[str] = None,
) -> SignedRequest:
    created = int(time.time()) if created is None else created
    nonce = nonce or os.urandom(16).hex()
    private = Ed25519PrivateKey.from_private_bytes(holder.private_key.to_bytes())
    signature = private.sign(_canonical(method, path, body, token, created, nonce))
    return SignedRequest(
        method=method,
        path=path,
        body=body,
        created=created,
        nonce=nonce,
        key=holder.public_key.to_bytes().hex(),
        signature=base64.b64encode(signature).decode(),
        token=token,
    )


def to_headers(request: SignedRequest) -> dict[str, str]:
    """HTTP headers that carry the token and the signature."""
    headers = {
        HEADER_KEY: request.key,
        HEADER_CREATED: str(request.created),
        HEADER_NONCE: request.nonce,
        HEADER_SIGNATURE: request.signature,
    }
    if request.token:
        headers["Authorization"] = f"Bearer {request.token}"
    return headers


def bearer_token(headers: Mapping[str, str]) -> Optional[str]:
    value = headers.get("authorization") or headers.get("Authorization") or ""
    scheme, _, token = value.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def from_http(
    method: str, path: str, body: bytes, headers: Mapping[str, str]
) -> Optional[SignedRequest]:
    """Rebuild a SignedRequest from an incoming HTTP request, or None if headers are missing.

    `headers` must be case-insensitive (Starlette and httpx headers are).
    """
    try:
        return SignedRequest(
            method=method,
            path=path,
            body=body,
            created=int(headers[HEADER_CREATED.lower()]),
            nonce=headers[HEADER_NONCE.lower()],
            key=headers[HEADER_KEY.lower()],
            signature=headers[HEADER_SIGNATURE.lower()],
            token=bearer_token(headers) or "",
        )
    except (KeyError, ValueError):
        return None


@dataclass
class ReplayCache:
    """Remembers (key, nonce) pairs until they fall out of the time window."""

    window: int = WINDOW_SECONDS
    max_entries: int = 100_000
    _seen: dict[tuple[str, str], int] = field(default_factory=dict)

    def check_and_add(self, key: str, nonce: str, now: int) -> bool:
        if len(self._seen) >= self.max_entries:
            self._seen = {k: t for k, t in self._seen.items() if now - t <= self.window}
            if len(self._seen) >= self.max_entries:
                return False  # still full of live entries: fail closed
        if (key, nonce) in self._seen:
            return False
        self._seen[(key, nonce)] = now
        return True


def verify_request(
    request: SignedRequest,
    cache: ReplayCache,
    *,
    now: Optional[int] = None,
) -> Optional[str]:
    """Return the signer's hex key if the request is valid, otherwise None."""
    now = int(time.time()) if now is None else now
    if abs(now - request.created) > cache.window:
        return None
    try:
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(request.key))
        public.verify(
            base64.b64decode(request.signature, validate=True),
            _canonical(
                request.method,
                request.path,
                request.body,
                request.token,
                request.created,
                request.nonce,
            ),
        )
    except (InvalidSignature, ValueError):
        return None
    if not cache.check_and_add(request.key, request.nonce, now):
        return None
    return request.key

"""Signed revocation list for offline gateways.

The issuer publishes the revocation IDs of revoked Biscuit tokens as a small
signed JSON document. Gateways fetch it periodically and keep the last valid
copy, so they keep working when the issuer is unreachable. How old that copy
may get is the revocation lag measured in the experiments.

Document format:

    {"payload": {"seq": 7, "issued_at": 1760000000, "revoked": ["ab12...", ...]},
     "signature": "<base64 Ed25519 signature over the canonical payload>"}
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from biscuit_auth import KeyPair, PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class RevocationList:
    seq: int
    issued_at: int
    revoked: frozenset[str]


def sign_revocation_list(
    issuer: KeyPair, revoked: Iterable[str], *, seq: int, issued_at: int
) -> dict[str, Any]:
    payload = {"seq": seq, "issued_at": issued_at, "revoked": sorted(set(revoked))}
    private = Ed25519PrivateKey.from_private_bytes(issuer.private_key.to_bytes())
    signature = private.sign(_canonical(payload))
    return {"payload": payload, "signature": base64.b64encode(signature).decode()}


def verify_revocation_list(document: Any, issuer: PublicKey) -> Optional[RevocationList]:
    """Return the list if the document is well formed and signed by `issuer`."""
    try:
        payload = document["payload"]
        signature = base64.b64decode(document["signature"], validate=True)
        Ed25519PublicKey.from_public_bytes(issuer.to_bytes()).verify(
            signature, _canonical(payload)
        )
        revoked = payload["revoked"]
        if not isinstance(revoked, list) or not all(isinstance(r, str) for r in revoked):
            return None
        return RevocationList(
            seq=int(payload["seq"]),
            issued_at=int(payload["issued_at"]),
            revoked=frozenset(revoked),
        )
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return None

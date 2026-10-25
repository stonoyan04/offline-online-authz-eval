"""Load and save Ed25519 keys as hex strings (for env vars and config files)."""

from __future__ import annotations

from biscuit_auth import Algorithm, KeyPair, PrivateKey, PublicKey


def keypair_from_hex(private_hex: str) -> KeyPair:
    raw = bytes.fromhex(private_hex.strip())
    if len(raw) != 32:
        raise ValueError("Ed25519 private key must be 32 bytes")
    return KeyPair.from_private_key(PrivateKey.from_bytes(raw, Algorithm.Ed25519))


def public_key_from_hex(public_hex: str) -> PublicKey:
    raw = bytes.fromhex(public_hex.strip())
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return PublicKey.from_bytes(raw, Algorithm.Ed25519)


def private_hex(keypair: KeyPair) -> str:
    return keypair.private_key.to_bytes().hex()


def public_hex(keypair_or_key) -> str:
    key = getattr(keypair_or_key, "public_key", keypair_or_key)
    return key.to_bytes().hex()

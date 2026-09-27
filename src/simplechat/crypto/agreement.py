"""X25519 ephemeral key agreement via PyNaCl."""

from __future__ import annotations

from dataclasses import dataclass

from nacl.public import Box, PrivateKey, PublicKey

from simplechat.protocol.constants import PUBKEY_SIZE


@dataclass
class EphemeralKeyPair:
    """Ephemeral X25519 keypair. Private key must never leave the process."""

    private_key: PrivateKey

    @classmethod
    def generate(cls) -> EphemeralKeyPair:
        return cls(private_key=PrivateKey.generate())

    @property
    def public_bytes(self) -> bytes:
        return bytes(self.private_key.public_key)

    def shared_secret(self, peer_public: bytes) -> bytearray:
        """
        Compute X25519 shared secret with peer's raw 32-byte public key.
        Returns a bytearray so callers can wipe it.
        """
        if len(peer_public) != PUBKEY_SIZE:
            raise ValueError("invalid peer public key length")
        try:
            peer = PublicKey(peer_public)
        except Exception as exc:  # noqa: BLE001 — fail closed on bad keys
            raise ValueError("invalid peer public key") from exc
        box = Box(self.private_key, peer)
        return bytearray(box.shared_key())

    def destroy(self) -> None:
        """Best-effort: drop reference to private key material."""
        # PyNaCl PrivateKey does not expose mutable sk wipe; drop reference.
        object.__setattr__(self, "private_key", None)


def validate_public_key(peer_public: bytes) -> None:
    if len(peer_public) != PUBKEY_SIZE:
        raise ValueError("invalid peer public key length")
    try:
        PublicKey(peer_public)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("invalid peer public key") from exc

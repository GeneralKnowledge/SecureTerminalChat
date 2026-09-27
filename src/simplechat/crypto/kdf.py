"""HKDF-SHA256 key derivation for simplechat v1."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from simplechat.crypto.wipe import wipe
from simplechat.protocol.constants import CONTEXT, KEY_SIZE


def _hkdf(ikm: bytes, info: bytes, length: int = KEY_SIZE) -> bytearray:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return bytearray(hkdf.derive(bytes(ikm)))


@dataclass
class SessionKeys:
    """Directional AEAD keys plus fingerprint material."""

    send_key: bytearray
    receive_key: bytearray
    fingerprint_key: bytearray

    def destroy(self) -> None:
        wipe(self.send_key)
        wipe(self.receive_key)
        wipe(self.fingerprint_key)


def derive_session_keys(shared_secret: bytes, *, is_host: bool) -> SessionKeys:
    """
    Derive host→joiner and joiner→host keys with domain-separated HKDF info.
    Map to send/receive according to role.
    """
    host_to_joiner = _hkdf(shared_secret, CONTEXT + b"|host-to-joiner")
    joiner_to_host = _hkdf(shared_secret, CONTEXT + b"|joiner-to-host")
    fingerprint_key = _hkdf(shared_secret, CONTEXT + b"|fingerprint")

    if is_host:
        send_key, receive_key = host_to_joiner, joiner_to_host
    else:
        send_key, receive_key = joiner_to_host, host_to_joiner

    return SessionKeys(
        send_key=send_key,
        receive_key=receive_key,
        fingerprint_key=fingerprint_key,
    )

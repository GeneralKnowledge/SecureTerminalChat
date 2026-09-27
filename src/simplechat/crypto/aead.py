"""ChaCha20-Poly1305 IETF AEAD via PyNaCl/libsodium."""

from __future__ import annotations

from nacl import bindings
from nacl.exceptions import CryptoError

from simplechat.protocol.constants import KEY_SIZE, NONCE_SIZE, TAG_SIZE


class NonceReuseError(ValueError):
    """Raised when an encrypt would reuse a nonce with the same key."""


class AeadCipher:
    """
    Directional ChaCha20-Poly1305 helper.
    Nonce = counter.to_bytes(12, 'big'). Tracks last encrypted counter to
    prevent reuse within this object.
    """

    def __init__(self, key: bytes | bytearray) -> None:
        if len(key) != KEY_SIZE:
            raise ValueError("AEAD key must be 32 bytes")
        self._key = bytearray(key)
        self._last_encrypt_counter: int | None = None
        self._destroyed = False

    def _require_live(self) -> None:
        if self._destroyed:
            raise RuntimeError("cipher destroyed")

    @staticmethod
    def nonce_for_counter(counter: int) -> bytes:
        if counter < 0:
            raise ValueError("counter must be non-negative")
        return counter.to_bytes(NONCE_SIZE, "big")

    def encrypt(self, plaintext: bytes, aad: bytes, counter: int) -> bytes:
        self._require_live()
        if self._last_encrypt_counter is not None and counter <= self._last_encrypt_counter:
            raise NonceReuseError("nonce/counter reuse prevented")
        nonce = self.nonce_for_counter(counter)
        ct = bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
            plaintext,
            aad,
            nonce,
            bytes(self._key),
        )
        self._last_encrypt_counter = counter
        # ct includes ciphertext || tag
        return nonce + ct

    def decrypt(self, payload: bytes, aad: bytes, counter: int) -> bytes:
        self._require_live()
        if len(payload) < NONCE_SIZE + TAG_SIZE:
            raise CryptoError("ciphertext too short")
        nonce = payload[:NONCE_SIZE]
        expected = self.nonce_for_counter(counter)
        if nonce != expected:
            raise CryptoError("nonce does not match counter")
        ct = payload[NONCE_SIZE:]
        try:
            return bindings.crypto_aead_chacha20poly1305_ietf_decrypt(
                ct,
                aad,
                nonce,
                bytes(self._key),
            )
        except CryptoError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise CryptoError("decryption failed") from exc

    def destroy(self) -> None:
        from simplechat.crypto.wipe import wipe

        wipe(self._key)
        self._destroyed = True

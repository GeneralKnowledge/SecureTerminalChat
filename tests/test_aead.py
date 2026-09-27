"""AEAD encrypt/decrypt and tamper tests."""

from __future__ import annotations

import pytest
from nacl.exceptions import CryptoError

from simplechat.crypto.aead import AeadCipher, NonceReuseError
from simplechat.crypto.agreement import EphemeralKeyPair
from simplechat.crypto.kdf import derive_session_keys
from simplechat.protocol.constants import MSG_CHAT, PROTOCOL_VERSION
from simplechat.protocol.handshake import build_aad


def _keys() -> tuple[AeadCipher, AeadCipher]:
    a = EphemeralKeyPair.generate()
    b = EphemeralKeyPair.generate()
    shared = a.shared_secret(b.public_bytes)
    host = derive_session_keys(shared, is_host=True)
    joiner = derive_session_keys(shared, is_host=False)
    return AeadCipher(host.send_key), AeadCipher(joiner.receive_key)


def test_round_trip() -> None:
    enc, dec = _keys()
    aad = build_aad(PROTOCOL_VERSION, MSG_CHAT, 0x01, 0)
    ct = enc.encrypt(b"hello", aad, 0)
    assert dec.decrypt(ct, aad, 0) == b"hello"


def test_modified_ciphertext_rejected() -> None:
    enc, dec = _keys()
    aad = build_aad(PROTOCOL_VERSION, MSG_CHAT, 0x01, 0)
    ct = bytearray(enc.encrypt(b"hello", aad, 0))
    ct[-1] ^= 0x01
    with pytest.raises(CryptoError):
        dec.decrypt(bytes(ct), aad, 0)


def test_modified_aad_rejected() -> None:
    enc, dec = _keys()
    aad = build_aad(PROTOCOL_VERSION, MSG_CHAT, 0x01, 0)
    ct = enc.encrypt(b"hello", aad, 0)
    bad_aad = build_aad(PROTOCOL_VERSION, MSG_CHAT, 0x01, 1)
    with pytest.raises(CryptoError):
        dec.decrypt(ct, bad_aad, 0)


def test_wrong_key_cannot_decrypt() -> None:
    enc, _ = _keys()
    other = AeadCipher(bytes(32))
    aad = build_aad(PROTOCOL_VERSION, MSG_CHAT, 0x01, 0)
    ct = enc.encrypt(b"hello", aad, 0)
    with pytest.raises(CryptoError):
        other.decrypt(ct, aad, 0)


def test_nonce_reuse_prevented() -> None:
    enc, _ = _keys()
    aad = build_aad(PROTOCOL_VERSION, MSG_CHAT, 0x01, 0)
    enc.encrypt(b"a", aad, 0)
    with pytest.raises(NonceReuseError):
        enc.encrypt(b"b", aad, 0)
    with pytest.raises(NonceReuseError):
        enc.encrypt(b"c", aad, 0)  # still same/lower

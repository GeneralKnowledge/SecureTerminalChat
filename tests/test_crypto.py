"""Cryptographic agreement and KDF tests."""

from __future__ import annotations

from simplechat.crypto.agreement import EphemeralKeyPair
from simplechat.crypto.kdf import derive_session_keys


def test_x25519_agreement_matches() -> None:
    a = EphemeralKeyPair.generate()
    b = EphemeralKeyPair.generate()
    sa = a.shared_secret(b.public_bytes)
    sb = b.shared_secret(a.public_bytes)
    assert sa == sb
    assert len(sa) == 32


def test_kdf_matching_session_keys() -> None:
    a = EphemeralKeyPair.generate()
    b = EphemeralKeyPair.generate()
    shared = a.shared_secret(b.public_bytes)
    host = derive_session_keys(shared, is_host=True)
    joiner = derive_session_keys(shared, is_host=False)
    assert host.send_key == joiner.receive_key
    assert host.receive_key == joiner.send_key
    assert host.fingerprint_key == joiner.fingerprint_key
    assert host.send_key != host.receive_key


def test_different_sessions_different_keys() -> None:
    a1, b1 = EphemeralKeyPair.generate(), EphemeralKeyPair.generate()
    a2, b2 = EphemeralKeyPair.generate(), EphemeralKeyPair.generate()
    s1 = a1.shared_secret(b1.public_bytes)
    s2 = a2.shared_secret(b2.public_bytes)
    k1 = derive_session_keys(s1, is_host=True)
    k2 = derive_session_keys(s2, is_host=True)
    assert k1.send_key != k2.send_key
    assert k1.fingerprint_key != k2.fingerprint_key


def test_invalid_public_key_rejected() -> None:
    a = EphemeralKeyPair.generate()
    try:
        a.shared_secret(b"short")
        assert False, "expected ValueError"
    except ValueError:
        pass

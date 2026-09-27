"""Fingerprint determinism tests."""

from __future__ import annotations

from simplechat.crypto.agreement import EphemeralKeyPair
from simplechat.crypto.fingerprint import compute_fingerprint
from simplechat.crypto.kdf import derive_session_keys


def test_fingerprint_deterministic() -> None:
    a = EphemeralKeyPair.generate()
    b = EphemeralKeyPair.generate()
    shared = a.shared_secret(b.public_bytes)
    k = derive_session_keys(shared, is_host=True)
    fp1 = compute_fingerprint(k.fingerprint_key)
    fp2 = compute_fingerprint(k.fingerprint_key)
    assert fp1 == fp2
    assert len(fp1) == 14  # XXXX-XXXX-XXXX
    assert fp1[4] == "-" and fp1[9] == "-"
    assert fp1 == fp1.upper()


def test_different_material_different_fingerprint() -> None:
    fps = set()
    for _ in range(5):
        a = EphemeralKeyPair.generate()
        b = EphemeralKeyPair.generate()
        shared = a.shared_secret(b.public_bytes)
        k = derive_session_keys(shared, is_host=True)
        fps.add(compute_fingerprint(k.fingerprint_key))
    assert len(fps) == 5

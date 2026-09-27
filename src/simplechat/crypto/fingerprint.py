"""Human-readable session fingerprint with domain separation."""

from __future__ import annotations

import hashlib

from simplechat.protocol.constants import CONTEXT


def compute_fingerprint(fingerprint_key: bytes) -> str:
    """
    fingerprint_display = SHA256(CONTEXT || "|fingerprint-display" || fingerprint_key)
    Show first 6 bytes as XXXX-XXXX-XXXX (uppercase hex).
    """
    digest = hashlib.sha256(
        CONTEXT + b"|fingerprint-display" + bytes(fingerprint_key)
    ).digest()
    hex6 = digest[:6].hex().upper()
    return f"{hex6[0:4]}-{hex6[4:8]}-{hex6[8:12]}"

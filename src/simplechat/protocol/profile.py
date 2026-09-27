"""Security profile: tor (default) vs direct (clearnet)."""

from __future__ import annotations

from enum import Enum


class SecurityProfile(str, Enum):
    """
    tor     — Wormhole over Tor + onion transport (default; hides peer IPs)
    direct  — Clearnet Wormhole + plain TCP (explicit downgrade; IPs visible)
    """

    TOR = "tor"
    DIRECT = "direct"


def parse_profile(value: str) -> SecurityProfile:
    try:
        return SecurityProfile(value.lower().strip())
    except ValueError as exc:
        raise ValueError(
            f"unknown security profile {value!r}; choose 'tor' or 'direct'"
        ) from exc

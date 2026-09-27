"""Handshake / bootstrap bundle validation."""

from __future__ import annotations

import base64
import json

import pytest

from simplechat.crypto.agreement import EphemeralKeyPair
from simplechat.protocol.handshake import BootstrapBundle, make_host_bundle


def test_bundle_round_trip() -> None:
    kp = EphemeralKeyPair.generate()
    onion = ("a" * 56) + ".onion"
    b = make_host_bundle(onion, kp.public_bytes, 9400)
    parsed = BootstrapBundle.from_json(b.to_json())
    assert parsed.onion_address == onion
    assert parsed.host_ephemeral_public_key == kp.public_bytes
    assert parsed.protocol_version == 1


def test_bad_version_rejected() -> None:
    kp = EphemeralKeyPair.generate()
    onion = ("b" * 56) + ".onion"
    raw = json.dumps(
        {
            "protocol": "simplechat",
            "protocol_version": 99,
            "onion_address": onion,
            "onion_port": 9400,
            "host_ephemeral_public_key": base64.b64encode(kp.public_bytes).decode(),
        }
    )
    with pytest.raises(ValueError, match="version"):
        BootstrapBundle.from_json(raw)


def test_bad_onion_rejected() -> None:
    kp = EphemeralKeyPair.generate()
    with pytest.raises(ValueError, match="onion"):
        make_host_bundle("not-an-onion", kp.public_bytes)


def test_malformed_json_rejected() -> None:
    with pytest.raises(ValueError, match="malformed"):
        BootstrapBundle.from_json("{not-json")

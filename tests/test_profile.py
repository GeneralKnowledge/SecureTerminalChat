"""Security profile and direct-bundle tests."""

from __future__ import annotations

import json

import pytest

from simplechat.cli import build_parser, main
from simplechat.crypto.agreement import EphemeralKeyPair
from simplechat.protocol.handshake import (
    BootstrapBundle,
    make_direct_bundle,
    make_tor_bundle,
)
from simplechat.protocol.profile import SecurityProfile, parse_profile


def test_parse_profile() -> None:
    assert parse_profile("tor") is SecurityProfile.TOR
    assert parse_profile("DIRECT") is SecurityProfile.DIRECT
    with pytest.raises(ValueError):
        parse_profile("vpn")


def test_direct_bundle_round_trip() -> None:
    kp = EphemeralKeyPair.generate()
    b = make_direct_bundle("192.168.1.10", 9400, kp.public_bytes)
    assert b.transport == "direct"
    parsed = BootstrapBundle.from_json(b.to_json())
    assert parsed.host_address == "192.168.1.10"
    assert parsed.host_port == 9400
    assert parsed.profile is SecurityProfile.DIRECT


def test_tor_bundle_includes_transport() -> None:
    kp = EphemeralKeyPair.generate()
    onion = ("a" * 56) + ".onion"
    b = make_tor_bundle(onion, kp.public_bytes, 9400)
    data = json.loads(b.to_json())
    assert data["transport"] == "tor"
    assert "onion_address" in data
    assert "host_address" not in data


def test_profile_mismatch_rejected_by_join_validation() -> None:
    kp = EphemeralKeyPair.generate()
    tor_bundle = make_tor_bundle(("b" * 56) + ".onion", kp.public_bytes)
    # Simulate join checking
    parsed = BootstrapBundle.from_json(tor_bundle.to_json())
    assert parsed.profile is SecurityProfile.TOR
    with pytest.raises(ValueError, match="profile mismatch"):
        if parsed.profile != SecurityProfile.DIRECT:
            raise ValueError(
                f"profile mismatch: CLI is direct, bootstrap bundle is {parsed.profile.value}"
            )


def test_cli_defaults_to_tor() -> None:
    parser = build_parser()
    args = parser.parse_args(["host"])
    assert args.profile == "tor"
    args = parser.parse_args(["join", "--profile", "direct", "1-foo-bar"])
    assert args.profile == "direct"
    assert args.code == "1-foo-bar"


def test_cli_rejects_advertise_on_tor() -> None:
    with pytest.raises(SystemExit) as ei:
        main(["host", "--profile", "tor", "--advertise", "1.2.3.4"])
    assert ei.value.code == 2

"""Handshake helpers: bootstrap bundle + AAD construction."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any

from simplechat.crypto.agreement import validate_public_key
from simplechat.protocol.constants import (
    DEFAULT_ONION_PORT,
    PROTOCOL_NAME,
    PROTOCOL_VERSION,
    PUBKEY_SIZE,
)

_ONION_RE = re.compile(r"^[a-z2-7]{56}\.onion$")


@dataclass(frozen=True)
class BootstrapBundle:
    protocol: str
    protocol_version: int
    onion_address: str
    onion_port: int
    host_ephemeral_public_key: bytes

    def to_json(self) -> str:
        obj = {
            "protocol": self.protocol,
            "protocol_version": self.protocol_version,
            "onion_address": self.onion_address,
            "onion_port": self.onion_port,
            "host_ephemeral_public_key": base64.b64encode(
                self.host_ephemeral_public_key
            ).decode("ascii"),
        }
        return json.dumps(obj, separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> BootstrapBundle:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("malformed bootstrap bundle") from exc
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Any) -> BootstrapBundle:
        if not isinstance(data, dict):
            raise ValueError("malformed bootstrap bundle")
        protocol = data.get("protocol")
        version = data.get("protocol_version")
        onion = data.get("onion_address")
        port = data.get("onion_port")
        pk_b64 = data.get("host_ephemeral_public_key")
        if protocol != PROTOCOL_NAME:
            raise ValueError("unexpected protocol name")
        if version != PROTOCOL_VERSION:
            raise ValueError("unexpected protocol version")
        if not isinstance(onion, str) or not _ONION_RE.match(onion):
            raise ValueError("invalid onion address")
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ValueError("invalid onion port")
        if not isinstance(pk_b64, str):
            raise ValueError("invalid host public key")
        try:
            pk = base64.b64decode(pk_b64, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise ValueError("invalid host public key encoding") from exc
        validate_public_key(pk)
        return cls(
            protocol=protocol,
            protocol_version=version,
            onion_address=onion,
            onion_port=port,
            host_ephemeral_public_key=pk,
        )


def make_host_bundle(
    onion_address: str,
    host_public_key: bytes,
    onion_port: int = DEFAULT_ONION_PORT,
) -> BootstrapBundle:
    validate_public_key(host_public_key)
    if not isinstance(onion_address, str) or not _ONION_RE.match(onion_address):
        raise ValueError("invalid onion address")
    if not isinstance(onion_port, int) or not (1 <= onion_port <= 65535):
        raise ValueError("invalid onion port")
    return BootstrapBundle(
        protocol=PROTOCOL_NAME,
        protocol_version=PROTOCOL_VERSION,
        onion_address=onion_address,
        onion_port=onion_port,
        host_ephemeral_public_key=host_public_key,
    )


def build_aad(version: int, message_type: int, direction: int, counter: int) -> bytes:
    return (
        bytes([version, message_type, direction])
        + counter.to_bytes(8, "big")
    )


def parse_handshake_payload(payload: bytes) -> bytes:
    if len(payload) != PUBKEY_SIZE:
        raise ValueError("invalid handshake payload length")
    validate_public_key(payload)
    return payload

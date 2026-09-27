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
from simplechat.protocol.profile import SecurityProfile

_ONION_RE = re.compile(r"^[a-z2-7]{56}\.onion$")
# Hostname or IPv4/IPv6 literal — keep permissive but reject empty / whitespace.
_HOST_RE = re.compile(r"^[A-Za-z0-9._:~%\-\[\]]+$")


@dataclass(frozen=True)
class BootstrapBundle:
    protocol: str
    protocol_version: int
    transport: str
    host_ephemeral_public_key: bytes
    onion_address: str | None = None
    onion_port: int | None = None
    host_address: str | None = None
    host_port: int | None = None

    @property
    def profile(self) -> SecurityProfile:
        return SecurityProfile(self.transport)

    def to_json(self) -> str:
        obj: dict[str, Any] = {
            "protocol": self.protocol,
            "protocol_version": self.protocol_version,
            "transport": self.transport,
            "host_ephemeral_public_key": base64.b64encode(
                self.host_ephemeral_public_key
            ).decode("ascii"),
        }
        if self.transport == SecurityProfile.TOR.value:
            obj["onion_address"] = self.onion_address
            obj["onion_port"] = self.onion_port
        elif self.transport == SecurityProfile.DIRECT.value:
            obj["host_address"] = self.host_address
            obj["host_port"] = self.host_port
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
        pk_b64 = data.get("host_ephemeral_public_key")
        if protocol != PROTOCOL_NAME:
            raise ValueError("unexpected protocol name")
        if version != PROTOCOL_VERSION:
            raise ValueError("unexpected protocol version")
        if not isinstance(pk_b64, str):
            raise ValueError("invalid host public key")
        try:
            pk = base64.b64decode(pk_b64, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise ValueError("invalid host public key encoding") from exc
        validate_public_key(pk)

        # Backward compatible: missing transport + onion fields => tor
        transport = data.get("transport")
        if transport is None and "onion_address" in data:
            transport = SecurityProfile.TOR.value
        if transport not in (
            SecurityProfile.TOR.value,
            SecurityProfile.DIRECT.value,
        ):
            raise ValueError("invalid or missing transport profile")

        if transport == SecurityProfile.TOR.value:
            onion = data.get("onion_address")
            port = data.get("onion_port")
            if not isinstance(onion, str) or not _ONION_RE.match(onion):
                raise ValueError("invalid onion address")
            if not isinstance(port, int) or not (1 <= port <= 65535):
                raise ValueError("invalid onion port")
            return cls(
                protocol=protocol,
                protocol_version=version,
                transport=transport,
                host_ephemeral_public_key=pk,
                onion_address=onion,
                onion_port=port,
            )

        address = data.get("host_address")
        port = data.get("host_port")
        if not isinstance(address, str) or not _HOST_RE.match(address):
            raise ValueError("invalid host address")
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ValueError("invalid host port")
        return cls(
            protocol=protocol,
            protocol_version=version,
            transport=transport,
            host_ephemeral_public_key=pk,
            host_address=address,
            host_port=port,
        )


def make_tor_bundle(
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
        transport=SecurityProfile.TOR.value,
        host_ephemeral_public_key=host_public_key,
        onion_address=onion_address,
        onion_port=onion_port,
    )


def make_direct_bundle(
    host_address: str,
    host_port: int,
    host_public_key: bytes,
) -> BootstrapBundle:
    validate_public_key(host_public_key)
    if not isinstance(host_address, str) or not _HOST_RE.match(host_address):
        raise ValueError("invalid host address")
    if not isinstance(host_port, int) or not (1 <= host_port <= 65535):
        raise ValueError("invalid host port")
    return BootstrapBundle(
        protocol=PROTOCOL_NAME,
        protocol_version=PROTOCOL_VERSION,
        transport=SecurityProfile.DIRECT.value,
        host_ephemeral_public_key=host_public_key,
        host_address=host_address,
        host_port=host_port,
    )


# Back-compat alias used by older tests/call sites
def make_host_bundle(
    onion_address: str,
    host_public_key: bytes,
    onion_port: int = DEFAULT_ONION_PORT,
) -> BootstrapBundle:
    return make_tor_bundle(onion_address, host_public_key, onion_port)


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

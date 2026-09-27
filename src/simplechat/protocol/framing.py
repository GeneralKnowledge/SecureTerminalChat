"""Length-prefixed message framing with bounded allocations."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from simplechat.protocol.constants import (
    LENGTH_PREFIX_SIZE,
    MAX_FRAME_BODY,
    MIN_FRAME_BODY,
    PROTOCOL_VERSION,
)


class FrameError(ValueError):
    """Malformed or illegal frame."""


@dataclass(frozen=True)
class Frame:
    version: int
    message_type: int
    counter: int
    payload: bytes

    def encode(self) -> bytes:
        if self.version != PROTOCOL_VERSION:
            raise FrameError("unsupported version")
        body = (
            struct.pack("!BB", self.version, self.message_type)
            + struct.pack("!Q", self.counter)
            + self.payload
        )
        if len(body) < MIN_FRAME_BODY:
            raise FrameError("body too short")
        if len(body) > MAX_FRAME_BODY:
            raise FrameError("body too large")
        return struct.pack("!I", len(body)) + body

    @classmethod
    def decode_body(cls, body: bytes) -> Frame:
        if len(body) < MIN_FRAME_BODY:
            raise FrameError("body too short")
        if len(body) > MAX_FRAME_BODY:
            raise FrameError("body too large")
        version, message_type = struct.unpack_from("!BB", body, 0)
        (counter,) = struct.unpack_from("!Q", body, 2)
        payload = body[10:]
        if version != PROTOCOL_VERSION:
            raise FrameError(f"unexpected protocol version: {version}")
        return cls(
            version=version,
            message_type=message_type,
            counter=counter,
            payload=payload,
        )


class FrameDecoder:
    """Incremental decoder for TCP streams."""

    def __init__(self, max_body: int = MAX_FRAME_BODY) -> None:
        self._buf = bytearray()
        self._max_body = max_body

    def feed(self, data: bytes) -> list[Frame]:
        if not data:
            return []
        self._buf.extend(data)
        frames: list[Frame] = []
        while True:
            if len(self._buf) < LENGTH_PREFIX_SIZE:
                break
            (length,) = struct.unpack_from("!I", self._buf, 0)
            if length == 0 or length < MIN_FRAME_BODY:
                raise FrameError(f"illegal frame length: {length}")
            if length > self._max_body:
                raise FrameError(f"frame length exceeds maximum: {length}")
            total = LENGTH_PREFIX_SIZE + length
            if len(self._buf) < total:
                break
            body = bytes(self._buf[LENGTH_PREFIX_SIZE:total])
            del self._buf[:total]
            frames.append(Frame.decode_body(body))
        return frames

    def reset(self) -> None:
        self._buf.clear()

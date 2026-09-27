"""Framing decoder tests."""

from __future__ import annotations

import struct

import pytest

from simplechat.protocol.constants import MAX_FRAME_BODY, PROTOCOL_VERSION
from simplechat.protocol.framing import Frame, FrameDecoder, FrameError


def _frame(payload: bytes = b"hi", counter: int = 0, mtype: int = 2) -> bytes:
    return Frame(
        version=PROTOCOL_VERSION,
        message_type=mtype,
        counter=counter,
        payload=payload,
    ).encode()


def test_round_trip() -> None:
    raw = _frame(b"abc", 3)
    dec = FrameDecoder()
    frames = dec.feed(raw)
    assert len(frames) == 1
    assert frames[0].payload == b"abc"
    assert frames[0].counter == 3


def test_partial_reads() -> None:
    raw = _frame(b"hello-world")
    dec = FrameDecoder()
    assert dec.feed(raw[:3]) == []
    assert dec.feed(raw[3:8]) == []
    frames = dec.feed(raw[8:])
    assert len(frames) == 1
    assert frames[0].payload == b"hello-world"


def test_multiple_frames_one_read() -> None:
    raw = _frame(b"a", 0) + _frame(b"b", 1) + _frame(b"c", 2)
    frames = FrameDecoder().feed(raw)
    assert [f.payload for f in frames] == [b"a", b"b", b"c"]


def test_zero_length_rejected() -> None:
    with pytest.raises(FrameError):
        FrameDecoder().feed(struct.pack("!I", 0))


def test_undersized_rejected() -> None:
    with pytest.raises(FrameError):
        FrameDecoder().feed(struct.pack("!I", 5) + b"abcde")


def test_oversized_rejected() -> None:
    with pytest.raises(FrameError):
        FrameDecoder().feed(struct.pack("!I", MAX_FRAME_BODY + 1))


def test_wrong_version_rejected() -> None:
    body = struct.pack("!BB", 99, 2) + struct.pack("!Q", 0) + b"x"
    raw = struct.pack("!I", len(body)) + body
    with pytest.raises(FrameError):
        FrameDecoder().feed(raw)


def test_truncated_waits() -> None:
    raw = _frame(b"xyz")
    dec = FrameDecoder()
    assert dec.feed(raw[:-1]) == []
    assert len(dec.feed(raw[-1:])) == 1

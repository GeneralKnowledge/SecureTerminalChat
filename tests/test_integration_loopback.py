"""In-process loopback integration: handshake + encrypted chat."""

from __future__ import annotations

import threading

import pytest

from simplechat.crypto.agreement import EphemeralKeyPair
from simplechat.protocol.session import ProtocolError, Session
from simplechat.protocol.state import SessionState
from simplechat.transport.tor_transport import paired_loopback


def _advance_to_established(host: Session, joiner: Session) -> None:
    for s in (host, joiner):
        s.transition(SessionState.BOOTSTRAPPING)
        s.transition(SessionState.CONNECTING)
        s.transition(SessionState.HANDSHAKING)

    # Joiner knows host pubkey a priori (as from wormhole bundle)
    joiner.accept_peer_public_key(host.local_keys.public_bytes)
    hs = joiner.build_handshake_frame()
    events = host.feed(hs)
    assert events == [("handshake", None)]
    assert host.fingerprint == joiner.fingerprint
    assert host.fingerprint is not None

    for s in (host, joiner):
        s.transition(SessionState.VERIFYING)
        s.transition(SessionState.ESTABLISHED)


def test_encrypted_chat_loopback() -> None:
    host = Session(is_host=True, local_keys=EphemeralKeyPair.generate())
    joiner = Session(is_host=False, local_keys=EphemeralKeyPair.generate())
    _advance_to_established(host, joiner)

    h_pipe, j_pipe = paired_loopback()
    h_pipe.sendall(host.encrypt_chat(b"Hello"))
    data = j_pipe.recv()
    events = joiner.feed(data)
    assert events == [("chat", b"Hello")]

    j_pipe.sendall(joiner.encrypt_chat(b"Hello!"))
    data = h_pipe.recv()
    events = host.feed(data)
    assert events == [("chat", b"Hello!")]


def test_tampered_message_fails_closed() -> None:
    host = Session(is_host=True, local_keys=EphemeralKeyPair.generate())
    joiner = Session(is_host=False, local_keys=EphemeralKeyPair.generate())
    _advance_to_established(host, joiner)
    frame = bytearray(host.encrypt_chat(b"secret"))
    frame[-2] ^= 0xFF
    with pytest.raises(ProtocolError, match="authentication|frame|replay"):
        joiner.feed(bytes(frame))


def test_replay_fails_closed() -> None:
    host = Session(is_host=True, local_keys=EphemeralKeyPair.generate())
    joiner = Session(is_host=False, local_keys=EphemeralKeyPair.generate())
    _advance_to_established(host, joiner)
    frame = host.encrypt_chat(b"once")
    assert joiner.feed(frame) == [("chat", b"once")]
    with pytest.raises(ProtocolError):
        joiner.feed(frame)


def test_messages_after_close_rejected() -> None:
    host = Session(is_host=True, local_keys=EphemeralKeyPair.generate())
    joiner = Session(is_host=False, local_keys=EphemeralKeyPair.generate())
    _advance_to_established(host, joiner)
    frame = host.encrypt_chat(b"bye")
    joiner.close_session()
    with pytest.raises(ProtocolError):
        joiner.feed(frame)


def test_two_threads_exchange() -> None:
    """Two threads over loopback pipes exchange plaintext."""
    host = Session(is_host=True, local_keys=EphemeralKeyPair.generate())
    joiner = Session(is_host=False, local_keys=EphemeralKeyPair.generate())
    _advance_to_established(host, joiner)
    h_pipe, j_pipe = paired_loopback()
    received: list[bytes] = []
    err: list[BaseException] = []

    def joiner_reader() -> None:
        try:
            data = j_pipe.recv()
            events = joiner.feed(data)
            for kind, val in events:
                if kind == "chat" and isinstance(val, bytes):
                    received.append(val)
                    j_pipe.sendall(joiner.encrypt_chat(b"ack:" + val))
        except BaseException as exc:  # noqa: BLE001
            err.append(exc)

    t = threading.Thread(target=joiner_reader)
    t.start()
    h_pipe.sendall(host.encrypt_chat(b"ping"))
    t.join(timeout=5)
    assert not err
    assert received == [b"ping"]
    reply = h_pipe.recv()
    events = host.feed(reply)
    assert events == [("chat", b"ack:ping")]

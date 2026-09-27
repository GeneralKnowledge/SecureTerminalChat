"""Encrypted chat session over a framed byte stream."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from nacl.exceptions import CryptoError

from simplechat.crypto.aead import AeadCipher
from simplechat.crypto.agreement import EphemeralKeyPair
from simplechat.crypto.fingerprint import compute_fingerprint
from simplechat.crypto.kdf import SessionKeys, derive_session_keys
from simplechat.crypto.wipe import wipe
from simplechat.protocol.constants import (
    DIR_HOST_TO_JOINER,
    DIR_JOINER_TO_HOST,
    MAX_PLAINTEXT,
    MSG_CHAT,
    MSG_CLOSE,
    MSG_HANDSHAKE,
    MSG_VERIFY,
    PROTOCOL_VERSION,
)
from simplechat.protocol.counters import CounterState, ReplayError
from simplechat.protocol.framing import Frame, FrameDecoder, FrameError
from simplechat.protocol.handshake import build_aad, parse_handshake_payload
from simplechat.protocol.state import SessionState, StateMachine

log = logging.getLogger("simplechat.protocol")


class ProtocolError(Exception):
    """Fatal protocol failure — session must terminate."""


@dataclass
class Session:
    """
    Protocol session. Chat UI drives this object; it never touches raw crypto APIs.
    """

    is_host: bool
    local_keys: EphemeralKeyPair
    sm: StateMachine = field(default_factory=StateMachine)
    decoder: FrameDecoder = field(default_factory=FrameDecoder)
    send_counters: CounterState = field(default_factory=CounterState)
    recv_counters: CounterState = field(default_factory=CounterState)
    session_keys: SessionKeys | None = None
    send_cipher: AeadCipher | None = None
    recv_cipher: AeadCipher | None = None
    fingerprint: str | None = None
    peer_verified: bool = False
    peer_public: bytes | None = None
    _shared_secret: bytearray | None = None
    _send_direction: int = 0
    _recv_direction: int = 0

    def __post_init__(self) -> None:
        if self.is_host:
            self._send_direction = DIR_HOST_TO_JOINER
            self._recv_direction = DIR_JOINER_TO_HOST
        else:
            self._send_direction = DIR_JOINER_TO_HOST
            self._recv_direction = DIR_HOST_TO_JOINER

    # --- state helpers ---

    def transition(self, state: SessionState) -> None:
        self.sm.transition(state)
        log.info("state=%s", state.name)

    @property
    def state(self) -> SessionState:
        return self.sm.state

    # --- handshake ---

    def build_handshake_frame(self) -> bytes:
        """Joiner: send local public key (counter 0)."""
        if self.is_host:
            raise ProtocolError("host does not send handshake pubkey frame")
        frame = Frame(
            version=PROTOCOL_VERSION,
            message_type=MSG_HANDSHAKE,
            counter=0,
            payload=self.local_keys.public_bytes,
        )
        return frame.encode()

    def accept_peer_public_key(self, peer_public: bytes) -> None:
        """Derive session keys from peer public key."""
        if self.session_keys is not None:
            raise ProtocolError("keys already established")
        peer_public = parse_handshake_payload(peer_public)
        self.peer_public = peer_public
        shared = self.local_keys.shared_secret(peer_public)
        self._shared_secret = shared
        keys = derive_session_keys(shared, is_host=self.is_host)
        wipe(shared)
        self._shared_secret = None
        self.session_keys = keys
        self.send_cipher = AeadCipher(keys.send_key)
        self.recv_cipher = AeadCipher(keys.receive_key)
        self.fingerprint = compute_fingerprint(keys.fingerprint_key)
        log.info("handshake complete; fingerprint ready")

    def process_handshake_frame(self, frame: Frame) -> None:
        if frame.message_type != MSG_HANDSHAKE:
            raise ProtocolError("expected handshake frame")
        if frame.counter != 0:
            raise ProtocolError("invalid handshake counter")
        self.accept_peer_public_key(frame.payload)

    # --- chat ---

    def encrypt_chat(self, plaintext: bytes) -> bytes:
        self._require_established()
        if len(plaintext) > MAX_PLAINTEXT:
            raise ProtocolError("plaintext too large")
        assert self.send_cipher is not None
        counter = self.send_counters.next_send_counter()
        aad = build_aad(PROTOCOL_VERSION, MSG_CHAT, self._send_direction, counter)
        payload = self.send_cipher.encrypt(plaintext, aad, counter)
        frame = Frame(
            version=PROTOCOL_VERSION,
            message_type=MSG_CHAT,
            counter=counter,
            payload=payload,
        )
        return frame.encode()

    def encrypt_close(self) -> bytes:
        self._require_established()
        assert self.send_cipher is not None
        counter = self.send_counters.next_send_counter()
        aad = build_aad(PROTOCOL_VERSION, MSG_CLOSE, self._send_direction, counter)
        payload = self.send_cipher.encrypt(b"", aad, counter)
        frame = Frame(
            version=PROTOCOL_VERSION,
            message_type=MSG_CLOSE,
            counter=counter,
            payload=payload,
        )
        return frame.encode()

    def encrypt_verify(self, verified: bool) -> bytes:
        self._require_established()
        assert self.send_cipher is not None
        counter = self.send_counters.next_send_counter()
        aad = build_aad(PROTOCOL_VERSION, MSG_VERIFY, self._send_direction, counter)
        payload = self.send_cipher.encrypt(bytes([1 if verified else 0]), aad, counter)
        frame = Frame(
            version=PROTOCOL_VERSION,
            message_type=MSG_VERIFY,
            counter=counter,
            payload=payload,
        )
        return frame.encode()

    def feed(self, data: bytes) -> list[tuple[str, bytes | bool | None]]:
        """
        Feed TCP bytes; return list of events:
          ("chat", plaintext_bytes)
          ("close", None)
          ("verify", bool)
          ("handshake", None)  — after processing peer handshake
        """
        try:
            frames = self.decoder.feed(data)
        except FrameError as exc:
            raise ProtocolError(f"invalid frame: {exc}") from exc

        events: list[tuple[str, bytes | bool | None]] = []
        for frame in frames:
            events.append(self._handle_frame(frame))
        return events

    def _handle_frame(self, frame: Frame) -> tuple[str, bytes | bool | None]:
        if frame.message_type == MSG_HANDSHAKE:
            if self.state not in (SessionState.HANDSHAKING, SessionState.CONNECTING):
                # Allow during HANDSHAKING primarily
                if self.session_keys is not None:
                    raise ProtocolError("unexpected handshake")
            self.process_handshake_frame(frame)
            return ("handshake", None)

        if self.session_keys is None or self.recv_cipher is None:
            raise ProtocolError("encrypted frame before handshake")

        if self.state == SessionState.CLOSED or self.recv_counters.closed:
            raise ProtocolError("messages rejected after session closure")

        try:
            self.recv_counters.accept_recv_counter(frame.counter)
        except ReplayError:
            raise ProtocolError("replay or unexpected counter") from None

        aad = build_aad(
            frame.version, frame.message_type, self._recv_direction, frame.counter
        )
        try:
            plaintext = self.recv_cipher.decrypt(frame.payload, aad, frame.counter)
        except CryptoError as exc:
            raise ProtocolError("authentication failure") from exc

        if frame.message_type == MSG_CHAT:
            return ("chat", plaintext)
        if frame.message_type == MSG_CLOSE:
            return ("close", None)
        if frame.message_type == MSG_VERIFY:
            if len(plaintext) != 1 or plaintext[0] not in (0, 1):
                raise ProtocolError("invalid verify payload")
            return ("verify", bool(plaintext[0]))
        raise ProtocolError(f"unknown message type: {frame.message_type}")

    def mark_verified(self) -> None:
        self.peer_verified = True

    def close_session(self) -> None:
        self.send_counters.close()
        self.recv_counters.close()
        if self.send_cipher:
            self.send_cipher.destroy()
        if self.recv_cipher:
            self.recv_cipher.destroy()
        if self.session_keys:
            self.session_keys.destroy()
        if self._shared_secret:
            wipe(self._shared_secret)
            self._shared_secret = None
        self.local_keys.destroy()
        self.sm.force_close()
        log.info("state=CLOSED")

    def _require_established(self) -> None:
        if self.state != SessionState.ESTABLISHED or self.send_cipher is None:
            raise ProtocolError("session not established")

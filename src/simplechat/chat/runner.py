"""Host/join session runners for the CLI."""

from __future__ import annotations

import logging
import select
import socket
import sys
import threading
from typing import BinaryIO, Protocol

from simplechat.bootstrap.wormhole_bootstrap import WormholeError, receive_bundle, send_bundle
from simplechat.chat.ui import ChatUI
from simplechat.crypto.agreement import EphemeralKeyPair
from simplechat.protocol.constants import DEFAULT_ONION_PORT
from simplechat.protocol.handshake import BootstrapBundle, make_host_bundle
from simplechat.protocol.session import ProtocolError, Session
from simplechat.protocol.state import SessionState
from simplechat.transport.tor_transport import TorError, TorTransport

log = logging.getLogger("simplechat.chat")


class ByteStream(Protocol):
    def sendall(self, data: bytes) -> None: ...
    def recv(self, bufsize: int = 4096) -> bytes: ...
    def close(self) -> None: ...


def _recv_loop(session: Session, conn: ByteStream, ui: ChatUI, stop: threading.Event) -> None:
    try:
        while not stop.is_set():
            try:
                data = conn.recv(4096)
            except OSError:
                break
            if not data:
                break
            try:
                events = session.feed(data)
            except (ProtocolError, Exception) as exc:  # noqa: BLE001
                ui.error(str(exc))
                stop.set()
                break
            for kind, value in events:
                if kind == "chat" and isinstance(value, bytes):
                    try:
                        text = value.decode("utf-8")
                    except UnicodeDecodeError:
                        ui.error("peer sent invalid UTF-8")
                        stop.set()
                        break
                    ui.show_peer(text)
                elif kind == "close":
                    ui.info("Peer closed the session.")
                    stop.set()
                    break
                elif kind == "verify" and isinstance(value, bool):
                    if value:
                        ui.info("Peer marked this session as verified on their side.")
                elif kind == "handshake":
                    pass
    finally:
        stop.set()


def _chat_loop(session: Session, conn: ByteStream, ui: ChatUI, stop: threading.Event) -> None:
    while not stop.is_set():
        # Use select on stdin when possible
        if sys.stdin in (None,):
            break
        try:
            ready, _, _ = select.select([sys.stdin], [], [], 0.5)
        except (OSError, ValueError):
            # Non-interactive; wait for stop
            stop.wait(0.5)
            continue
        if stop.is_set():
            break
        if not ready:
            continue
        line = sys.stdin.readline()
        if line == "":
            stop.set()
            break
        text = line.rstrip("\n")
        if not text:
            continue
        if text == "/quit":
            try:
                conn.sendall(session.encrypt_close())
            except Exception:  # noqa: BLE001
                pass
            stop.set()
            break
        if text == "/status":
            ui.show_status()
            continue
        if text == "/verify":
            session.mark_verified()
            ui.verified = True
            ui.info("Identity verification: VERIFIED (local mark only).")
            try:
                conn.sendall(session.encrypt_verify(True))
            except Exception as exc:  # noqa: BLE001
                ui.error(f"failed to send verify notice: {exc}")
            ui.show_status()
            continue
        try:
            frame = session.encrypt_chat(text.encode("utf-8"))
            conn.sendall(frame)
            ui.show_you(text)
        except Exception as exc:  # noqa: BLE001
            ui.error(str(exc))
            stop.set()
            break


def run_established_chat(session: Session, conn: ByteStream, ui: ChatUI) -> None:
    session.transition(SessionState.VERIFYING)
    assert session.fingerprint is not None
    ui.encryption_active = True
    ui.show_fingerprint(session.fingerprint)
    session.transition(SessionState.ESTABLISHED)

    stop = threading.Event()
    reader = threading.Thread(
        target=_recv_loop, args=(session, conn, ui, stop), daemon=True
    )
    reader.start()
    try:
        _chat_loop(session, conn, ui, stop)
    finally:
        stop.set()
        reader.join(timeout=2.0)


def run_host(
    *,
    ui: ChatUI | None = None,
    use_tor: bool = True,
    use_wormhole: bool = True,
    bundle_sink: list[str] | None = None,
    accept_conn: ByteStream | None = None,
    onion_port: int = DEFAULT_ONION_PORT,
) -> int:
    """
    Host a session. For tests, pass use_tor=False, use_wormhole=False,
    bundle_sink list, and accept_conn pre-connected stream.
    """
    ui = ui or ChatUI()
    tor: TorTransport | None = None
    session: Session | None = None
    conn: ByteStream | None = accept_conn

    try:
        session = Session(is_host=True, local_keys=EphemeralKeyPair.generate())
        session.transition(SessionState.BOOTSTRAPPING)

        if use_tor:
            ui.info("Starting Tor...")
            tor = TorTransport()
            onion = tor.start(create_onion=True, onion_port=onion_port)
            if onion is None:
                raise TorError("onion service not created")
            ui.tor_active = True
            bundle = make_host_bundle(onion.address, session.local_keys.public_bytes, onion.port)
        else:
            # Test/local mode: fake onion in bundle; real conn provided
            bundle = make_host_bundle(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
                session.local_keys.public_bytes,
                onion_port,
            )

        bundle_json = bundle.to_json()
        if bundle_sink is not None:
            bundle_sink.append(bundle_json)

        if use_wormhole:
            def _show(code: str) -> None:
                ui.show_wormhole_code(code)
                ui.info("Waiting for peer...")

            send_bundle(bundle_json, on_code=_show)
        else:
            ui.info("Waiting for peer (local mode)...")

        session.transition(SessionState.CONNECTING)
        if conn is None:
            assert tor is not None
            conn = tor.accept(timeout=600)

        ui.info("Peer connected (transport).")
        session.transition(SessionState.HANDSHAKING)

        # Read until handshake event
        while session.session_keys is None:
            data = conn.recv(4096)
            if not data:
                raise ProtocolError("peer disconnected during handshake")
            events = session.feed(data)
            if not any(k == "handshake" for k, _ in events):
                # may be partial; continue
                if session.session_keys is None and events:
                    raise ProtocolError("unexpected message during handshake")

        run_established_chat(session, conn, ui)
        return 0
    except (TorError, WormholeError, ProtocolError, ValueError) as exc:
        ui.error(str(exc))
        return 1
    except KeyboardInterrupt:
        ui.info("Interrupted.")
        return 130
    finally:
        if session is not None:
            try:
                session.transition(SessionState.CLOSING)
            except Exception:  # noqa: BLE001
                pass
            session.close_session()
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass
        if tor is not None:
            tor.stop()
            ui.tor_active = False


def run_join(
    code: str | None = None,
    *,
    ui: ChatUI | None = None,
    use_tor: bool = True,
    use_wormhole: bool = True,
    bundle_json: str | None = None,
    conn: ByteStream | None = None,
) -> int:
    ui = ui or ChatUI()
    tor: TorTransport | None = None
    session: Session | None = None
    stream: ByteStream | None = conn

    try:
        session = Session(is_host=False, local_keys=EphemeralKeyPair.generate())
        session.transition(SessionState.BOOTSTRAPPING)

        if use_wormhole:
            if not code:
                raise WormholeError("wormhole code required")
            ui.info("Connecting to Magic Wormhole...")
            raw = receive_bundle(code)
        else:
            if not bundle_json:
                raise ValueError("bundle_json required in local mode")
            raw = bundle_json

        bundle = BootstrapBundle.from_json(raw)
        session.transition(SessionState.CONNECTING)

        if use_tor:
            ui.info("Starting Tor...")
            tor = TorTransport()
            tor.start(create_onion=False)
            ui.tor_active = True
            ui.info("Connecting to onion service...")
            stream = tor.connect_onion(bundle.onion_address, bundle.onion_port)
        elif stream is None:
            raise ValueError("conn required in local mode")

        session.transition(SessionState.HANDSHAKING)
        assert stream is not None
        # Derive keys using host pubkey from bundle, then send our pubkey
        session.accept_peer_public_key(bundle.host_ephemeral_public_key)
        stream.sendall(session.build_handshake_frame())

        run_established_chat(session, stream, ui)
        return 0
    except (TorError, WormholeError, ProtocolError, ValueError) as exc:
        ui.error(str(exc))
        return 1
    except KeyboardInterrupt:
        ui.info("Interrupted.")
        return 130
    finally:
        if session is not None:
            try:
                session.transition(SessionState.CLOSING)
            except Exception:  # noqa: BLE001
                pass
            session.close_session()
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass
        if tor is not None:
            tor.stop()
            ui.tor_active = False

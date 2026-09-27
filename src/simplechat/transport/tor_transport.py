"""Ephemeral Tor onion transport via Stem."""

from __future__ import annotations

import logging
import os
import shutil
import socket
import tempfile
import threading
from dataclasses import dataclass

log = logging.getLogger("simplechat.transport")

try:
    from stem.control import Controller
    from stem.process import launch_tor_with_config
except ImportError:  # pragma: no cover
    Controller = None  # type: ignore[misc, assignment]
    launch_tor_with_config = None  # type: ignore[misc, assignment]


class TorError(RuntimeError):
    pass


@dataclass
class OnionEndpoint:
    address: str  # foo.onion
    port: int


class TorTransport:
    """
    Manages an ephemeral Tor process and optional onion service.
    For joiners, only SOCKS is required.
    """

    def __init__(self, tor_binary: str | None = None) -> None:
        self._tor_binary = tor_binary or shutil.which("tor") or (
            "/usr/sbin/tor" if os.path.isfile("/usr/sbin/tor") else None
        )
        self._tor_process = None
        self._controller: Controller | None = None
        self._datadir: tempfile.TemporaryDirectory[str] | None = None
        self._socks_port: int | None = None
        self._control_port: int | None = None
        self._service_id: str | None = None
        self._onion: OnionEndpoint | None = None
        self._listen_sock: socket.socket | None = None

    @property
    def socks_port(self) -> int:
        if self._socks_port is None:
            raise TorError("Tor not started")
        return self._socks_port

    @property
    def onion(self) -> OnionEndpoint | None:
        return self._onion

    def start(self, *, create_onion: bool, onion_port: int = 9400) -> OnionEndpoint | None:
        if launch_tor_with_config is None or Controller is None:
            raise TorError("stem is not installed")
        if not self._tor_binary:
            raise TorError("tor binary not found on PATH")

        self._datadir = tempfile.TemporaryDirectory(prefix="simplechat-tor-")
        socks = _free_port()
        control = _free_port()
        self._socks_port = socks
        self._control_port = control
        datadir = self._datadir.name

        log.info("Starting Tor (socks=%s control=%s)...", socks, control)
        config = {
            "SocksPort": str(socks),
            "ControlPort": str(control),
            "DataDirectory": datadir,
            "CookieAuthentication": "1",
            "PublishHidServDescriptors": "1",
        }
        try:
            self._tor_process = launch_tor_with_config(
                config=config,
                tor_cmd=self._tor_binary,
                take_ownership=True,
                timeout=300,
                completion_percent=100,
                init_msg_handler=lambda line: log.debug("tor: %s", line),
            )
        except OSError as exc:
            raise TorError(f"failed to start Tor: {exc}") from exc

        try:
            self._controller = Controller.from_port(port=control)
            self._controller.authenticate()
        except Exception as exc:  # noqa: BLE001
            self.stop()
            raise TorError(f"failed to authenticate to Tor control port: {exc}") from exc

        if not create_onion:
            return None

        # Bind local listener for onion target
        listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen.bind(("127.0.0.1", 0))
        listen.listen(1)
        local_port = listen.getsockname()[1]
        self._listen_sock = listen

        log.info("Creating temporary onion service...")
        try:
            response = self._controller.create_ephemeral_hidden_service(
                {onion_port: local_port},
                await_publication=True,
            )
        except Exception as exc:  # noqa: BLE001
            self.stop()
            raise TorError(f"failed to create onion service: {exc}") from exc

        self._service_id = response.service_id
        address = f"{response.service_id}.onion"
        self._onion = OnionEndpoint(address=address, port=onion_port)
        log.info("Onion service ready")
        return self._onion

    def accept(self, timeout: float | None = None) -> socket.socket:
        if self._listen_sock is None:
            raise TorError("no onion listener")
        self._listen_sock.settimeout(timeout)
        try:
            conn, _addr = self._listen_sock.accept()
        except TimeoutError as exc:
            raise TorError("timed out waiting for peer") from exc
        except socket.timeout as exc:
            raise TorError("timed out waiting for peer") from exc
        conn.settimeout(None)
        return conn

    def connect_onion(self, address: str, port: int, timeout: float = 120.0) -> socket.socket:
        """Connect to an onion address via SOCKS5 (no auth)."""
        if self._socks_port is None:
            raise TorError("Tor not started")
        return socks5_connect(
            "127.0.0.1",
            self._socks_port,
            address,
            port,
            timeout=timeout,
        )

    def stop(self) -> None:
        log.info("Shutting down Tor...")
        if self._controller and self._service_id:
            try:
                self._controller.remove_ephemeral_hidden_service(self._service_id)
            except Exception:  # noqa: BLE001
                log.debug("onion removal failed", exc_info=True)
        if self._listen_sock:
            try:
                self._listen_sock.close()
            except OSError:
                pass
            self._listen_sock = None
        if self._controller:
            try:
                self._controller.close()
            except Exception:  # noqa: BLE001
                pass
            self._controller = None
        if self._tor_process:
            try:
                self._tor_process.terminate()
                self._tor_process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                try:
                    self._tor_process.kill()
                except Exception:  # noqa: BLE001
                    pass
            self._tor_process = None
        if self._datadir:
            try:
                self._datadir.cleanup()
            except Exception:  # noqa: BLE001
                pass
            self._datadir = None
        self._onion = None
        log.info("Tor shutdown complete")


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    timeout: float = 120.0,
) -> socket.socket:
    """Minimal SOCKS5 CONNECT (no auth) for onion destinations."""
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        # greeting
        sock.sendall(b"\x05\x01\x00")
        resp = _recvexact(sock, 2)
        if resp != b"\x05\x00":
            raise TorError(f"SOCKS5 auth negotiation failed: {resp!r}")
        # connect request: ATYP domain
        host_bytes = dest_host.encode("ascii")
        req = (
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + dest_port.to_bytes(2, "big")
        )
        sock.sendall(req)
        # response header
        hdr = _recvexact(sock, 4)
        if hdr[0] != 5 or hdr[1] != 0:
            raise TorError(f"SOCKS5 connect failed: status={hdr[1]}")
        atyp = hdr[3]
        if atyp == 1:
            _recvexact(sock, 4 + 2)
        elif atyp == 3:
            ln = _recvexact(sock, 1)[0]
            _recvexact(sock, ln + 2)
        elif atyp == 4:
            _recvexact(sock, 16 + 2)
        else:
            raise TorError(f"SOCKS5 unknown atyp {atyp}")
        sock.settimeout(None)
        return sock
    except Exception:
        sock.close()
        raise


def _recvexact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise TorError("SOCKS5 connection closed")
        buf.extend(chunk)
    return bytes(buf)


class LoopbackPipe:
    """
    In-memory bidirectional byte pipe for tests (no Tor).
    Pair two pipes: a.peer = b; b.peer = a
    """

    def __init__(self) -> None:
        self._inbox: list[bytes] = []
        self._cond = threading.Condition()
        self.peer: LoopbackPipe | None = None
        self._closed = False

    def sendall(self, data: bytes) -> None:
        if self.peer is None:
            raise OSError("no peer")
        if self._closed or self.peer._closed:
            raise OSError("pipe closed")
        with self.peer._cond:
            self.peer._inbox.append(bytes(data))
            self.peer._cond.notify_all()

    def recv(self, bufsize: int = 4096) -> bytes:
        with self._cond:
            while not self._inbox and not self._closed:
                self._cond.wait(timeout=1.0)
            if not self._inbox:
                return b""
            data = self._inbox.pop(0)
            if len(data) > bufsize:
                self._inbox.insert(0, data[bufsize:])
                return data[:bufsize]
            return data

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()


def paired_loopback() -> tuple[LoopbackPipe, LoopbackPipe]:
    a, b = LoopbackPipe(), LoopbackPipe()
    a.peer = b
    b.peer = a
    return a, b

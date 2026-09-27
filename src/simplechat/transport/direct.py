"""Direct (clearnet) TCP listener/dialer for the direct security profile."""

from __future__ import annotations

import socket


class DirectTransportError(RuntimeError):
    pass


def guess_advertise_address() -> str:
    """Best-effort local IPv4 for --advertise default (may be wrong behind NAT)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 80))
        return s.getsockname()[0]
    except OSError as exc:
        raise DirectTransportError(
            "could not guess advertise address; pass --advertise HOST"
        ) from exc
    finally:
        s.close()


class DirectListener:
    """Listen on TCP for an inbound peer connection."""

    def __init__(self, bind_host: str = "0.0.0.0", bind_port: int = 0) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((bind_host, bind_port))
        self._sock.listen(1)
        self.bind_host = bind_host
        self.bind_port = int(self._sock.getsockname()[1])

    def accept(self, timeout: float | None = None) -> socket.socket:
        self._sock.settimeout(timeout)
        try:
            conn, _addr = self._sock.accept()
        except TimeoutError as exc:
            raise DirectTransportError("timed out waiting for peer") from exc
        except socket.timeout as exc:
            raise DirectTransportError("timed out waiting for peer") from exc
        conn.settimeout(None)
        return conn

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def connect_direct(host: str, port: int, timeout: float = 60.0) -> socket.socket:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise DirectTransportError(f"direct connect failed: {exc}") from exc
    sock.settimeout(None)
    return sock

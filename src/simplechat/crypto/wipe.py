"""Best-effort wipe of sensitive bytearrays."""

from __future__ import annotations


def wipe(buf: bytearray | None) -> None:
    """Overwrite a bytearray with zeros. No-op for None."""
    if buf is None:
        return
    for i in range(len(buf)):
        buf[i] = 0


def wipe_bytes_view(data: bytes | bytearray | memoryview | None) -> bytearray | None:
    """
    If data is a bytearray, wipe it. bytes objects are immutable; callers should
    prefer keeping secrets in bytearray form when destruction matters.
    """
    if isinstance(data, bytearray):
        wipe(data)
        return data
    return None

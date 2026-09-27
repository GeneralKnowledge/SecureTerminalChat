"""Strict monotonic receive counters and send counter allocation."""

from __future__ import annotations

from simplechat.protocol.constants import COUNTER_MAX


class ReplayError(ValueError):
    """Message rejected due to replay / counter rules."""


class CounterOverflowError(ValueError):
    """Send counter would overflow."""


class CounterState:
    """Per-direction send/receive counters with strict accept rules."""

    def __init__(self) -> None:
        self.send_counter = 0
        self.recv_expected = 0
        self._closed = False

    def close(self) -> None:
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed

    def next_send_counter(self) -> int:
        if self._closed:
            raise ReplayError("session closed")
        if self.send_counter > COUNTER_MAX:
            raise CounterOverflowError("send counter overflow")
        c = self.send_counter
        if c == COUNTER_MAX:
            # Allow using COUNTER_MAX once, then overflow on next
            self.send_counter = COUNTER_MAX + 1
            return c
        self.send_counter = c + 1
        return c

    def accept_recv_counter(self, counter: int) -> None:
        if self._closed:
            raise ReplayError("messages rejected after session closure")
        if counter != self.recv_expected:
            raise ReplayError(
                f"unexpected counter: got {counter}, expected {self.recv_expected}"
            )
        if self.recv_expected == COUNTER_MAX:
            self.recv_expected = COUNTER_MAX + 1  # next accept will fail overflow path
        else:
            self.recv_expected += 1
        if self.recv_expected > COUNTER_MAX + 1:
            raise CounterOverflowError("receive counter overflow")

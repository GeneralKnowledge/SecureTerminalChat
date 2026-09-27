"""Replay / counter strictness tests."""

from __future__ import annotations

import pytest

from simplechat.protocol.constants import COUNTER_MAX
from simplechat.protocol.counters import CounterOverflowError, CounterState, ReplayError


def test_first_message() -> None:
    c = CounterState()
    assert c.next_send_counter() == 0
    c.accept_recv_counter(0)
    assert c.recv_expected == 1


def test_duplicate_rejected() -> None:
    c = CounterState()
    c.accept_recv_counter(0)
    with pytest.raises(ReplayError):
        c.accept_recv_counter(0)


def test_old_counter_rejected() -> None:
    c = CounterState()
    c.accept_recv_counter(0)
    c.accept_recv_counter(1)
    with pytest.raises(ReplayError):
        c.accept_recv_counter(0)


def test_skipped_counter_rejected() -> None:
    c = CounterState()
    with pytest.raises(ReplayError):
        c.accept_recv_counter(1)


def test_very_large_unexpected_rejected() -> None:
    c = CounterState()
    with pytest.raises(ReplayError):
        c.accept_recv_counter(2**63)


def test_after_close_rejected() -> None:
    c = CounterState()
    c.close()
    with pytest.raises(ReplayError):
        c.accept_recv_counter(0)
    with pytest.raises(ReplayError):
        c.next_send_counter()


def test_send_sequence() -> None:
    c = CounterState()
    assert c.next_send_counter() == 0
    assert c.next_send_counter() == 1
    assert c.next_send_counter() == 2


def test_counter_overflow_send() -> None:
    c = CounterState()
    c.send_counter = COUNTER_MAX
    assert c.next_send_counter() == COUNTER_MAX
    with pytest.raises(CounterOverflowError):
        c.next_send_counter()

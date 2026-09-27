"""State machine transition tests."""

from __future__ import annotations

import pytest

from simplechat.protocol.state import (
    InvalidStateTransition,
    SessionState,
    StateMachine,
)


def test_happy_path() -> None:
    sm = StateMachine()
    assert sm.state == SessionState.STARTING
    for s in (
        SessionState.BOOTSTRAPPING,
        SessionState.CONNECTING,
        SessionState.HANDSHAKING,
        SessionState.VERIFYING,
        SessionState.ESTABLISHED,
        SessionState.CLOSING,
        SessionState.CLOSED,
    ):
        sm.transition(s)
    assert sm.state == SessionState.CLOSED


def test_invalid_transition() -> None:
    sm = StateMachine()
    with pytest.raises(InvalidStateTransition):
        sm.transition(SessionState.ESTABLISHED)


def test_closed_terminal() -> None:
    sm = StateMachine()
    sm.force_close()
    assert sm.state == SessionState.CLOSED
    with pytest.raises(InvalidStateTransition):
        sm.transition(SessionState.STARTING)

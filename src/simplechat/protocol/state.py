"""Session state machine."""

from __future__ import annotations

from enum import Enum, auto


class SessionState(Enum):
    STARTING = auto()
    BOOTSTRAPPING = auto()
    CONNECTING = auto()
    HANDSHAKING = auto()
    VERIFYING = auto()
    ESTABLISHED = auto()
    CLOSING = auto()
    CLOSED = auto()


_ALLOWED: dict[SessionState, frozenset[SessionState]] = {
    SessionState.STARTING: frozenset({SessionState.BOOTSTRAPPING, SessionState.CLOSING}),
    SessionState.BOOTSTRAPPING: frozenset({SessionState.CONNECTING, SessionState.CLOSING}),
    SessionState.CONNECTING: frozenset({SessionState.HANDSHAKING, SessionState.CLOSING}),
    SessionState.HANDSHAKING: frozenset({SessionState.VERIFYING, SessionState.CLOSING}),
    SessionState.VERIFYING: frozenset({SessionState.ESTABLISHED, SessionState.CLOSING}),
    SessionState.ESTABLISHED: frozenset({SessionState.CLOSING}),
    SessionState.CLOSING: frozenset({SessionState.CLOSED}),
    SessionState.CLOSED: frozenset(),
}


class InvalidStateTransition(ValueError):
    pass


class StateMachine:
    def __init__(self) -> None:
        self.state = SessionState.STARTING

    def transition(self, new_state: SessionState) -> None:
        allowed = _ALLOWED[self.state]
        if new_state not in allowed:
            raise InvalidStateTransition(
                f"invalid transition {self.state.name} → {new_state.name}"
            )
        self.state = new_state

    def force_close(self) -> None:
        """Move toward CLOSED from any non-terminal state."""
        if self.state == SessionState.CLOSED:
            return
        if self.state != SessionState.CLOSING:
            # Bypass graph for emergency close from any state except we still
            # record CLOSING then CLOSED for lifecycle clarity.
            self.state = SessionState.CLOSING
        self.state = SessionState.CLOSED

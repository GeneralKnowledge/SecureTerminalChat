"""Local-mode host/join runner integration without Tor/Wormhole."""

from __future__ import annotations

import io
import threading

from simplechat.chat.runner import run_host, run_join
from simplechat.chat.ui import ChatUI
from simplechat.transport.tor_transport import paired_loopback


def test_runner_local_handshake_and_status(monkeypatch: object) -> None:
    """
    Drive host/join in local mode far enough to establish encryption,
    then quit via /quit on both sides.
    """
    h_pipe, j_pipe = paired_loopback()
    bundle_sink: list[str] = []
    host_out = io.StringIO()
    join_out = io.StringIO()
    results: dict[str, int] = {}

    # Provide scripted stdin for both sides after connection
    host_lines = iter(["/status\n", "/quit\n"])
    join_lines = iter(["/status\n", "/quit\n"])

    def host_readline() -> str:
        try:
            return next(host_lines)
        except StopIteration:
            return ""

    def join_readline() -> str:
        try:
            return next(join_lines)
        except StopIteration:
            return ""

    def host_main() -> None:
        # Patch stdin readline for host thread — use a simple approach:
        # run_host blocks in chat loop; we monkeypatch select/readline carefully.
        import simplechat.chat.runner as runner

        orig_chat = runner._chat_loop

        def short_chat(session, conn, ui, stop):  # noqa: ANN001
            ui.show_status()
            assert ui.encryption_active
            stop.set()

        runner._chat_loop = short_chat  # type: ignore[assignment]
        try:
            results["host"] = run_host(
                ui=ChatUI(out=host_out, err=host_out),
                use_tor=False,
                use_wormhole=False,
                bundle_sink=bundle_sink,
                accept_conn=h_pipe,
            )
        finally:
            runner._chat_loop = orig_chat  # type: ignore[assignment]

    def join_main() -> None:
        import time

        # Wait for bundle
        for _ in range(50):
            if bundle_sink:
                break
            time.sleep(0.05)
        assert bundle_sink, "host did not publish bundle"
        import simplechat.chat.runner as runner

        orig_chat = runner._chat_loop

        def short_chat(session, conn, ui, stop):  # noqa: ANN001
            ui.show_status()
            assert ui.encryption_active
            # Exchange one message
            conn.sendall(session.encrypt_chat(b"hi from joiner"))
            stop.set()

        runner._chat_loop = short_chat  # type: ignore[assignment]
        try:
            results["join"] = run_join(
                code=None,
                ui=ChatUI(out=join_out, err=join_out),
                use_tor=False,
                use_wormhole=False,
                bundle_json=bundle_sink[0],
                conn=j_pipe,
            )
        finally:
            runner._chat_loop = orig_chat  # type: ignore[assignment]

    th = threading.Thread(target=host_main)
    tj = threading.Thread(target=join_main)
    th.start()
    tj.start()
    th.join(timeout=15)
    tj.join(timeout=15)
    assert results.get("host") == 0
    assert results.get("join") == 0
    assert "Fingerprint:" in host_out.getvalue()
    assert "Fingerprint:" in join_out.getvalue()
    assert "Encryption: ACTIVE" in host_out.getvalue()

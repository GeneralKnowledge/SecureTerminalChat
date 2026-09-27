"""Local-mode host/join runner integration without Tor/Wormhole."""

from __future__ import annotations

import io
import threading
import time

from simplechat.chat.runner import run_host, run_join
from simplechat.chat.ui import ChatUI
from simplechat.protocol.profile import SecurityProfile
from simplechat.transport.tor_transport import paired_loopback


def test_runner_local_handshake_and_status() -> None:
    h_pipe, j_pipe = paired_loopback()
    bundle_sink: list[str] = []
    host_out = io.StringIO()
    join_out = io.StringIO()
    results: dict[str, int] = {}

    def host_main() -> None:
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
                profile=SecurityProfile.DIRECT,
                use_wormhole=False,
                bundle_sink=bundle_sink,
                accept_conn=h_pipe,
                advertise="127.0.0.1",
                listen_port=9400,
            )
        finally:
            runner._chat_loop = orig_chat  # type: ignore[assignment]

    def join_main() -> None:
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
            conn.sendall(session.encrypt_chat(b"hi from joiner"))
            stop.set()

        runner._chat_loop = short_chat  # type: ignore[assignment]
        try:
            results["join"] = run_join(
                code=None,
                ui=ChatUI(out=join_out, err=join_out),
                profile=SecurityProfile.DIRECT,
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
    assert "DIRECT" in host_out.getvalue()
    assert "Tor: OFF" in host_out.getvalue() or "IPs visible" in host_out.getvalue()

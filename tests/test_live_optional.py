"""Optional live integration (Tor + Wormhole). Skipped unless SIMPLECHAT_LIVE=1."""

from __future__ import annotations

import os
import shutil
import threading
import time

import pytest

pytestmark = pytest.mark.live

require_live = pytest.mark.skipif(
    os.environ.get("SIMPLECHAT_LIVE") != "1",
    reason="Set SIMPLECHAT_LIVE=1 to run live Tor/Wormhole tests",
)


@require_live
@pytest.mark.timeout(300)
def test_live_wormhole_tor_chat() -> None:
    if not shutil.which("tor"):
        pytest.skip("tor binary not available")

    from simplechat.chat.runner import run_host, run_join
    from simplechat.chat.ui import ChatUI
    import io

    code_box: list[str] = []
    host_out = io.StringIO()
    join_out = io.StringIO()
    results: dict[str, int] = {}

    def on_code_capture(code: str) -> None:
        code_box.append(code)

    # Patch send_bundle to capture code via UI path is hard; instead wrap runner
    import simplechat.bootstrap.wormhole_bootstrap as wh

    orig_send = wh.send_bundle

    def capturing_send(bundle_json: str, on_code=None):  # noqa: ANN001
        def _wrapped(code: str) -> None:
            code_box.append(code)
            if on_code:
                on_code(code)

        return orig_send(bundle_json, on_code=_wrapped)

    wh.send_bundle = capturing_send  # type: ignore[assignment]

    import simplechat.chat.runner as runner

    orig_chat = runner._chat_loop

    def host_chat(session, conn, ui, stop):  # noqa: ANN001
        # wait briefly for a peer message or just quit
        deadline = time.time() + 60
        while time.time() < deadline and not stop.is_set():
            time.sleep(0.2)
            # peer may have sent via recv thread
            if "hi-live" in host_out.getvalue():
                break
        try:
            conn.sendall(session.encrypt_chat(b"host-ok"))
        except Exception:  # noqa: BLE001
            pass
        stop.set()

    def join_chat(session, conn, ui, stop):  # noqa: ANN001
        conn.sendall(session.encrypt_chat(b"hi-live"))
        deadline = time.time() + 60
        while time.time() < deadline and not stop.is_set():
            time.sleep(0.2)
            if "host-ok" in join_out.getvalue():
                break
        stop.set()

    def host_main() -> None:
        runner._chat_loop = host_chat  # type: ignore[assignment]
        try:
            results["host"] = run_host(ui=ChatUI(out=host_out, err=host_out))
        finally:
            runner._chat_loop = orig_chat  # type: ignore[assignment]

    def join_main() -> None:
        for _ in range(120):
            if code_box:
                break
            time.sleep(0.5)
        assert code_box, "no wormhole code"
        runner._chat_loop = join_chat  # type: ignore[assignment]
        try:
            results["join"] = run_join(code_box[0], ui=ChatUI(out=join_out, err=join_out))
        finally:
            runner._chat_loop = orig_chat  # type: ignore[assignment]

    try:
        th = threading.Thread(target=host_main)
        tj = threading.Thread(target=join_main)
        th.start()
        tj.start()
        th.join(timeout=280)
        tj.join(timeout=280)
        assert results.get("host") == 0, host_out.getvalue()
        assert results.get("join") == 0, join_out.getvalue()
        assert "Fingerprint:" in host_out.getvalue()
        assert "Fingerprint:" in join_out.getvalue()
    finally:
        wh.send_bundle = orig_send  # type: ignore[assignment]
        runner._chat_loop = orig_chat  # type: ignore[assignment]

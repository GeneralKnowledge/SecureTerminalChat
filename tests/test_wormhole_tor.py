"""Wormhole Tor / clearnet bootstrap argument and wiring tests."""

from __future__ import annotations

import pytest

from simplechat.bootstrap.wormhole_bootstrap import WormholeError, wormhole_tor_args


def test_wormhole_tor_args() -> None:
    assert wormhole_tor_args("tcp:127.0.0.1:9051") == [
        "--tor",
        "--tor-control-port",
        "tcp:127.0.0.1:9051",
    ]


def test_wormhole_tor_args_required() -> None:
    with pytest.raises(WormholeError):
        wormhole_tor_args("")
    with pytest.raises(WormholeError):
        wormhole_tor_args("   ")


def test_send_bundle_passes_tor_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    from simplechat.bootstrap import wormhole_bootstrap as wb

    captured: dict[str, object] = {}

    class FakeProc:
        def __init__(self) -> None:
            self.stdout = _FakeStream([])
            self.stderr = _FakeStream(
                ["Wormhole code is: 1-test-code\n", "text message sent\n"]
            )

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def kill(self) -> None:
            pass

    class _FakeStream:
        def __init__(self, lines: list[str]) -> None:
            self._lines = list(lines)

        def readline(self) -> str:
            if self._lines:
                return self._lines.pop(0)
            return ""

    def fake_popen(cmd, **kwargs):  # noqa: ANN001
        captured["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr(wb.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(wb, "_wormhole_bin", lambda: "wormhole")

    code = wb.send_bundle(
        '{"protocol":"simplechat"}',
        tor_control_endpoint="tcp:127.0.0.1:12345",
    )
    assert code == "1-test-code"
    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert "--tor" in cmd
    assert "tcp:127.0.0.1:12345" in cmd
    idx = cmd.index("--tor-control-port")
    assert cmd[idx + 1] == "tcp:127.0.0.1:12345"


def test_send_bundle_clearnet_omits_tor_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    from simplechat.bootstrap import wormhole_bootstrap as wb

    captured: dict[str, object] = {}

    class FakeProc:
        def __init__(self) -> None:
            self.stdout = _FakeStream([])
            self.stderr = _FakeStream(["Wormhole code is: 9-clear-net\n"])

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def kill(self) -> None:
            pass

    class _FakeStream:
        def __init__(self, lines: list[str]) -> None:
            self._lines = list(lines)

        def readline(self) -> str:
            if self._lines:
                return self._lines.pop(0)
            return ""

    def fake_popen(cmd, **kwargs):  # noqa: ANN001
        captured["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr(wb.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(wb, "_wormhole_bin", lambda: "wormhole")

    code = wb.send_bundle('{"ok":1}', tor_control_endpoint=None)
    assert code == "9-clear-net"
    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert "--tor" not in cmd


def test_receive_bundle_passes_tor_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    from simplechat.bootstrap import wormhole_bootstrap as wb

    captured: dict[str, object] = {}

    class Result:
        returncode = 0
        stdout = '{"ok":1}\n'
        stderr = ""

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        captured["cmd"] = cmd
        return Result()

    monkeypatch.setattr(wb.subprocess, "run", fake_run)
    monkeypatch.setattr(wb, "_wormhole_bin", lambda: "wormhole")

    msg = wb.receive_bundle("1-test-code", tor_control_endpoint="tcp:127.0.0.1:9999")
    assert msg == '{"ok":1}'
    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert "--tor" in cmd
    assert cmd[cmd.index("--tor-control-port") + 1] == "tcp:127.0.0.1:9999"

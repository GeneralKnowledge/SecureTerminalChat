"""Magic Wormhole bootstrap transfer (setup only — never chat traffic).

Uses the ``wormhole`` CLI in a subprocess so we do not fight Twisted's
single-reactor-per-process limitation, and so host/join can run in
separate processes cleanly.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Callable

log = logging.getLogger("simplechat.bootstrap")

APPID = "simplechat.v1"


class WormholeError(RuntimeError):
    pass


def _wormhole_bin() -> str:
    path = shutil.which("wormhole")
    if not path:
        candidate = Path.home() / ".local" / "bin" / "wormhole"
        if candidate.is_file():
            return str(candidate)
        raise WormholeError("wormhole CLI not found on PATH")
    return path


def _env() -> dict[str, str]:
    env = os.environ.copy()
    local_bin = str(Path.home() / ".local" / "bin")
    env["PATH"] = local_bin + os.pathsep + env.get("PATH", "")
    return env


def send_bundle(bundle_json: str, on_code: Callable[[str], None] | None = None) -> str:
    """
    Send bootstrap JSON via Magic Wormhole.
    Calls on_code(code) when the code appears on stderr/stdout.
    Blocks until the peer receives (or failure).
    Returns the wormhole code.
    """
    wh = _wormhole_bin()
    code_holder: dict[str, str] = {}

    proc = subprocess.Popen(
        [wh, "--appid", APPID, "send", "--text", bundle_json],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_env(),
    )

    def _watch(stream: object, label: str) -> None:
        assert hasattr(stream, "readline")
        for line in iter(stream.readline, ""):  # type: ignore[attr-defined]
            line_s = line.strip()
            if not line_s:
                continue
            log.debug("wormhole %s: %s", label, line_s)
            lowered = line_s.lower()
            if "wormhole code is:" in lowered:
                code = line_s.split(":", 1)[1].strip()
                if code and "code" not in code_holder:
                    code_holder["code"] = code
                    if on_code:
                        on_code(code)

    t_out = threading.Thread(target=_watch, args=(proc.stdout, "out"), daemon=True)
    t_err = threading.Thread(target=_watch, args=(proc.stderr, "err"), daemon=True)
    t_out.start()
    t_err.start()
    try:
        rc = proc.wait(timeout=600)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        raise WormholeError("wormhole send timed out") from exc
    t_out.join(timeout=2)
    t_err.join(timeout=2)
    if rc != 0:
        raise WormholeError(f"wormhole send failed with exit {rc}")
    code = code_holder.get("code")
    if not code:
        raise WormholeError("wormhole send failed: no code captured")
    return code


def receive_bundle(code: str) -> str:
    """Receive bootstrap JSON string via Magic Wormhole code."""
    wh = _wormhole_bin()
    try:
        proc = subprocess.run(
            [wh, "--appid", APPID, "receive", "--only-text", code],
            capture_output=True,
            text=True,
            timeout=600,
            env=_env(),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise WormholeError("wormhole receive timed out") from exc
    except FileNotFoundError as exc:
        raise WormholeError("wormhole CLI not found") from exc

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise WormholeError(f"wormhole receive failed: {err}")

    text = (proc.stdout or "").strip()
    if not text:
        # sometimes message lands on stderr alongside status
        text = (proc.stderr or "").strip()
    if not text:
        raise WormholeError("wormhole receive failed: empty message")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in reversed(lines):
        if ln.startswith("{") and ln.endswith("}"):
            return ln
    return lines[-1]

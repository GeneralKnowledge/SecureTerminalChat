"""Magic Wormhole bootstrap transfer (setup only — never chat traffic).

Uses the ``wormhole`` CLI in a subprocess so we do not fight Twisted's
single-reactor-per-process limitation.

- **tor profile:** ``--tor`` + session Tor control port (default)
- **direct profile:** clearnet Wormhole (explicit security downgrade)
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
    env.setdefault("WORMHOLE_QR", "0")
    return env


def wormhole_tor_args(tor_control_endpoint: str) -> list[str]:
    """
    CLI flags so Magic Wormhole uses an already-running Tor via control port.

    ``tor_control_endpoint`` is a Twisted client endpoint string, e.g.
    ``tcp:127.0.0.1:9051``.
    """
    if not tor_control_endpoint or not tor_control_endpoint.strip():
        raise WormholeError("tor control endpoint required for Tor-profile Wormhole")
    return [
        "--tor",
        "--tor-control-port",
        tor_control_endpoint.strip(),
    ]


def send_bundle(
    bundle_json: str,
    *,
    tor_control_endpoint: str | None = None,
    on_code: Callable[[str], None] | None = None,
) -> str:
    """
    Send bootstrap JSON via Magic Wormhole.

    Pass ``tor_control_endpoint`` for the tor profile. Omit it for direct
    (clearnet) profile — an intentional security downgrade.
    """
    wh = _wormhole_bin()
    code_holder: dict[str, str] = {}
    if tor_control_endpoint is not None:
        tor_args = wormhole_tor_args(tor_control_endpoint)
        log.info("wormhole send via Tor control %s", tor_control_endpoint)
    else:
        tor_args = []
        log.info("wormhole send via clearnet (direct profile)")

    cmd = [wh, "--appid", APPID, "send", *tor_args, "--text", bundle_json]

    proc = subprocess.Popen(
        cmd,
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
        hint = (
            "(is Tor running and the control port reachable?)"
            if tor_control_endpoint
            else "(clearnet Wormhole failed)"
        )
        raise WormholeError(f"wormhole send failed with exit {rc} {hint}")
    code = code_holder.get("code")
    if not code:
        raise WormholeError("wormhole send failed: no code captured")
    return code


def receive_bundle(code: str, *, tor_control_endpoint: str | None = None) -> str:
    """Receive bootstrap JSON via Magic Wormhole (Tor or clearnet)."""
    wh = _wormhole_bin()
    if tor_control_endpoint is not None:
        tor_args = wormhole_tor_args(tor_control_endpoint)
        log.info("wormhole receive via Tor control %s", tor_control_endpoint)
    else:
        tor_args = []
        log.info("wormhole receive via clearnet (direct profile)")

    cmd = [wh, "--appid", APPID, "receive", *tor_args, "--only-text", code]

    try:
        proc = subprocess.run(
            cmd,
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
        hint = (
            "(is Tor running and the control port reachable?)"
            if tor_control_endpoint
            else "(clearnet Wormhole failed)"
        )
        raise WormholeError(f"wormhole receive failed: {err} {hint}")

    text = (proc.stdout or "").strip()
    if not text:
        text = (proc.stderr or "").strip()
    if not text:
        raise WormholeError("wormhole receive failed: empty message")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in reversed(lines):
        if ln.startswith("{") and ln.endswith("}"):
            return ln
    return lines[-1]

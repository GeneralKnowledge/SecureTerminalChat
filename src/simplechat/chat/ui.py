"""Conservative CLI status display — never prints secrets."""

from __future__ import annotations

import sys
from typing import TextIO


class ChatUI:
    def __init__(self, out: TextIO = sys.stdout, err: TextIO = sys.stderr) -> None:
        self.out = out
        self.err = err
        self.encryption_active = False
        self.tor_active = False
        self.verified = False

    def info(self, msg: str) -> None:
        print(msg, file=self.out, flush=True)

    def error(self, msg: str) -> None:
        print(f"Error: {msg}", file=self.err, flush=True)

    def show_wormhole_code(self, code: str) -> None:
        self.info("Wormhole code:")
        self.info(code)

    def show_status(self) -> None:
        enc = "ACTIVE" if self.encryption_active else "INACTIVE"
        tor = "ACTIVE" if self.tor_active else "INACTIVE"
        ver = "VERIFIED" if self.verified else "NOT VERIFIED"
        self.info(f"Encryption: {enc}")
        self.info(f"Tor: {tor}")
        self.info(f"Identity verification: {ver}")

    def show_fingerprint(self, fingerprint: str) -> None:
        self.info("Peer connected.")
        self.info(f"Fingerprint: {fingerprint}")
        self.info("Compare this fingerprint with your peer over a separate trusted channel.")
        self.info(
            "If the fingerprints match, type /verify to mark the peer as verified."
        )
        self.info(
            "Fingerprint verification does not prove the absence of malware "
            "or device compromise."
        )
        if not self.verified:
            self.info(
                "Identity verification: NOT VERIFIED — peer identity has not been "
                "independently verified."
            )
        self.show_status()
        self.info("Type messages and press Enter. Commands: /verify  /status  /quit")

    def show_you(self, text: str) -> None:
        self.info(f"You: {text}")

    def show_peer(self, text: str) -> None:
        self.info(f"Peer: {text}")
